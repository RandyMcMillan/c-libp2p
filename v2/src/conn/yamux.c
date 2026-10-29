#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "libp2p/conn/yamux.h"
#include "libp2p/utils/logger.h"

#define YAMUX_VERSION 0
#define YAMUX_TYPE_DATA 0
#define YAMUX_TYPE_WINDOW_UPDATE 1
#define YAMUX_TYPE_PING 2
#define YAMUX_TYPE_GO_AWAY 3

#define YAMUX_FLAG_SYN 1
#define YAMUX_FLAG_ACK 2
#define YAMUX_FLAG_FIN 4
#define YAMUX_FLAG_RST 8

#define YAMUX_INITIAL_WINDOW_SIZE (256 * 1024)
#define YAMUX_WINDOW_UPDATE_THRESHOLD (YAMUX_INITIAL_WINDOW_SIZE / 2)
#define YAMUX_MAX_PAYLOAD 65535

#pragma pack(push, 1)
struct YamuxHeader {
    uint8_t version;
    uint8_t type;
    uint16_t flags;
    uint32_t stream_id;
    uint32_t length;
};
#pragma pack(pop)

struct YamuxPendingInbound {
    uint32_t stream_id;
    unsigned char* data;
    size_t data_len;
    size_t data_pos;
    struct YamuxPendingInbound* next;
};

struct YamuxSession {
    struct Libp2pV2Stream* underlying_stream;
    uint32_t next_stream_id;
    int is_server;
    int closed;
    uint32_t ping_seq;
    struct YamuxPendingInbound* pending_inbound;
};

struct YamuxStreamContext {
    struct YamuxSession* session;
    uint32_t stream_id;
    uint32_t send_window;
    uint32_t recv_window;
    int syn_ack_received;
    int closed;
    /* Buffered payload from a partially-read DATA frame. */
    unsigned char* read_buffer;
    size_t read_buffer_len;
    size_t read_buffer_pos;
};

static int yamux_read_full(struct Libp2pV2Stream* stream, unsigned char* buf, size_t len)
{
    size_t total = 0;
    while (total < len) {
        ssize_t ret = stream->read(stream, buf + total, len - total);
        if (ret <= 0)
            return 0;
        total += (size_t)ret;
    }
    return 1;
}

static int yamux_send_header(struct YamuxSession* session, uint8_t type, uint16_t flags,
                             uint32_t stream_id, uint32_t length)
{
    struct YamuxHeader hdr;
    hdr.version = YAMUX_VERSION;
    hdr.type = type;
    hdr.flags = htons(flags);
    hdr.stream_id = htonl(stream_id);
    hdr.length = htonl(length);

    ssize_t ret = session->underlying_stream->write(session->underlying_stream,
                                                    (const unsigned char*)&hdr, sizeof(hdr));
    return ret == (ssize_t)sizeof(hdr);
}

static int yamux_read_header(struct YamuxSession* session, struct YamuxHeader* hdr)
{
    if (!yamux_read_full(session->underlying_stream, (unsigned char*)hdr, sizeof(*hdr)))
        return 0;
    hdr->flags = ntohs(hdr->flags);
    hdr->stream_id = ntohl(hdr->stream_id);
    hdr->length = ntohl(hdr->length);
    return 1;
}

static int yamux_send_ping_response(struct YamuxSession* session, uint32_t value)
{
    return yamux_send_header(session, YAMUX_TYPE_PING, YAMUX_FLAG_ACK, 0, value);
}

static int yamux_pending_add(struct YamuxSession* session, uint32_t stream_id)
{
    struct YamuxPendingInbound* node = (struct YamuxPendingInbound*)malloc(sizeof(struct YamuxPendingInbound));
    if (!node)
        return 0;
    node->stream_id = stream_id;
    node->data = NULL;
    node->data_len = 0;
    node->data_pos = 0;
    node->next = session->pending_inbound;
    session->pending_inbound = node;
    return 1;
}

static int yamux_pending_remove(struct YamuxSession* session, uint32_t stream_id)
{
    struct YamuxPendingInbound** current = &session->pending_inbound;
    while (*current) {
        if ((*current)->stream_id == stream_id) {
            struct YamuxPendingInbound* to_free = *current;
            *current = (*current)->next;
            if (to_free->data)
                free(to_free->data);
            free(to_free);
            return 1;
        }
        current = &(*current)->next;
    }
    return 0;
}

static int yamux_pending_exists(struct YamuxSession* session, uint32_t stream_id)
{
    struct YamuxPendingInbound* current = session->pending_inbound;
    while (current) {
        if (current->stream_id == stream_id)
            return 1;
        current = current->next;
    }
    return 0;
}

static int yamux_handle_control_frame(struct YamuxSession* session, const struct YamuxHeader* hdr)
{
    if (hdr->type == YAMUX_TYPE_PING) {
        if (hdr->flags & YAMUX_FLAG_ACK)
            return 1; /* ping response; caller must correlate value */
        return yamux_send_ping_response(session, hdr->length);
    }

    if (hdr->type == YAMUX_TYPE_GO_AWAY) {
        session->closed = 1;
        if (session->underlying_stream)
            session->underlying_stream->close(session->underlying_stream);
        return 0;
    }

    return 1;
}

static int yamux_discard_payload(struct YamuxSession* session, uint32_t length)
{
    unsigned char discard[1024];
    uint32_t remaining = length;
    while (remaining > 0) {
        uint32_t chunk = remaining > sizeof(discard) ? (uint32_t)sizeof(discard) : remaining;
        if (!yamux_read_full(session->underlying_stream, discard, chunk))
            return 0;
        remaining -= chunk;
    }
    return 1;
}

static ssize_t yamux_stream_write(struct Libp2pV2Stream* stream, const unsigned char* buf, size_t count) {
    if (stream == NULL || stream->stream_context == NULL)
        return -1;

    struct YamuxStreamContext* ctx = (struct YamuxStreamContext*)stream->stream_context;
    libp2p_v2_logger_info("yamux", "stream_write stream_id=%u count=%zu send_window=%u\n",
                          ctx->stream_id, count, ctx->send_window);
    if (ctx->session->closed || ctx->closed)
        return -1;

    if (count > YAMUX_MAX_PAYLOAD)
        count = YAMUX_MAX_PAYLOAD;

    if (count > ctx->send_window)
        count = ctx->send_window;

    if (count == 0)
        return -1; /* would block until window update */

    libp2p_v2_logger_info("yamux", "stream_write stream_id=%u sending DATA header length=%zu\n",
                          ctx->stream_id, count);
    if (!yamux_send_header(ctx->session, YAMUX_TYPE_DATA, 0, ctx->stream_id, (uint32_t)count))
        return -1;

    libp2p_v2_logger_info("yamux", "stream_write stream_id=%u sending payload\n", ctx->stream_id);
    ssize_t ret = ctx->session->underlying_stream->write(ctx->session->underlying_stream, buf, count);
    libp2p_v2_logger_info("yamux", "stream_write stream_id=%u payload ret=%zd\n", ctx->stream_id, ret);
    if (ret != (ssize_t)count)
        return -1;

    ctx->send_window -= (uint32_t)count;
    return (ssize_t)count;
}

static ssize_t yamux_stream_read(struct Libp2pV2Stream* stream, unsigned char* buf, size_t count) {
    if (stream == NULL || stream->stream_context == NULL || buf == NULL)
        return -1;

    struct YamuxStreamContext* ctx = (struct YamuxStreamContext*)stream->stream_context;

    for (;;) {
        if (ctx->session->closed || ctx->closed)
            return -1;

        /* Serve buffered payload first. */
        if (ctx->read_buffer != NULL && ctx->read_buffer_pos < ctx->read_buffer_len) {
            size_t avail = ctx->read_buffer_len - ctx->read_buffer_pos;
            size_t to_copy = count < avail ? count : avail;
            memcpy(buf, ctx->read_buffer + ctx->read_buffer_pos, to_copy);
            ctx->read_buffer_pos += to_copy;
            return (ssize_t)to_copy;
        }

        struct YamuxHeader hdr;
        if (!yamux_read_header(ctx->session, &hdr))
            return -1;

        if (hdr.version != YAMUX_VERSION) {
            libp2p_v2_logger_error("yamux", "Unsupported yamux version: %d\n", hdr.version);
            return -1;
        }

        if (hdr.type == YAMUX_TYPE_PING || hdr.type == YAMUX_TYPE_GO_AWAY) {
            if (!yamux_handle_control_frame(ctx->session, &hdr))
                return -1;
            continue;
        }

        if (hdr.type == YAMUX_TYPE_WINDOW_UPDATE) {
            if (hdr.stream_id == ctx->stream_id) {
                ctx->send_window += hdr.length;
                if ((hdr.flags & YAMUX_FLAG_ACK) && !ctx->syn_ack_received)
                    ctx->syn_ack_received = 1;
            }
            continue;
        }

        if (hdr.type != YAMUX_TYPE_DATA) {
            /* Unknown frame type: discard payload if any and continue. */
            if (!yamux_discard_payload(ctx->session, hdr.length))
                return -1;
            continue;
        }

        if (hdr.stream_id != ctx->stream_id) {
            /* Buffer DATA payloads for pending inbound streams so they survive
             * until the caller accepts the stream. */
            struct YamuxPendingInbound* pending = ctx->session->pending_inbound;
            while (pending && pending->stream_id != hdr.stream_id)
                pending = pending->next;
            if (pending && hdr.length > 0) {
                yamux_send_header(ctx->session, YAMUX_TYPE_WINDOW_UPDATE, 0,
                                  hdr.stream_id, hdr.length);
                unsigned char* tmp = (unsigned char*)realloc(pending->data,
                                                             pending->data_len + hdr.length);
                if (tmp && yamux_read_full(ctx->session->underlying_stream,
                                           tmp + pending->data_len, hdr.length)) {
                    pending->data = tmp;
                    pending->data_len += hdr.length;
                    libp2p_v2_logger_info("yamux", "stream %u: buffered %u bytes for pending inbound stream %u\n",
                                          ctx->stream_id, hdr.length, hdr.stream_id);
                    continue;
                }
                if (tmp)
                    pending->data = tmp;
            }
            if (!yamux_discard_payload(ctx->session, hdr.length))
                return -1;
            continue;
        }

        /* DATA frame for this stream. */
        uint32_t payload_len = hdr.length;
        int fin = (hdr.flags & YAMUX_FLAG_FIN) != 0;

        if (payload_len == 0) {
            if (fin) {
                ctx->closed = 1;
                return 0;
            }
            continue;
        }

        /* Read the full payload into our stream buffer so later small reads
         * do not have to parse a new yamux frame header each time. */
        if (ctx->read_buffer) {
            free(ctx->read_buffer);
            ctx->read_buffer = NULL;
        }
        ctx->read_buffer = (unsigned char*)malloc(payload_len);
        if (ctx->read_buffer == NULL)
            return -1;
        if (!yamux_read_full(ctx->session->underlying_stream, ctx->read_buffer, payload_len))
            return -1;
        ctx->read_buffer_len = payload_len;
        ctx->read_buffer_pos = 0;

        /* Replenish the receive window so the peer can keep sending. */
        if (ctx->recv_window >= payload_len) {
            ctx->recv_window -= payload_len;
        } else {
            ctx->recv_window = 0;
        }
        uint32_t increment = YAMUX_INITIAL_WINDOW_SIZE - ctx->recv_window;
        if (increment >= YAMUX_WINDOW_UPDATE_THRESHOLD) {
            if (yamux_send_header(ctx->session, YAMUX_TYPE_WINDOW_UPDATE, 0, ctx->stream_id, increment))
                ctx->recv_window += increment;
        }

        if (fin)
            ctx->closed = 1;

        size_t to_copy = count < payload_len ? count : payload_len;
        memcpy(buf, ctx->read_buffer, to_copy);
        ctx->read_buffer_pos = to_copy;
        return (ssize_t)to_copy;
    }
}

static void yamux_stream_close(struct Libp2pV2Stream* stream) {
    if (stream == NULL)
        return;

    if (stream->stream_context != NULL) {
        struct YamuxStreamContext* ctx = (struct YamuxStreamContext*)stream->stream_context;
        if (!ctx->closed && !ctx->session->closed && ctx->session->underlying_stream != NULL) {
            yamux_send_header(ctx->session, YAMUX_TYPE_DATA, YAMUX_FLAG_FIN, ctx->stream_id, 0);
        }
        ctx->closed = 1;
        if (ctx->read_buffer)
            free(ctx->read_buffer);
        free(ctx);
        stream->stream_context = NULL;
    }
    free(stream);
}

struct YamuxSession* libp2p_yamux_session_new(struct Libp2pV2Stream* stream, int is_server) {
    if (stream == NULL)
        return NULL;

    struct YamuxSession* session = (struct YamuxSession*)malloc(sizeof(struct YamuxSession));
    if (session != NULL) {
        session->underlying_stream = stream;
        session->is_server = is_server;
        session->next_stream_id = is_server ? 2 : 1;
        session->closed = 0;
        session->ping_seq = 1;
        session->pending_inbound = NULL;
    }
    return session;
}

static int yamux_wait_for_syn(struct YamuxSession* session, struct YamuxHeader* syn_hdr)
{
    for (;;) {
        if (!yamux_read_header(session, syn_hdr))
            return 0;

        if (syn_hdr->type == YAMUX_TYPE_PING || syn_hdr->type == YAMUX_TYPE_GO_AWAY) {
            if (!yamux_handle_control_frame(session, syn_hdr))
                return 0;
            continue;
        }

        /* In yamux a new stream is opened with a WINDOW_UPDATE bearing SYN. */
        if (syn_hdr->type == YAMUX_TYPE_WINDOW_UPDATE && (syn_hdr->flags & YAMUX_FLAG_SYN))
            return 1;

        /* Discard anything else. */
        if (!yamux_discard_payload(session, syn_hdr->length))
            return 0;
    }
}

struct Libp2pV2Stream* libp2p_yamux_stream_open(struct YamuxSession* session) {
    if (session == NULL || session->closed)
        return NULL;

    struct YamuxStreamContext* ctx = (struct YamuxStreamContext*)malloc(sizeof(struct YamuxStreamContext));
    if (ctx == NULL)
        return NULL;

    ctx->session = session;
    ctx->stream_id = session->next_stream_id;
    session->next_stream_id += 2;
    /* go-yamux v4 grants each side an implicit initial send window of
     * 256 KiB; WINDOW_UPDATE frames only extend it. */
    ctx->send_window = YAMUX_INITIAL_WINDOW_SIZE;
    ctx->recv_window = YAMUX_INITIAL_WINDOW_SIZE;
    ctx->syn_ack_received = 0;
    ctx->closed = 0;
    ctx->read_buffer = NULL;
    ctx->read_buffer_len = 0;
    ctx->read_buffer_pos = 0;

    struct Libp2pV2Stream* stream = (struct Libp2pV2Stream*)calloc(1, sizeof(struct Libp2pV2Stream));
    if (stream == NULL) {
        free(ctx);
        return NULL;
    }

    stream->stream_context = ctx;
    stream->read = yamux_stream_read;
    stream->write = yamux_stream_write;
    stream->close = yamux_stream_close;

    /* Open the stream with a SYN-bearing WINDOW_UPDATE, exactly like
     * go-yamux v4.  The initial receive window is implicit, so the
     * delta advertised here is zero. */
    if (!yamux_send_header(session, YAMUX_TYPE_WINDOW_UPDATE,
                           YAMUX_FLAG_SYN, ctx->stream_id, 0)) {
        free(ctx);
        free(stream);
        return NULL;
    }

    /* Wait for the peer's ACK.  go-yamux v4 acknowledges a new stream with
     * a WINDOW_UPDATE carrying ACK and a zero-length delta. */
    int ack_seen = 0;
    while (!ack_seen) {
        struct YamuxHeader hdr;
        if (!yamux_read_header(session, &hdr)) {
            libp2p_v2_logger_error("yamux", "stream %u: timed out waiting for ACK window update\n", ctx->stream_id);
            free(ctx);
            free(stream);
            return NULL;
        }

        libp2p_v2_logger_info("yamux", "stream %u: open received type=%u flags=0x%x stream_id=%u length=%u\n",
                              ctx->stream_id, hdr.type, hdr.flags, hdr.stream_id, hdr.length);

        if (hdr.type == YAMUX_TYPE_PING || hdr.type == YAMUX_TYPE_GO_AWAY) {
            if (!yamux_handle_control_frame(session, &hdr)) {
                free(ctx);
                free(stream);
                return NULL;
            }
            continue;
        }

        if (hdr.type == YAMUX_TYPE_WINDOW_UPDATE && hdr.stream_id == ctx->stream_id) {
            ctx->send_window += hdr.length;
            if (hdr.flags & YAMUX_FLAG_ACK)
                ack_seen = 1;
            continue;
        }

        /* Accept inbound SYNs for other streams: acknowledge them and queue
         * the stream id so libp2p_yamux_stream_accept can return it. */
        if (hdr.type == YAMUX_TYPE_WINDOW_UPDATE && (hdr.flags & YAMUX_FLAG_SYN)) {
            if (!yamux_pending_exists(session, hdr.stream_id)) {
                yamux_send_header(session, YAMUX_TYPE_WINDOW_UPDATE,
                                  YAMUX_FLAG_ACK, hdr.stream_id, 0);
                yamux_pending_add(session, hdr.stream_id);
                libp2p_v2_logger_info("yamux", "stream %u: queued inbound SYN for stream %u\n",
                                      ctx->stream_id, hdr.stream_id);
            }
            continue;
        }

        /* Buffer DATA payloads for pending inbound streams so they are available
         * once the caller accepts the stream. */
        if (hdr.type == YAMUX_TYPE_DATA && yamux_pending_exists(session, hdr.stream_id)) {
            struct YamuxPendingInbound* pending = session->pending_inbound;
            while (pending && pending->stream_id != hdr.stream_id)
                pending = pending->next;
            if (pending && hdr.length > 0) {
                unsigned char* tmp = (unsigned char*)realloc(pending->data,
                                                             pending->data_len + hdr.length);
                if (tmp) {
                    pending->data = tmp;
                    if (yamux_read_full(session->underlying_stream,
                                        pending->data + pending->data_len, hdr.length)) {
                        pending->data_len += hdr.length;
                        libp2p_v2_logger_info("yamux", "stream %u: buffered %u bytes for pending inbound stream %u\n",
                                              ctx->stream_id, hdr.length, hdr.stream_id);
                    }
                } else {
                    if (!yamux_discard_payload(session, hdr.length)) {
                        free(ctx);
                        free(stream);
                        return NULL;
                    }
                }
            }
            continue;
        }

        /* Discard frames for other streams / unexpected types. */
        if (!yamux_discard_payload(session, hdr.length)) {
            free(ctx);
            free(stream);
            return NULL;
        }
    }

    ctx->syn_ack_received = 1;
    libp2p_v2_logger_info("yamux", "stream %u: open ACK seen, returning stream %p\n",
                          ctx->stream_id, (void*)stream);
    return stream;
}

struct Libp2pV2Stream* libp2p_yamux_stream_accept(struct YamuxSession* session) {
    if (session == NULL || session->closed)
        return NULL;

    uint32_t stream_id = 0;

    /* If a remote SYN was already received while waiting for another stream's
     * ACK, return the queued stream immediately. */
    struct YamuxPendingInbound* accepted_pending = NULL;
    if (session->pending_inbound != NULL) {
        accepted_pending = session->pending_inbound;
        stream_id = accepted_pending->stream_id;
        libp2p_v2_logger_info("yamux", "accept returning queued inbound stream %u\n", stream_id);
    } else {
        struct YamuxHeader hdr;
        if (!yamux_wait_for_syn(session, &hdr))
            return NULL;

        stream_id = hdr.stream_id;
        uint32_t syn_payload = hdr.length;

        /* Consume any payload that may accompany the SYN. */
        if (syn_payload > 0) {
            if (!yamux_discard_payload(session, syn_payload))
                return NULL;
        }
    }

    struct YamuxStreamContext* ctx = (struct YamuxStreamContext*)malloc(sizeof(struct YamuxStreamContext));
    if (ctx == NULL)
        return NULL;

    ctx->session = session;
    ctx->stream_id = stream_id;
    ctx->send_window = YAMUX_INITIAL_WINDOW_SIZE;
    ctx->recv_window = YAMUX_INITIAL_WINDOW_SIZE;
    ctx->syn_ack_received = 1;
    ctx->closed = 0;
    ctx->read_buffer = NULL;
    ctx->read_buffer_len = 0;
    ctx->read_buffer_pos = 0;

    /* Transfer any buffered payload from the pending inbound entry, then
     * remove the pending entry. */
    if (accepted_pending && accepted_pending->data_len > 0) {
        ctx->read_buffer = accepted_pending->data;
        ctx->read_buffer_len = accepted_pending->data_len;
        ctx->read_buffer_pos = 0;
        accepted_pending->data = NULL;
        accepted_pending->data_len = 0;
        libp2p_v2_logger_info("yamux", "accept stream %u: transferred %zu buffered bytes\n",
                              stream_id, ctx->read_buffer_len);
    }
    if (accepted_pending) {
        session->pending_inbound = accepted_pending->next;
        free(accepted_pending);
    }

    struct Libp2pV2Stream* stream = (struct Libp2pV2Stream*)calloc(1, sizeof(struct Libp2pV2Stream));
    if (stream == NULL) {
        free(ctx);
        return NULL;
    }

    stream->stream_context = ctx;
    stream->read = yamux_stream_read;
    stream->write = yamux_stream_write;
    stream->close = yamux_stream_close;

    /* Acknowledge the new stream with a WINDOW_UPDATE bearing the ACK flag.
     * go-yamux v4 uses a zero delta because the implicit initial send window
     * is already 256 KiB. */
    if (!yamux_send_header(session, YAMUX_TYPE_WINDOW_UPDATE,
                           YAMUX_FLAG_ACK, ctx->stream_id, 0)) {
        free(ctx);
        free(stream);
        return NULL;
    }

    return stream;
}

int libp2p_yamux_session_ping(struct YamuxSession* session)
{
    if (session == NULL || session->closed)
        return 0;

    uint32_t value = session->ping_seq++;
    if (!yamux_send_header(session, YAMUX_TYPE_PING, 0, 0, value))
        return 0;

    for (;;) {
        struct YamuxHeader hdr;
        if (!yamux_read_header(session, &hdr))
            return 0;

        if (hdr.type == YAMUX_TYPE_PING && (hdr.flags & YAMUX_FLAG_ACK) && hdr.length == value)
            return 1;

        if (!yamux_handle_control_frame(session, &hdr))
            return 0;

        /* Discard non-control payloads. */
        if (!yamux_discard_payload(session, hdr.length))
            return 0;
    }
}

void libp2p_yamux_session_goaway(struct YamuxSession* session, uint32_t code)
{
    if (session == NULL || session->closed)
        return;

    yamux_send_header(session, YAMUX_TYPE_GO_AWAY, 0, 0, code);
    session->closed = 1;
    if (session->underlying_stream) {
        session->underlying_stream->close(session->underlying_stream);
        session->underlying_stream = NULL;
    }
}

void libp2p_yamux_session_free(struct YamuxSession* session) {
    if (session != NULL) {
        if (session->underlying_stream != NULL && !session->closed) {
            session->underlying_stream->close(session->underlying_stream);
        }
        struct YamuxPendingInbound* pending = session->pending_inbound;
        while (pending) {
            struct YamuxPendingInbound* next = pending->next;
            if (pending->data)
                free(pending->data);
            free(pending);
            pending = next;
        }
        free(session);
    }
}
