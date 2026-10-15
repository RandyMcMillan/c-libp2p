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

struct YamuxSession {
    struct Libp2pV2Stream* underlying_stream;
    uint32_t next_stream_id;
    int is_server;
    int closed;
    uint32_t ping_seq;
};

struct YamuxStreamContext {
    struct YamuxSession* session;
    uint32_t stream_id;
    uint32_t send_window;
    uint32_t recv_window;
    int syn_ack_received;
    int closed;
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
    if (ctx->session->closed || ctx->closed)
        return -1;

    if (count > YAMUX_MAX_PAYLOAD)
        count = YAMUX_MAX_PAYLOAD;

    if (count > ctx->send_window)
        count = ctx->send_window;

    if (count == 0)
        return -1; /* would block until window update */

    if (!yamux_send_header(ctx->session, YAMUX_TYPE_DATA, 0, ctx->stream_id, (uint32_t)count))
        return -1;

    ssize_t ret = ctx->session->underlying_stream->write(ctx->session->underlying_stream, buf, count);
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

        uint32_t to_read = payload_len > count ? (uint32_t)count : payload_len;
        if (!yamux_read_full(ctx->session->underlying_stream, buf, to_read))
            return -1;

        if (payload_len > to_read) {
            if (!yamux_discard_payload(ctx->session, payload_len - to_read))
                return -1;
        }

        /* Replenish the receive window so the peer can keep sending. */
        if (ctx->recv_window >= to_read) {
            ctx->recv_window -= (uint32_t)to_read;
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

        return (ssize_t)to_read;
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

        if (syn_hdr->type == YAMUX_TYPE_DATA && (syn_hdr->flags & YAMUX_FLAG_SYN))
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
    ctx->send_window = 0;
    ctx->recv_window = YAMUX_INITIAL_WINDOW_SIZE;
    ctx->syn_ack_received = 0;
    ctx->closed = 0;

    struct Libp2pV2Stream* stream = (struct Libp2pV2Stream*)calloc(1, sizeof(struct Libp2pV2Stream));
    if (stream == NULL) {
        free(ctx);
        return NULL;
    }

    stream->stream_context = ctx;
    stream->read = yamux_stream_read;
    stream->write = yamux_stream_write;
    stream->close = yamux_stream_close;

    /* Send SYN. */
    if (!yamux_send_header(session, YAMUX_TYPE_DATA, YAMUX_FLAG_SYN, ctx->stream_id, 0)) {
        free(ctx);
        free(stream);
        return NULL;
    }

    /* Wait for the peer's WINDOW_UPDATE with ACK. */
    for (;;) {
        struct YamuxHeader hdr;
        if (!yamux_read_header(session, &hdr)) {
            free(ctx);
            free(stream);
            return NULL;
        }

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
            if (hdr.flags & YAMUX_FLAG_ACK) {
                ctx->syn_ack_received = 1;
                break;
            }
            continue;
        }

        if (hdr.type == YAMUX_TYPE_DATA && hdr.stream_id == ctx->stream_id && (hdr.flags & YAMUX_FLAG_ACK)) {
            /* Some peers may ACK on the first DATA frame. */
            ctx->syn_ack_received = 1;
            /* This frame's payload would belong to the stream; we cannot easily
             * buffer it here.  For our use cases the ACK arrives on a
             * WINDOW_UPDATE, so treat this as an error to avoid complexity. */
            free(ctx);
            free(stream);
            return NULL;
        }

        /* Discard frames for other streams / unexpected types. */
        if (!yamux_discard_payload(session, hdr.length)) {
            free(ctx);
            free(stream);
            return NULL;
        }
    }

    return stream;
}

struct Libp2pV2Stream* libp2p_yamux_stream_accept(struct YamuxSession* session) {
    if (session == NULL || session->closed)
        return NULL;

    struct YamuxHeader hdr;
    if (!yamux_wait_for_syn(session, &hdr))
        return NULL;

    uint32_t stream_id = hdr.stream_id;
    uint32_t syn_payload = hdr.length;

    /* Consume any payload that may accompany the SYN. */
    if (syn_payload > 0) {
        if (!yamux_discard_payload(session, syn_payload))
            return NULL;
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

    struct Libp2pV2Stream* stream = (struct Libp2pV2Stream*)calloc(1, sizeof(struct Libp2pV2Stream));
    if (stream == NULL) {
        free(ctx);
        return NULL;
    }

    stream->stream_context = ctx;
    stream->read = yamux_stream_read;
    stream->write = yamux_stream_write;
    stream->close = yamux_stream_close;

    /* Acknowledge the new stream with a WINDOW_UPDATE bearing the ACK flag. */
    if (!yamux_send_header(session, YAMUX_TYPE_WINDOW_UPDATE,
                           YAMUX_FLAG_ACK, ctx->stream_id, ctx->recv_window)) {
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
        free(session);
    }
}
