#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

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
    struct Stream* underlying_stream;
    uint32_t next_stream_id;
    int is_server;
};

struct YamuxStreamContext {
    struct YamuxSession* session;
    uint32_t stream_id;
};

static ssize_t yamux_stream_write(struct Stream* stream, const unsigned char* buf, size_t count) {
    if (stream == NULL || stream->stream_context == NULL)
        return -1;

    struct YamuxStreamContext* ctx = (struct YamuxStreamContext*)stream->stream_context;

    struct YamuxHeader hdr;
    hdr.version = YAMUX_VERSION;
    hdr.type = YAMUX_TYPE_DATA;
    hdr.flags = htons(0);
    hdr.stream_id = htonl(ctx->stream_id);
    hdr.length = htonl((uint32_t)count);

    if (ctx->session->underlying_stream->write(ctx->session->underlying_stream, (const unsigned char*)&hdr, sizeof(hdr)) <= 0)
        return -1;

    return ctx->session->underlying_stream->write(ctx->session->underlying_stream, buf, count);
}

static ssize_t yamux_stream_read(struct Stream* stream, unsigned char* buf, size_t count) {
    if (stream == NULL || stream->stream_context == NULL)
        return -1;

    struct YamuxStreamContext* ctx = (struct YamuxStreamContext*)stream->stream_context;

    struct YamuxHeader hdr;
    if (ctx->session->underlying_stream->read(ctx->session->underlying_stream, (unsigned char*)&hdr, sizeof(hdr)) <= 0)
        return -1;

    uint32_t payload_len = ntohl(hdr.length);
    if (payload_len > count)
        payload_len = (uint32_t)count;

    return ctx->session->underlying_stream->read(ctx->session->underlying_stream, buf, payload_len);
}

static void yamux_stream_close(struct Stream* stream) {
    if (stream == NULL)
        return;

    if (stream->stream_context != NULL) {
        struct YamuxStreamContext* ctx = (struct YamuxStreamContext*)stream->stream_context;

        struct YamuxHeader hdr;
        hdr.version = YAMUX_VERSION;
        hdr.type = YAMUX_TYPE_DATA;
        hdr.flags = htons(YAMUX_FLAG_FIN);
        hdr.stream_id = htonl(ctx->stream_id);
        hdr.length = htonl(0);

        ctx->session->underlying_stream->write(ctx->session->underlying_stream, (const unsigned char*)&hdr, sizeof(hdr));

        free(ctx);
        stream->stream_context = NULL;
    }
    free(stream);
}

struct YamuxSession* libp2p_yamux_session_new(struct Stream* stream, int is_server) {
    if (stream == NULL)
        return NULL;

    struct YamuxSession* session = (struct YamuxSession*)malloc(sizeof(struct YamuxSession));
    if (session != NULL) {
        session->underlying_stream = stream;
        session->is_server = is_server;
        session->next_stream_id = is_server ? 2 : 1;
    }
    return session;
}

struct Stream* libp2p_yamux_stream_open(struct YamuxSession* session) {
    if (session == NULL)
        return NULL;

    struct YamuxStreamContext* ctx = (struct YamuxStreamContext*)malloc(sizeof(struct YamuxStreamContext));
    if (ctx == NULL)
        return NULL;

    ctx->session = session;
    ctx->stream_id = session->next_stream_id;
    session->next_stream_id += 2;

    struct Stream* stream = (struct Stream*)calloc(1, sizeof(struct Stream));
    if (stream == NULL) {
        free(ctx);
        return NULL;
    }

    stream->stream_context = ctx;
    stream->read = yamux_stream_read;
    stream->write = yamux_stream_write;
    stream->close = yamux_stream_close;

    struct YamuxHeader hdr;
    hdr.version = YAMUX_VERSION;
    hdr.type = YAMUX_TYPE_DATA;
    hdr.flags = htons(YAMUX_FLAG_SYN);
    hdr.stream_id = htonl(ctx->stream_id);
    hdr.length = htonl(0);

    session->underlying_stream->write(session->underlying_stream, (const unsigned char*)&hdr, sizeof(hdr));

    return stream;
}

void libp2p_yamux_session_free(struct YamuxSession* session) {
    if (session != NULL) {
        if (session->underlying_stream != NULL) {
            session->underlying_stream->close(session->underlying_stream);
        }
        free(session);
    }
}
