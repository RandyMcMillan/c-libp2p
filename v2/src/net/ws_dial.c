#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libp2p/net/ws.h"
#include "libp2p/utils/logger.h"

#ifdef HAS_LIBWEBSOCKETS

#include <libwebsockets.h>

struct ws_stream_context {
    struct lws_context *ctx;
    struct lws *wsi;
    int connected;
    int failed;
    int write_done;

    uint8_t rx_buf[65536];
    size_t rx_len;

    const uint8_t *tx_buf;
    size_t tx_len;
    size_t tx_sent;
};

static int ws_callback(struct lws *wsi, enum lws_callback_reasons reason,
                       void *user, void *in, size_t len)
{
    struct ws_stream_context *ctx = (struct ws_stream_context *)user;
    libp2p_v2_logger_info("ws", "callback reason=%d len=%zu ctx=%p\n", (int)reason, len, (void*)ctx);
    if (ctx == NULL)
        return 0;

    switch (reason) {
    case LWS_CALLBACK_CLIENT_ESTABLISHED:
        ctx->connected = 1;
        break;

    case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
        libp2p_v2_logger_info("ws", "connection error\n");
        ctx->failed = 1;
        break;

    case LWS_CALLBACK_CLIENT_RECEIVE:
        libp2p_v2_logger_info("ws", "received %zu bytes\n", len);
        if (ctx->rx_len + len > sizeof(ctx->rx_buf)) {
            ctx->failed = 1;
            return -1;
        }
        memcpy(ctx->rx_buf + ctx->rx_len, in, len);
        ctx->rx_len += len;
        break;

    case LWS_CALLBACK_CLIENT_WRITEABLE:
        libp2p_v2_logger_info("ws", "writable tx_sent=%zu tx_len=%zu\n", ctx->tx_sent, ctx->tx_len);
        if (ctx->tx_buf && ctx->tx_sent < ctx->tx_len) {
            size_t remaining = ctx->tx_len - ctx->tx_sent;
            size_t chunk = remaining;
            if (chunk > 4096)
                chunk = 4096;
            unsigned char *wbuf = malloc(LWS_PRE + chunk);
            if (wbuf == NULL) {
                ctx->failed = 1;
                return -1;
            }
            memcpy(&wbuf[LWS_PRE], ctx->tx_buf + ctx->tx_sent, chunk);
            int n = lws_write(wsi, &wbuf[LWS_PRE], chunk, LWS_WRITE_BINARY);
            libp2p_v2_logger_info("ws", "lws_write returned %d for chunk %zu\n", n, chunk);
            free(wbuf);
            if (n < 0) {
                ctx->failed = 1;
                return -1;
            }
            ctx->tx_sent += (size_t)n;
            if (ctx->tx_sent < ctx->tx_len) {
                lws_callback_on_writable(wsi);
            } else {
                ctx->write_done = 1;
            }
        } else {
            ctx->write_done = 1;
        }
        break;

    case LWS_CALLBACK_CLOSED:
        libp2p_v2_logger_info("ws", "connection closed\n");
        ctx->connected = 0;
        ctx->failed = 1;
        break;

    default:
        break;
    }
    return 0;
}

static struct lws_protocols ws_protocols[] = {
    { "libp2p-ws", ws_callback, sizeof(struct ws_stream_context), 65536 },
    { NULL, NULL, 0, 0 }
};

static ssize_t ws_stream_read(struct Libp2pV2Stream* stream, unsigned char* buf, size_t count)
{
    struct ws_stream_context* ctx = (struct ws_stream_context*)stream->stream_context;
    if (ctx == NULL)
        return -1;

    if (ctx->rx_len > 0) {
        size_t to_copy = count < ctx->rx_len ? count : ctx->rx_len;
        memcpy(buf, ctx->rx_buf, to_copy);
        if (to_copy < ctx->rx_len)
            memmove(ctx->rx_buf, ctx->rx_buf + to_copy, ctx->rx_len - to_copy);
        ctx->rx_len -= to_copy;
        return (ssize_t)to_copy;
    }

    if (!ctx->connected || ctx->failed)
        return -1;

    /* Service the event loop for up to ~1 second waiting for data. */
    for (int i = 0; i < 100; i++) {
        lws_service(ctx->ctx, 10);
        if (ctx->rx_len > 0) {
            size_t to_copy = count < ctx->rx_len ? count : ctx->rx_len;
            memcpy(buf, ctx->rx_buf, to_copy);
            if (to_copy < ctx->rx_len)
                memmove(ctx->rx_buf, ctx->rx_buf + to_copy, ctx->rx_len - to_copy);
            ctx->rx_len -= to_copy;
            return (ssize_t)to_copy;
        }
        if (ctx->failed)
            return -1;
    }
    return 0;
}

static ssize_t ws_stream_write(struct Libp2pV2Stream* stream, const unsigned char* buf, size_t count)
{
    struct ws_stream_context* ctx = (struct ws_stream_context*)stream->stream_context;
    if (ctx == NULL || !ctx->connected || ctx->failed) {
        libp2p_v2_logger_info("ws", "write rejected connected=%d failed=%d\n",
                              ctx ? ctx->connected : 0, ctx ? ctx->failed : 1);
        return -1;
    }

    ctx->tx_buf = buf;
    ctx->tx_len = count;
    ctx->tx_sent = 0;
    ctx->write_done = 0;
    int cb_ret = lws_callback_on_writable(ctx->wsi);
    libp2p_v2_logger_info("ws", "requested writable returned %d\n", cb_ret);

    int last_i = -1;
    for (int i = 0; i < 1000 && !ctx->write_done && !ctx->failed; i++) {
        last_i = i;
        lws_service(ctx->ctx, 10);
    }
    libp2p_v2_logger_info("ws", "write loop exited i=%d write_done=%d failed=%d\n",
                          last_i, ctx->write_done, ctx->failed);

    if (ctx->failed) {
        libp2p_v2_logger_info("ws", "write failed: connection failed after loop\n");
        return -1;
    }
    libp2p_v2_logger_info("ws", "wrote %zu/%zu bytes\n", ctx->tx_sent, count);
    return (ssize_t)ctx->tx_sent;
}

static void ws_stream_close(struct Libp2pV2Stream* stream)
{
    if (stream == NULL)
        return;
    struct ws_stream_context* ctx = (struct ws_stream_context*)stream->stream_context;
    if (ctx != NULL) {
        if (ctx->wsi != NULL) {
            lws_set_timeout(ctx->wsi, PENDING_TIMEOUT_CLOSE_SEND, LWS_TO_KILL_ASYNC);
        }
        if (ctx->ctx != NULL) {
            lws_context_destroy(ctx->ctx);
        }
        free(ctx);
    }
    free(stream);
}

struct Libp2pV2Stream* libp2p_net_ws_dial(const char* ip_address, uint16_t port)
{
    if (ip_address == NULL)
        return NULL;

    struct lws_context_creation_info info;
    memset(&info, 0, sizeof(info));
    info.port = CONTEXT_PORT_NO_LISTEN;
    info.protocols = ws_protocols;

    struct lws_context *ctx = lws_create_context(&info);
    if (ctx == NULL) {
        libp2p_v2_logger_error("ws", "failed to create lws context\n");
        return NULL;
    }
    lws_set_log_level(LLL_ERR | LLL_WARN | LLL_NOTICE | LLL_INFO | LLL_DEBUG | LLL_HEADER | LLL_CLIENT | LLL_LATENCY, NULL);

    struct ws_stream_context *ws_ctx = calloc(1, sizeof(struct ws_stream_context));
    if (ws_ctx == NULL) {
        lws_context_destroy(ctx);
        return NULL;
    }
    ws_ctx->ctx = ctx;

    struct lws_client_connect_info ccinfo;
    memset(&ccinfo, 0, sizeof(ccinfo));
    ccinfo.context = ctx;
    ccinfo.address = ip_address;
    ccinfo.port = port;
    ccinfo.path = "/";
    ccinfo.host = ccinfo.address;
    ccinfo.origin = ccinfo.address;
    ccinfo.protocol = ws_protocols[0].name;
    ccinfo.ssl_connection = 0;
    ccinfo.userdata = ws_ctx;

    struct lws *wsi = lws_client_connect_via_info(&ccinfo);
    if (wsi == NULL) {
        libp2p_v2_logger_error("ws", "lws_client_connect_via_info failed\n");
        free(ws_ctx);
        lws_context_destroy(ctx);
        return NULL;
    }
    ws_ctx->wsi = wsi;

    /* Drive the handshake to completion. */
    for (int i = 0; i < 500 && !ws_ctx->connected && !ws_ctx->failed; i++) {
        lws_service(ctx, 10);
    }

    if (!ws_ctx->connected) {
        libp2p_v2_logger_error("ws", "WebSocket handshake to %s:%u failed\n", ip_address, port);
        ws_ctx->wsi = NULL;
        lws_context_destroy(ctx);
        free(ws_ctx);
        return NULL;
    }

    struct Libp2pV2Stream* stream = calloc(1, sizeof(struct Libp2pV2Stream));
    if (stream == NULL) {
        ws_ctx->wsi = NULL;
        lws_context_destroy(ctx);
        free(ws_ctx);
        return NULL;
    }
    stream->stream_context = ws_ctx;
    stream->read = ws_stream_read;
    stream->write = ws_stream_write;
    stream->close = ws_stream_close;

    return stream;
}

#else /* !HAS_LIBWEBSOCKETS */

struct Libp2pV2Stream* libp2p_net_ws_dial(const char* ip_address, uint16_t port)
{
    (void)ip_address;
    (void)port;
    libp2p_v2_logger_error("ws", "libwebsockets not available at compile time\n");
    return NULL;
}

#endif
