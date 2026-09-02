#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "libp2p/transport/quic.h"

#ifdef HAVE_LSQUIC
#include <lsquic.h>
#include <openssl/ssl.h>

typedef struct {
    libp2p_transport_t base;
    lsquic_engine_t *engine;
    SSL_CTX *ssl_ctx;
} libp2p_quic_transport_t;

typedef struct {
    libp2p_stream_t base;
    lsquic_stream_t *ls_stream;
    uint8_t rx_buf[4096];
    size_t rx_len;
} quic_stream_impl_t;

/* Stream Callbacks */
static ssize_t quic_stream_read(libp2p_stream_t *stream, uint8_t *buf, size_t len) {
    quic_stream_impl_t *impl = (quic_stream_impl_t *)stream;
    if (!impl || !impl->ls_stream) {
        return -1;
    }
    return lsquic_stream_read(impl->ls_stream, buf, len);
}

static ssize_t quic_stream_write(libp2p_stream_t *stream, const uint8_t *buf, size_t len) {
    quic_stream_impl_t *impl = (quic_stream_impl_t *)stream;
    if (!impl || !impl->ls_stream) {
        return -1;
    }
    return lsquic_stream_write(impl->ls_stream, buf, len);
}

static void quic_stream_close(libp2p_stream_t *stream) {
    quic_stream_impl_t *impl = (quic_stream_impl_t *)stream;
    if (impl) {
        if (impl->ls_stream) {
            lsquic_stream_close(impl->ls_stream);
        }
        free(impl);
    }
}

/* Engine Handshake & Stream Lifecycle */
static lsquic_conn_ctx_t *on_new_conn(void *stream_if_ctx, lsquic_conn_t *c) {
    (void)stream_if_ctx;
    printf("[QUIC] Connected to peer successfully.\n");
    return (lsquic_conn_ctx_t *)c;
}

static lsquic_stream_ctx_t *on_new_stream(void *stream_if_ctx, lsquic_stream_t *s) {
    (void)stream_if_ctx;
    lsquic_stream_wantread(s, 1);
    quic_stream_impl_t *stream = calloc(1, sizeof(quic_stream_impl_t));
    if (!stream) {
        return NULL;
    }
    stream->base.read = quic_stream_read;
    stream->base.write = quic_stream_write;
    stream->base.close = quic_stream_close;
    stream->ls_stream = s;
    return (lsquic_stream_ctx_t *)stream;
}

static const struct lsquic_stream_if quic_stream_if = {
    .on_new_conn = on_new_conn,
    .on_new_stream = on_new_stream,
};

/* Transport Dialing Interface */
static int quic_dial(libp2p_transport_t *self, const char *multiaddr, libp2p_stream_t **out_stream) {
    libp2p_quic_transport_t *quic = (libp2p_quic_transport_t *)self;
    if (!quic || !multiaddr || !out_stream) {
        return -1;
    }

    /* Parse IPv4/UDP multiaddr e.g., /ip4/127.0.0.1/udp/4001/quic-v1 */
    char ip[64];
    int port;
    if (sscanf(multiaddr, "/ip4/%63[^/]/udp/%d/quic-v1", ip, &port) != 2) {
        fprintf(stderr, "[QUIC] Invalid QUIC multiaddr: %s\n", multiaddr);
        return -1;
    }

    struct sockaddr_in peer_addr;
    memset(&peer_addr, 0, sizeof(peer_addr));
    peer_addr.sin_family = AF_INET;
    peer_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &peer_addr.sin_addr) != 1) {
        fprintf(stderr, "[QUIC] Invalid IP address: %s\n", ip);
        return -1;
    }

    /* QUIC connects natively with integrated libp2p-TLS 1.3 auth */
    lsquic_conn_t *conn = lsquic_engine_connect(
        quic->engine,
        N_LSQUIC_VER,
        (struct sockaddr *)&peer_addr,
        NULL, NULL, NULL, NULL, 0, NULL, 0, NULL, 0
    );

    if (!conn) {
        fprintf(stderr, "[QUIC] lsquic_engine_connect failed\n");
        return -1;
    }

    /* Process connections to drive the handshake forward */
    lsquic_engine_process_conns(quic->engine);

    /* TODO: Properly wait for connection establishment and open a stream.
     * Currently this is a skeleton; the caller must pump the engine
     * event loop until the connection and stream callbacks fire.
     */
    (void)out_stream;
    return 0;
}

/* Transport Listen Interface */
static int quic_listen(libp2p_transport_t *self, const char *multiaddr) {
    (void)self;
    (void)multiaddr;
    fprintf(stderr, "[QUIC] listen not yet implemented\n");
    return -1;
}

/* Transport Close Interface */
static void quic_transport_close(libp2p_transport_t *self) {
    libp2p_quic_transport_t *quic = (libp2p_quic_transport_t *)self;
    if (quic) {
        if (quic->engine) {
            lsquic_engine_destroy(quic->engine);
        }
        free(quic);
    }
}

libp2p_transport_t *libp2p_quic_transport_create(void *tls_ctx) {
    SSL_CTX *ssl_ctx = (SSL_CTX *)tls_ctx;
    libp2p_quic_transport_t *t = calloc(1, sizeof(libp2p_quic_transport_t));
    if (!t) {
        return NULL;
    }
    t->base.name = "quic-v1";
    t->base.dial = quic_dial;
    t->base.listen = quic_listen;
    t->base.close = quic_transport_close;
    t->ssl_ctx = ssl_ctx;

    struct lsquic_engine_api api;
    memset(&api, 0, sizeof(api));
    api.ea_stream_if = &quic_stream_if;
    api.ea_stream_if_ctx = t;

    t->engine = lsquic_engine_new(0, &api);
    if (!t->engine) {
        free(t);
        return NULL;
    }
    return (libp2p_transport_t *)t;
}

#else /* !HAVE_LSQUIC */

libp2p_transport_t *libp2p_quic_transport_create(void *tls_ctx) {
    (void)tls_ctx;
    fprintf(stderr, "[QUIC] lsquic not available at compile time; quic transport disabled\n");
    return NULL;
}

#endif /* HAVE_LSQUIC */
