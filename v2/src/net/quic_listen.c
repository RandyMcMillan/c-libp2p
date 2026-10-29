#ifdef HAS_LSQUIC

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <lsquic.h>
#include <openssl/ssl.h>

#include "libp2p/net/quic.h"
#include "libp2p/conn/tls.h"
#include "libp2p/utils/debug.h"
#include "libp2p/utils/logger.h"

#define QUIC_LISTEN_ACCEPT_TIMEOUT_MS 30000
#define QUIC_LISTEN_READ_TIMEOUT_MS   30000

struct quic_listen_conn {
    lsquic_conn_t *conn;
    int handshake_status; /* 0 = pending, 1 = ok, -1 = failed */
    int stream_ready;
    int expecting_outbound;
    int ref_count;
    lsquic_stream_t *stream;
    struct quic_listen_conn *next;
};

struct Libp2pQuicListener {
    lsquic_engine_t *engine;
    int udp_fd;
    struct sockaddr_storage local_addr;
    socklen_t local_addr_len;
    struct Libp2pTlsIdentity *tls_identity;
    const noise_identity_callbacks_t *callbacks;
    pthread_mutex_t lock;
    struct quic_listen_conn *pending;
    int shutting_down;
};

struct quic_listen_stream_ctx {
    struct Libp2pQuicListener *listener;
    struct quic_listen_conn *conn;
    lsquic_stream_t *ls_stream;
};

static void quic_listen_conn_release(struct quic_listen_conn *conn)
{
    if (!conn)
        return;
    conn->ref_count--;
    if (conn->ref_count <= 0)
        free(conn);
}

static int quic_debug_scope_enabled(void)
{
    return libp2p_v2_debug_scope_enabled("quic");
}

static void quic_dbg(const char *fmt, ...)
{
    if (!quic_debug_scope_enabled())
        return;
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "[quic-listen] ");
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fflush(stderr);
}

static SSL_CTX *quic_listen_get_ssl_ctx(void *peer_ctx, const struct sockaddr *local)
{
    (void)local;
    struct Libp2pQuicListener *listener = (struct Libp2pQuicListener *)peer_ctx;
    if (!listener || !listener->tls_identity)
        return NULL;
    return libp2p_tls_identity_ssl_ctx(listener->tls_identity);
}

static int quic_listen_packets_out(void *ctx, const struct lsquic_out_spec *specs,
                                   unsigned n_packets_out)
{
    struct Libp2pQuicListener *listener = (struct Libp2pQuicListener *)ctx;
    int total = 0;
    for (unsigned i = 0; i < n_packets_out; i++) {
        const struct lsquic_out_spec *spec = &specs[i];
        for (size_t j = 0; j < spec->iovlen; j++) {
            ssize_t n = sendto(listener->udp_fd,
                               spec->iov[j].iov_base,
                               spec->iov[j].iov_len,
                               0,
                               spec->dest_sa,
                               (spec->dest_sa->sa_family == AF_INET)
                                   ? sizeof(struct sockaddr_in)
                                   : sizeof(struct sockaddr_in6));
            if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                    return total;
                libp2p_v2_logger_error("quic-listen", "sendto failed: %s\n", strerror(errno));
                return -1;
            }
            total++;
        }
    }
    return total;
}

static void quic_listener_pump(struct Libp2pQuicListener *listener, int max_wait_ms)
{
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(listener->udp_fd, &rfds);
    struct timeval tv;
    tv.tv_sec = max_wait_ms / 1000;
    tv.tv_usec = (max_wait_ms % 1000) * 1000;

    int r = select(listener->udp_fd + 1, &rfds, NULL, NULL, &tv);
    if (r > 0) {
        unsigned char buf[4096];
        struct sockaddr_storage peer;
        socklen_t peer_len = sizeof(peer);
        ssize_t n = recvfrom(listener->udp_fd, buf, sizeof(buf), 0,
                             (struct sockaddr *)&peer, &peer_len);
        if (n > 0) {
            lsquic_engine_packet_in(listener->engine, buf, (size_t)n,
                                    (struct sockaddr *)&listener->local_addr,
                                    (struct sockaddr *)&peer, listener, 0);
        }
    }
    lsquic_engine_process_conns(listener->engine);
}

static lsquic_conn_ctx_t *quic_listen_on_new_conn(void *stream_if_ctx, lsquic_conn_t *c)
{
    struct Libp2pQuicListener *listener = (struct Libp2pQuicListener *)stream_if_ctx;
    struct quic_listen_conn *conn = (struct quic_listen_conn *)calloc(1, sizeof(*conn));
    if (!conn)
        return NULL;
    conn->conn = c;
    conn->handshake_status = 0;
    conn->stream_ready = 0;
    conn->ref_count = 1;

    pthread_mutex_lock(&listener->lock);
    conn->next = listener->pending;
    listener->pending = conn;
    pthread_mutex_unlock(&listener->lock);

    libp2p_v2_logger_info("quic-listen", "new inbound QUIC connection\n");
    quic_dbg("new inbound QUIC connection\n");
    return (lsquic_conn_ctx_t *)conn;
}

static void quic_listen_on_conn_closed(lsquic_conn_t *c)
{
    lsquic_conn_ctx_t *conn_ctx = lsquic_conn_get_ctx(c);
    if (!conn_ctx)
        return;
    struct quic_listen_conn *conn = (struct quic_listen_conn *)conn_ctx;
    conn->handshake_status = -1;
    conn->conn = NULL;
    libp2p_v2_logger_info("quic-listen", "QUIC connection closed\n");
    quic_dbg("QUIC connection closed\n");
    quic_listen_conn_release(conn);
}

static void quic_listen_on_hsk_done(lsquic_conn_t *c, enum lsquic_hsk_status s)
{
    lsquic_conn_ctx_t *conn_ctx = lsquic_conn_get_ctx(c);
    if (!conn_ctx)
        return;
    struct quic_listen_conn *conn = (struct quic_listen_conn *)conn_ctx;
    if (s == LSQ_HSK_OK || s == LSQ_HSK_RESUMED_OK) {
        conn->handshake_status = 1;
        libp2p_v2_logger_info("quic-listen", "QUIC handshake complete\n");
        quic_dbg("QUIC handshake complete\n");
    } else {
        conn->handshake_status = -1;
        libp2p_v2_logger_info("quic-listen", "QUIC handshake failed: %d\n", s);
        quic_dbg("QUIC handshake failed: %d\n", s);
    }
}

static lsquic_stream_ctx_t *quic_listen_on_new_stream(void *stream_if_ctx, lsquic_stream_t *s)
{
    (void)stream_if_ctx;
    lsquic_conn_t *conn = lsquic_stream_conn(s);
    lsquic_conn_ctx_t *conn_ctx = lsquic_conn_get_ctx(conn);
    if (!conn_ctx)
        return NULL;
    struct quic_listen_conn *lc = (struct quic_listen_conn *)conn_ctx;

    lc->stream = s;
    lc->stream_ready = 1;
    lc->expecting_outbound = 0;
    /* Inbound streams are bidirectional: we read the peer's request and
     * write our response. */
    lsquic_stream_wantread(s, 1);
    lsquic_stream_wantwrite(s, 1);
    libp2p_v2_logger_info("quic-listen", "new QUIC stream ready (outbound=%d)\n", lc->expecting_outbound);
    quic_dbg("new QUIC stream ready (outbound=%d)\n", lc->expecting_outbound);

    return (lsquic_stream_ctx_t *)lc;
}

static void quic_listen_on_read(lsquic_stream_t *s, lsquic_stream_ctx_t *h)
{
    (void)h;
    /* Keep read interest armed for the synchronous reader. */
    lsquic_stream_wantread(s, 1);
}

static void quic_listen_on_write(lsquic_stream_t *s, lsquic_stream_ctx_t *h)
{
    (void)s;
    (void)h;
}

static void quic_listen_on_close(lsquic_stream_t *s, lsquic_stream_ctx_t *h)
{
    (void)s;
    (void)h;
}

static const struct lsquic_stream_if quic_listen_stream_if = {
    .on_new_conn = quic_listen_on_new_conn,
    .on_conn_closed = quic_listen_on_conn_closed,
    .on_new_stream = quic_listen_on_new_stream,
    .on_hsk_done = quic_listen_on_hsk_done,
    .on_read = quic_listen_on_read,
    .on_write = quic_listen_on_write,
    .on_close = quic_listen_on_close,
};

static ssize_t quic_listen_stream_read(struct Libp2pV2Stream *stream, unsigned char *buf, size_t count)
{
    struct quic_listen_stream_ctx *sc = (struct quic_listen_stream_ctx *)stream->stream_context;
    if (!sc || !sc->ls_stream)
        return -1;

    lsquic_stream_wantread(sc->ls_stream, 1);
    ssize_t n = lsquic_stream_read(sc->ls_stream, buf, count);
    if (n > 0)
        return n;
    if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
        libp2p_v2_logger_error("quic-listen", "lsquic_stream_read error: %s\n", strerror(errno));
        return -1;
    }

    struct Libp2pQuicListener *listener = sc->listener;
    int waited = 0;
    while (waited < QUIC_LISTEN_READ_TIMEOUT_MS) {
        lsquic_stream_wantread(sc->ls_stream, 1);
        lsquic_engine_process_conns(listener->engine);
        lsquic_stream_wantread(sc->ls_stream, 1);
        n = lsquic_stream_read(sc->ls_stream, buf, count);
        if (n > 0)
            return n;
        if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            libp2p_v2_logger_error("quic-listen", "lsquic_stream_read error after poll: %s\n", strerror(errno));
            return -1;
        }
        quic_listener_pump(listener, 10);
        waited += 10;
    }
    libp2p_v2_logger_info("quic-listen", "stream read timed out after %d ms\n", QUIC_LISTEN_READ_TIMEOUT_MS);
    return 0;
}

static ssize_t quic_listen_stream_write(struct Libp2pV2Stream *stream, const unsigned char *buf, size_t count)
{
    struct quic_listen_stream_ctx *sc = (struct quic_listen_stream_ctx *)stream->stream_context;
    if (!sc || !sc->ls_stream)
        return -1;

    lsquic_stream_wantwrite(sc->ls_stream, 1);
    ssize_t n = lsquic_stream_write(sc->ls_stream, buf, count);
    if (n > 0) {
        lsquic_stream_flush(sc->ls_stream);
        lsquic_engine_process_conns(sc->listener->engine);
        libp2p_v2_logger_info("quic-listen", "stream wrote %zd/%zu bytes\n", n, count);
    } else if (n < 0) {
        libp2p_v2_logger_error("quic-listen", "lsquic_stream_write failed: %s\n", strerror(errno));
    }
    return n;
}

static void quic_listen_stream_close(struct Libp2pV2Stream *stream)
{
    if (!stream)
        return;
    struct quic_listen_stream_ctx *sc = (struct quic_listen_stream_ctx *)stream->stream_context;
    if (sc) {
        if (sc->ls_stream)
            lsquic_stream_close(sc->ls_stream);
        if (sc->conn) {
            sc->conn->stream_ready = 0;
            quic_listen_conn_release(sc->conn);
        }
        free(sc);
    }
    free(stream);
}

static struct quic_listen_conn *listener_find_ready(struct Libp2pQuicListener *listener)
{
    struct quic_listen_conn **curr = &listener->pending;
    while (*curr) {
        struct quic_listen_conn *c = *curr;
        if (c->handshake_status == 1 && c->stream_ready) {
            *curr = c->next;
            c->ref_count++;
            return c;
        }
        curr = &c->next;
    }
    return NULL;
}

struct Libp2pQuicListener* libp2p_net_quic_listener_new(const char *ip_address, uint16_t port,
                                                        void *private_key,
                                                        const noise_identity_callbacks_t *callbacks)
{
    if (!ip_address || !private_key || !callbacks)
        return NULL;

    struct Libp2pQuicListener *listener = (struct Libp2pQuicListener *)calloc(1, sizeof(*listener));
    if (!listener)
        return NULL;
    listener->udp_fd = -1;
    listener->callbacks = callbacks;
    pthread_mutex_init(&listener->lock, NULL);

    listener->tls_identity = libp2p_tls_identity_new(private_key, callbacks);
    if (!listener->tls_identity) {
        quic_dbg("failed to create TLS identity\n");
        goto err;
    }

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_NUMERICHOST | AI_PASSIVE;

    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%u", port);

    struct addrinfo *res = NULL;
    int gai_err = getaddrinfo(ip_address, port_str, &hints, &res);
    if (gai_err != 0 || !res) {
        quic_dbg("getaddrinfo for %s:%s failed: %s\n", ip_address, port_str, gai_strerror(gai_err));
        goto err;
    }

    int fd = socket(res->ai_family, SOCK_DGRAM, 0);
    if (fd < 0) {
        freeaddrinfo(res);
        goto err;
    }

    int reuse = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    if (bind(fd, res->ai_addr, res->ai_addrlen) != 0) {
        quic_dbg("bind %s:%s failed: %s\n", ip_address, port_str, strerror(errno));
        close(fd);
        freeaddrinfo(res);
        goto err;
    }

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
        close(fd);
        freeaddrinfo(res);
        goto err;
    }

    memcpy(&listener->local_addr, res->ai_addr, res->ai_addrlen);
    listener->local_addr_len = res->ai_addrlen;
    listener->udp_fd = fd;
    freeaddrinfo(res);

    socklen_t len = sizeof(listener->local_addr);
    if (getsockname(fd, (struct sockaddr *)&listener->local_addr, &len) != 0) {
        quic_dbg("getsockname failed: %s\n", strerror(errno));
        goto err;
    }
    listener->local_addr_len = len;

    lsquic_global_init(LSQUIC_GLOBAL_SERVER | LSQUIC_GLOBAL_CLIENT);

    struct lsquic_engine_api api;
    memset(&api, 0, sizeof(api));
    api.ea_stream_if = &quic_listen_stream_if;
    api.ea_stream_if_ctx = listener;
    api.ea_packets_out = quic_listen_packets_out;
    api.ea_packets_out_ctx = listener;
    api.ea_get_ssl_ctx = quic_listen_get_ssl_ctx;
    api.ea_alpn = "libp2p";

    struct lsquic_engine_settings settings;
    lsquic_engine_init_settings(&settings, LSENG_SERVER);
    settings.es_init_max_streams_bidi = 100;
    settings.es_init_max_stream_data_bidi_local = 1 * 1024 * 1024;
    settings.es_init_max_stream_data_bidi_remote = 1 * 1024 * 1024;
    api.ea_settings = &settings;

    listener->engine = lsquic_engine_new(LSENG_SERVER, &api);
    if (!listener->engine) {
        quic_dbg("lsquic_engine_new(server) failed\n");
        goto err;
    }

    quic_dbg("QUIC listener created on %s:%u (fd=%d)\n", ip_address, port, fd);
    return listener;

err:
    libp2p_net_quic_listener_free(listener);
    return NULL;
}

struct Libp2pV2Stream* libp2p_net_quic_listener_accept(struct Libp2pQuicListener *listener)
{
    if (!listener || listener->shutting_down)
        return NULL;

    int waited = 0;
    while (waited < QUIC_LISTEN_ACCEPT_TIMEOUT_MS) {
        pthread_mutex_lock(&listener->lock);
        struct quic_listen_conn *lc = listener_find_ready(listener);
        pthread_mutex_unlock(&listener->lock);

        if (lc) {
            struct quic_listen_stream_ctx *sc = (struct quic_listen_stream_ctx *)calloc(1, sizeof(*sc));
            if (!sc) {
                lsquic_stream_close(lc->stream);
                free(lc);
                return NULL;
            }
            sc->listener = listener;
            sc->conn = lc;
            sc->ls_stream = lc->stream;

            struct Libp2pV2Stream *stream = (struct Libp2pV2Stream *)calloc(1, sizeof(*stream));
            if (!stream) {
                free(sc);
                lsquic_stream_close(lc->stream);
                free(lc);
                return NULL;
            }
            stream->stream_context = sc;
            stream->read = quic_listen_stream_read;
            stream->write = quic_listen_stream_write;
            stream->close = quic_listen_stream_close;

            quic_dbg("accepted inbound QUIC stream\n");
            return stream;
        }

        quic_listener_pump(listener, 10);
        waited += 10;
    }

    quic_dbg("QUIC accept timed out\n");
    return NULL;
}

void libp2p_net_quic_listener_free(struct Libp2pQuicListener *listener)
{
    if (!listener)
        return;
    listener->shutting_down = 1;
    if (listener->engine)
        lsquic_engine_destroy(listener->engine);
    if (listener->udp_fd >= 0)
        close(listener->udp_fd);
    libp2p_tls_identity_free(listener->tls_identity);
    pthread_mutex_destroy(&listener->lock);
    free(listener);
}

struct Libp2pV2Stream* libp2p_net_quic_conn_open_stream(struct Libp2pV2Stream *accepted_stream)
{
    if (!accepted_stream)
        return NULL;
    struct quic_listen_stream_ctx *sc = (struct quic_listen_stream_ctx *)accepted_stream->stream_context;
    if (!sc || !sc->listener || !sc->conn)
        return NULL;

    struct Libp2pQuicListener *listener = sc->listener;
    struct quic_listen_conn *lc = sc->conn;

    /* Take a reference for the outbound stream we are about to create. */
    lc->ref_count++;

    /* Reset state so the next on_new_stream callback is captured as the
     * outbound stream we are about to create. */
    lc->stream_ready = 0;
    lc->expecting_outbound = 1;
    lc->stream = NULL;

    if (!lc->conn) {
        quic_dbg("cannot open stream: underlying QUIC connection is gone\n");
        return NULL;
    }

    lsquic_conn_make_stream(lc->conn);
    lsquic_engine_process_conns(listener->engine);

    int waited = 0;
    while (waited < QUIC_LISTEN_ACCEPT_TIMEOUT_MS) {
        if (lc->stream_ready && lc->stream)
            break;
        quic_listener_pump(listener, 10);
        waited += 10;
    }

    if (!lc->stream_ready || !lc->stream) {
        quic_dbg("timed out waiting for outbound QUIC stream\n");
        return NULL;
    }

    struct quic_listen_stream_ctx *new_sc = (struct quic_listen_stream_ctx *)calloc(1, sizeof(*new_sc));
    if (!new_sc)
        return NULL;
    new_sc->listener = listener;
    new_sc->conn = lc;
    new_sc->ls_stream = lc->stream;

    struct Libp2pV2Stream *stream = (struct Libp2pV2Stream *)calloc(1, sizeof(*stream));
    if (!stream) {
        free(new_sc);
        return NULL;
    }
    stream->stream_context = new_sc;
    stream->read = quic_listen_stream_read;
    stream->write = quic_listen_stream_write;
    stream->close = quic_listen_stream_close;

    quic_dbg("opened outbound QUIC stream on accepted connection\n");
    return stream;
}

#else /* !HAS_LSQUIC */

#include <stddef.h>
#include "libp2p/net/quic.h"

struct Libp2pQuicListener* libp2p_net_quic_listener_new(const char *ip_address, uint16_t port,
                                                        void *private_key,
                                                        const noise_identity_callbacks_t *callbacks)
{
    (void)ip_address;
    (void)port;
    (void)private_key;
    (void)callbacks;
    return NULL;
}

struct Libp2pV2Stream* libp2p_net_quic_listener_accept(struct Libp2pQuicListener *listener)
{
    (void)listener;
    return NULL;
}

void libp2p_net_quic_listener_free(struct Libp2pQuicListener *listener)
{
    (void)listener;
}

struct Libp2pV2Stream* libp2p_net_quic_conn_open_stream(struct Libp2pV2Stream *accepted_stream)
{
    (void)accepted_stream;
    return NULL;
}

#endif /* HAS_LSQUIC */
