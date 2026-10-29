#ifdef HAS_LSQUIC

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
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

#define QUIC_DIAL_TIMEOUT_MS 30000
#define QUIC_READ_TIMEOUT_MS 30000

struct quic_dial_ctx {
    lsquic_engine_t *engine;
    int udp_fd;
    struct sockaddr_storage local_addr;
    socklen_t local_addr_len;
    struct sockaddr_storage peer_addr;
    socklen_t peer_addr_len;
    struct Libp2pTlsIdentity *tls_identity;
    const noise_identity_callbacks_t *callbacks;
    char *expected_peer_id;
    int handshake_status; /* 0 = pending, 1 = ok, -1 = failed */
    lsquic_conn_t *conn;
    lsquic_stream_t *outbound_stream;
    lsquic_stream_t *inbound_stream;
    int outbound_ready;
    int inbound_ready;
    int error;
};

struct quic_stream_ctx {
    struct quic_dial_ctx *dial;
    lsquic_stream_t *ls_stream;
    int owns_dial; /* true for the outbound stream; frees engine on close */
};

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
    fprintf(stderr, "[quic] ");
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fflush(stderr);
}

static void quic_process_incoming(struct quic_dial_ctx *dial, int max_wait_ms)
{
    struct timeval tv;
    tv.tv_sec = max_wait_ms / 1000;
    tv.tv_usec = (max_wait_ms % 1000) * 1000;

    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(dial->udp_fd, &rfds);

    int r = select(dial->udp_fd + 1, &rfds, NULL, NULL, &tv);
    if (r <= 0)
        return;

    unsigned char buf[4096];
    struct sockaddr_storage peer;
    socklen_t peer_len = sizeof(peer);
    ssize_t n = recvfrom(dial->udp_fd, buf, sizeof(buf), 0,
                         (struct sockaddr *)&peer, &peer_len);
    if (n > 0) {
        lsquic_engine_packet_in(dial->engine, buf, (size_t)n,
                                (struct sockaddr *)&dial->local_addr,
                                (struct sockaddr *)&peer, dial, 0);
    }
}

static void quic_drive_engine(struct quic_dial_ctx *dial, int max_wait_ms)
{
    lsquic_engine_process_conns(dial->engine);
    if (max_wait_ms > 0)
        quic_process_incoming(dial, max_wait_ms);
    lsquic_engine_process_conns(dial->engine);
}

static int quic_packets_out(void *ctx, const struct lsquic_out_spec *specs,
                            unsigned n_packets_out)
{
    struct quic_dial_ctx *dial = (struct quic_dial_ctx *)ctx;
    int total = 0;
    for (unsigned i = 0; i < n_packets_out; i++) {
        const struct lsquic_out_spec *spec = &specs[i];
        for (size_t j = 0; j < spec->iovlen; j++) {
            ssize_t n = sendto(dial->udp_fd,
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
                libp2p_v2_logger_error("quic", "sendto failed: %s\n", strerror(errno));
                return -1;
            }
            total++;
        }
    }
    return total;
}

static SSL_CTX *quic_get_ssl_ctx(void *peer_ctx, const struct sockaddr *local)
{
    (void)local;
    struct quic_dial_ctx *dial = (struct quic_dial_ctx *)peer_ctx;
    if (!dial || !dial->tls_identity)
        return NULL;
    return libp2p_tls_identity_ssl_ctx(dial->tls_identity);
}

static int quic_verify_cert(void *verify_ctx, struct stack_st_X509 *chain)
{
    struct quic_dial_ctx *dial = (struct quic_dial_ctx *)verify_ctx;
    if (!dial || !chain)
        return -1;
    if (sk_X509_num(chain) != 1) {
        libp2p_v2_logger_error("quic", "expected exactly one certificate, got %d\n", sk_X509_num(chain));
        quic_dbg("expected exactly one certificate, got %d\n", sk_X509_num(chain));
        return -1;
    }
    X509 *cert = sk_X509_value(chain, 0);
    if (!cert)
        return -1;
    if (!libp2p_tls_verify_peer_cert(cert, dial->expected_peer_id, dial->callbacks)) {
        libp2p_v2_logger_error("quic", "peer certificate verification failed\n");
        quic_dbg("peer certificate verification failed\n");
        return -1;
    }
    libp2p_v2_logger_info("quic", "peer certificate verified\n");
    quic_dbg("peer certificate verified\n");
    return 0;
}

static lsquic_conn_ctx_t *quic_on_new_conn(void *stream_if_ctx, lsquic_conn_t *c)
{
    struct quic_dial_ctx *dial = (struct quic_dial_ctx *)stream_if_ctx;
    dial->conn = c;
    libp2p_v2_logger_info("quic", "new QUIC connection\n");
    quic_dbg("new QUIC connection\n");
    return (lsquic_conn_ctx_t *)dial;
}

static void quic_on_conn_closed(lsquic_conn_t *c)
{
    lsquic_conn_ctx_t *conn_ctx = lsquic_conn_get_ctx(c);
    if (!conn_ctx)
        return;
    struct quic_dial_ctx *dial = (struct quic_dial_ctx *)conn_ctx;
    dial->error = 1;
    /* lsquic frees the connection and its streams after this callback. */
    dial->conn = NULL;
    dial->outbound_stream = NULL;
    dial->inbound_stream = NULL;
    libp2p_v2_logger_info("quic", "QUIC connection closed\n");
    quic_dbg("QUIC connection closed\n");
}

static void quic_on_hsk_done(lsquic_conn_t *c, enum lsquic_hsk_status s)
{
    lsquic_conn_ctx_t *conn_ctx = lsquic_conn_get_ctx(c);
    if (!conn_ctx)
        return;
    struct quic_dial_ctx *dial = (struct quic_dial_ctx *)conn_ctx;
    if (s == LSQ_HSK_OK || s == LSQ_HSK_RESUMED_OK) {
        dial->handshake_status = 1;
        libp2p_v2_logger_info("quic", "QUIC handshake complete\n");
        quic_dbg("QUIC handshake complete\n");
        lsquic_conn_make_stream(c);
    } else {
        dial->handshake_status = -1;
        libp2p_v2_logger_info("quic", "QUIC handshake failed: %d\n", s);
        quic_dbg("QUIC handshake failed: %d\n", s);
    }
}

static lsquic_stream_ctx_t *quic_on_new_stream(void *stream_if_ctx, lsquic_stream_t *s)
{
    struct quic_dial_ctx *dial = (struct quic_dial_ctx *)stream_if_ctx;
    if (!dial->outbound_ready) {
        dial->outbound_stream = s;
        dial->outbound_ready = 1;
        /* Outbound bidirectional streams carry both our writes and the peer's
         * replies; lsquic needs wantread set before it will buffer incoming
         * data for synchronous lsquic_stream_read calls. */
        lsquic_stream_wantwrite(s, 1);
        lsquic_stream_wantread(s, 1);
        libp2p_v2_logger_info("quic", "outbound QUIC stream ready\n");
        quic_dbg("outbound QUIC stream ready\n");
    } else {
        dial->inbound_stream = s;
        dial->inbound_ready = 1;
        lsquic_stream_wantread(s, 1);
        libp2p_v2_logger_info("quic", "inbound QUIC stream ready\n");
        quic_dbg("inbound QUIC stream ready\n");
    }
    return (lsquic_stream_ctx_t *)dial;
}

/* Data is pulled synchronously via lsquic_stream_read/write.  Keep read
 * interest armed so lsquic continues to buffer incoming data until the
 * synchronous reader consumes it. */
static void quic_on_read(lsquic_stream_t *s, lsquic_stream_ctx_t *h)
{
    (void)h;
    lsquic_stream_wantread(s, 1);
}

static void quic_on_write(lsquic_stream_t *s, lsquic_stream_ctx_t *h)
{
    (void)h;
    lsquic_stream_wantwrite(s, 0);
}

static void quic_on_close(lsquic_stream_t *s, lsquic_stream_ctx_t *h)
{
    struct quic_dial_ctx *dial = (struct quic_dial_ctx *)h;
    if (!dial)
        return;
    if (dial->outbound_stream == s)
        dial->outbound_stream = NULL;
    if (dial->inbound_stream == s)
        dial->inbound_stream = NULL;
}

static const struct lsquic_stream_if quic_stream_if = {
    .on_new_conn = quic_on_new_conn,
    .on_conn_closed = quic_on_conn_closed,
    .on_new_stream = quic_on_new_stream,
    .on_read = quic_on_read,
    .on_write = quic_on_write,
    .on_close = quic_on_close,
    .on_hsk_done = quic_on_hsk_done,
};

static ssize_t quic_stream_read(struct Libp2pV2Stream *stream, unsigned char *buf, size_t count)
{
    struct quic_stream_ctx *sc = (struct quic_stream_ctx *)stream->stream_context;
    if (!sc || !sc->ls_stream)
        return -1;

    lsquic_stream_wantread(sc->ls_stream, 1);
    ssize_t n = lsquic_stream_read(sc->ls_stream, buf, count);
    if (n > 0)
        return n;

    /* lsquic returns -1/EAGAIN when no data is available yet.  Treat that the
     * same as zero and poll for QUIC_READ_TIMEOUT_MS before giving up. */
    if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
        libp2p_v2_logger_error("quic", "lsquic_stream_read error: %s\n", strerror(errno));
        return -1;
    }

    /* No buffered data: drive the engine until data arrives or timeout.
     * Re-enable read interest before each poll and before each read so that
     * an on_read callback that fires while we are between reads cannot leave
     * the stream without read interest. */
    struct quic_dial_ctx *dial = sc->dial;
    int waited = 0;
    while (waited < QUIC_READ_TIMEOUT_MS) {
        lsquic_stream_wantread(sc->ls_stream, 1);
        lsquic_engine_process_conns(dial->engine);
        lsquic_stream_wantread(sc->ls_stream, 1);
        n = lsquic_stream_read(sc->ls_stream, buf, count);
        if (n > 0)
            return n;
        if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            libp2p_v2_logger_error("quic", "lsquic_stream_read error after poll: %s\n", strerror(errno));
            return -1;
        }
        quic_process_incoming(dial, 10);
        waited += 10;
    }
    libp2p_v2_logger_info("quic", "stream read timed out after %d ms\n", QUIC_READ_TIMEOUT_MS);
    return 0;
}

static ssize_t quic_stream_write(struct Libp2pV2Stream *stream, const unsigned char *buf, size_t count)
{
    struct quic_stream_ctx *sc = (struct quic_stream_ctx *)stream->stream_context;
    if (!sc || !sc->ls_stream)
        return -1;

    lsquic_stream_wantwrite(sc->ls_stream, 1);
    ssize_t n = lsquic_stream_write(sc->ls_stream, buf, count);
    if (n > 0) {
        lsquic_stream_flush(sc->ls_stream);
        lsquic_engine_process_conns(sc->dial->engine);
        libp2p_v2_logger_info("quic", "stream wrote %zd/%zu bytes\n", n, count);
    } else if (n < 0) {
        libp2p_v2_logger_error("quic", "lsquic_stream_write failed: %s\n", strerror(errno));
    } else {
        libp2p_v2_logger_info("quic", "lsquic_stream_write returned 0 for %zu bytes\n", count);
    }
    return n;
}

static void quic_stream_close(struct Libp2pV2Stream *stream)
{
    if (!stream)
        return;
    struct quic_stream_ctx *sc = (struct quic_stream_ctx *)stream->stream_context;
    if (sc) {
        /* Only close streams lsquic still owns (on_close clears the rest). */
        if (sc->ls_stream && sc->dial &&
            (sc->dial->outbound_stream == sc->ls_stream ||
             sc->dial->inbound_stream == sc->ls_stream))
            lsquic_stream_close(sc->ls_stream);
        if (sc->dial && sc->owns_dial) {
            if (sc->dial->conn)
                lsquic_conn_close(sc->dial->conn);
            if (sc->dial->engine)
                lsquic_engine_destroy(sc->dial->engine);
            if (sc->dial->udp_fd >= 0)
                close(sc->dial->udp_fd);
            libp2p_tls_identity_free(sc->dial->tls_identity);
            free(sc->dial->expected_peer_id);
            free(sc->dial);
        }
        free(sc);
    }
    free(stream);
}

static int quic_bind_local(int *out_fd, struct sockaddr_storage *out_addr, socklen_t *out_len,
                           int family)
{
    int fd = socket(family, SOCK_DGRAM, 0);
    if (fd < 0)
        return 0;

    struct sockaddr_storage addr;
    memset(&addr, 0, sizeof(addr));
    addr.ss_family = family;
    if (family == AF_INET) {
        ((struct sockaddr_in *)&addr)->sin_port = 0;
        ((struct sockaddr_in *)&addr)->sin_addr.s_addr = INADDR_ANY;
        *out_len = sizeof(struct sockaddr_in);
    } else {
        ((struct sockaddr_in6 *)&addr)->sin6_port = 0;
        ((struct sockaddr_in6 *)&addr)->sin6_addr = in6addr_any;
        *out_len = sizeof(struct sockaddr_in6);
    }

    if (bind(fd, (struct sockaddr *)&addr, *out_len) != 0) {
        close(fd);
        return 0;
    }

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
        close(fd);
        return 0;
    }

    socklen_t len = sizeof(*out_addr);
    if (getsockname(fd, (struct sockaddr *)out_addr, &len) != 0) {
        close(fd);
        return 0;
    }
    *out_len = len;
    *out_fd = fd;
    return 1;
}

struct Libp2pV2Stream* libp2p_net_quic_dial(const char *ip_address, uint16_t port,
                                            void *private_key,
                                            const char *expected_peer_id,
                                            const noise_identity_callbacks_t *callbacks)
{
    if (!ip_address || !private_key || !callbacks)
        return NULL;

    struct quic_dial_ctx *dial = (struct quic_dial_ctx *)calloc(1, sizeof(*dial));
    if (!dial)
        return NULL;
    dial->udp_fd = -1;
    dial->callbacks = callbacks;
    if (expected_peer_id) {
        dial->expected_peer_id = strdup(expected_peer_id);
        if (!dial->expected_peer_id)
            goto err;
    }

    dial->tls_identity = libp2p_tls_identity_new(private_key, callbacks);
    if (!dial->tls_identity) {
        quic_dbg("failed to create TLS identity\n");
        goto err;
    }

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_NUMERICHOST;

    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%u", port);

    struct addrinfo *res = NULL;
    int gai_err = getaddrinfo(ip_address, port_str, &hints, &res);
    if (gai_err != 0 || !res) {
        quic_dbg("getaddrinfo for %s:%s failed: %s\n", ip_address, port_str, gai_strerror(gai_err));
        goto err;
    }

    memcpy(&dial->peer_addr, res->ai_addr, res->ai_addrlen);
    dial->peer_addr_len = res->ai_addrlen;
    int family = res->ai_family;
    freeaddrinfo(res);

    if (!quic_bind_local(&dial->udp_fd, &dial->local_addr, &dial->local_addr_len, family)) {
        quic_dbg("failed to bind local UDP socket\n");
        goto err;
    }

    lsquic_global_init(LSQUIC_GLOBAL_CLIENT);

    struct lsquic_engine_api api;
    memset(&api, 0, sizeof(api));
    api.ea_stream_if = &quic_stream_if;
    api.ea_stream_if_ctx = dial;
    api.ea_packets_out = quic_packets_out;
    api.ea_packets_out_ctx = dial;
    api.ea_get_ssl_ctx = quic_get_ssl_ctx;
    api.ea_verify_cert = quic_verify_cert;
    api.ea_verify_ctx = dial;
    api.ea_alpn = "libp2p";

    struct lsquic_engine_settings settings;
    lsquic_engine_init_settings(&settings, 0);
    api.ea_settings = &settings;

    dial->engine = lsquic_engine_new(0, &api);
    if (!dial->engine) {
        quic_dbg("lsquic_engine_new failed\n");
        goto err;
    }

    lsquic_conn_t *conn = lsquic_engine_connect(dial->engine, N_LSQVER,
                                                (struct sockaddr *)&dial->local_addr,
                                                (struct sockaddr *)&dial->peer_addr,
                                                dial, NULL, NULL, 0, NULL, 0, NULL, 0);
    if (!conn) {
        quic_dbg("lsquic_engine_connect failed\n");
        goto err;
    }

    int waited = 0;
    while (waited < QUIC_DIAL_TIMEOUT_MS) {
        quic_drive_engine(dial, 10);
        if (dial->handshake_status == -1 || dial->error) {
            libp2p_v2_logger_error("quic", "QUIC dial failed during handshake\n");
            quic_dbg("QUIC dial failed during handshake\n");
            goto err;
        }
        if (dial->outbound_ready)
            break;
        waited += 10;
    }

    if (!dial->outbound_ready) {
        libp2p_v2_logger_error("quic", "QUIC dial timed out waiting for outbound stream\n");
        quic_dbg("QUIC dial timed out waiting for outbound stream\n");
        goto err;
    }

    struct quic_stream_ctx *sc = (struct quic_stream_ctx *)calloc(1, sizeof(*sc));
    if (!sc)
        goto err;
    sc->dial = dial;
    sc->ls_stream = dial->outbound_stream;
    sc->owns_dial = 1;

    struct Libp2pV2Stream *stream = (struct Libp2pV2Stream *)calloc(1, sizeof(*stream));
    if (!stream) {
        free(sc);
        goto err;
    }
    stream->stream_context = sc;
    stream->read = quic_stream_read;
    stream->write = quic_stream_write;
    stream->close = quic_stream_close;

    libp2p_v2_logger_info("quic", "QUIC dial to %s:%u succeeded\n", ip_address, port);
    quic_dbg("QUIC dial to %s:%u succeeded\n", ip_address, port);
    return stream;

err:
    if (dial) {
        if (dial->outbound_stream)
            lsquic_stream_close(dial->outbound_stream);
        if (dial->inbound_stream)
            lsquic_stream_close(dial->inbound_stream);
        if (dial->conn)
            lsquic_conn_close(dial->conn);
        if (dial->engine)
            lsquic_engine_destroy(dial->engine);
        if (dial->udp_fd >= 0)
            close(dial->udp_fd);
        libp2p_tls_identity_free(dial->tls_identity);
        free(dial->expected_peer_id);
        free(dial);
    }
    return NULL;
}

struct Libp2pV2Stream* libp2p_net_quic_accept_stream(struct Libp2pV2Stream *outbound_stream)
{
    if (!outbound_stream)
        return NULL;
    struct quic_stream_ctx *out_sc = (struct quic_stream_ctx *)outbound_stream->stream_context;
    if (!out_sc || !out_sc->dial)
        return NULL;
    struct quic_dial_ctx *dial = out_sc->dial;

    int waited = 0;
    while (waited < QUIC_DIAL_TIMEOUT_MS) {
        if (dial->inbound_ready)
            break;
        quic_drive_engine(dial, 10);
        waited += 10;
    }
    if (!dial->inbound_ready)
        return NULL;

    struct quic_stream_ctx *sc = (struct quic_stream_ctx *)calloc(1, sizeof(*sc));
    if (!sc)
        return NULL;
    sc->dial = dial;
    sc->ls_stream = dial->inbound_stream;
    sc->owns_dial = 0;

    struct Libp2pV2Stream *stream = (struct Libp2pV2Stream *)calloc(1, sizeof(*stream));
    if (!stream) {
        free(sc);
        return NULL;
    }
    stream->stream_context = sc;
    stream->read = quic_stream_read;
    stream->write = quic_stream_write;
    stream->close = quic_stream_close;
    return stream;
}

#else /* !HAS_LSQUIC */

#include <stddef.h>
#include "libp2p/net/quic.h"

struct Libp2pV2Stream* libp2p_net_quic_dial(const char *ip_address, uint16_t port,
                                            void *private_key,
                                            const char *expected_peer_id,
                                            const noise_identity_callbacks_t *callbacks)
{
    (void)ip_address;
    (void)port;
    (void)private_key;
    (void)expected_peer_id;
    (void)callbacks;
    return NULL;
}

struct Libp2pV2Stream* libp2p_net_quic_accept_stream(struct Libp2pV2Stream *outbound_stream)
{
    (void)outbound_stream;
    return NULL;
}

#endif /* HAS_LSQUIC */
