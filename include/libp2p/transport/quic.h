#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * libp2p stream abstraction v2.
 *
 * Designed to be embedded as the first member of transport-specific
 * stream implementations so that up-casting works in C.
 */
typedef struct libp2p_stream {
    ssize_t (*read)(struct libp2p_stream *stream, uint8_t *buf, size_t len);
    ssize_t (*write)(struct libp2p_stream *stream, const uint8_t *buf, size_t len);
    void (*close)(struct libp2p_stream *stream);
    void *user_data;
} libp2p_stream_t;

/**
 * libp2p transport abstraction v2.
 *
 * Provides dial and listen capabilities for a specific multiaddr protocol.
 */
typedef struct libp2p_transport {
    const char *name;
    int (*dial)(struct libp2p_transport *self, const char *multiaddr, libp2p_stream_t **out_stream);
    int (*listen)(struct libp2p_transport *self, const char *multiaddr);
    void (*close)(struct libp2p_transport *self);
    void *user_data;
} libp2p_transport_t;

/**
 * Create a QUIC-v1 transport backed by lsquic.
 *
 * @param tls_ctx An OpenSSL SSL_CTX configured for libp2p TLS 1.3.
 * @return A libp2p_transport_t pointer, or NULL on error.
 *
 * Note: lsquic must be available at compile time (HAVE_LSQUIC defined).
 * If lsquic is not available, this function returns NULL.
 */
libp2p_transport_t *libp2p_quic_transport_create(void *tls_ctx);

#ifdef __cplusplus
}
#endif
