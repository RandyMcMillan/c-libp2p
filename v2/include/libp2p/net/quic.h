#ifndef LIBP2P_NET_QUIC_H
#define LIBP2P_NET_QUIC_H

#include <stdint.h>
#include "libp2p/conn/noise.h"
#include "libp2p/net/tcp.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Dial a remote peer over QUIC (RFC 9000) using the libp2p TLS 1.3
 * handshake and ALPN "libp2p".
 *
 * @param ip_address        Remote IP address (IPv4 or IPv6).
 * @param port              Remote UDP port.
 * @param private_key       Node identity private key (e.g. struct RsaPrivateKey*).
 * @param expected_peer_id  Expected libp2p peer ID, or NULL to accept any.
 * @param callbacks         Identity callbacks used to sign/verify the TLS
 *                          extension and derive peer IDs.
 * @return A Libp2pV2Stream for the first QUIC stream, or NULL on error.
 */
struct Libp2pV2Stream* libp2p_net_quic_dial(const char *ip_address, uint16_t port,
                                            void *private_key,
                                            const char *expected_peer_id,
                                            const noise_identity_callbacks_t *callbacks);

/**
 * Accept the next remotely-opened QUIC stream on the same connection as the
 * given outbound stream.  This blocks until a stream arrives or the timeout
 * expires.
 */
struct Libp2pV2Stream* libp2p_net_quic_accept_stream(struct Libp2pV2Stream *outbound_stream);

/**
 * Opaque QUIC server listener.  Created by libp2p_net_quic_listener_new()
 * and destroyed by libp2p_net_quic_listener_free().
 */
struct Libp2pQuicListener;

/**
 * Create a QUIC listener on the given IP address and UDP port.
 *
 * @param ip_address  Local IP address (IPv4 or IPv6).
 * @param port        Local UDP port.
 * @param private_key Node identity private key.
 * @param callbacks   Identity callbacks for signing/verifying the TLS
 *                    extension and deriving peer IDs.
 * @return A listener handle, or NULL on error.
 */
struct Libp2pQuicListener* libp2p_net_quic_listener_new(const char *ip_address, uint16_t port,
                                                        void *private_key,
                                                        const noise_identity_callbacks_t *callbacks);

/**
 * Accept the next inbound QUIC stream from a remote peer.  This blocks until
 * a stream is available or the internal timeout expires.
 *
 * @return A Libp2pV2Stream for the accepted stream, or NULL on timeout/error.
 */
struct Libp2pV2Stream* libp2p_net_quic_listener_accept(struct Libp2pQuicListener *listener);

/**
 * Destroy a QUIC listener and close all associated resources.
 */
void libp2p_net_quic_listener_free(struct Libp2pQuicListener *listener);

/**
 * Open a new outbound stream on the same QUIC connection as an accepted
 * inbound stream.  Blocks until the stream is ready or the timeout expires.
 *
 * @param accepted_stream A stream previously returned by
 *                        libp2p_net_quic_listener_accept().
 * @return A new outbound Libp2pV2Stream, or NULL on error/timeout.
 */
struct Libp2pV2Stream* libp2p_net_quic_conn_open_stream(struct Libp2pV2Stream *accepted_stream);

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_NET_QUIC_H */
