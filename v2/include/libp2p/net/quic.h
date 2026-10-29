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

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_NET_QUIC_H */
