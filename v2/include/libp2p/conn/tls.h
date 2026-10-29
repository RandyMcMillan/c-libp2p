#ifndef LIBP2P_CONN_TLS_H
#define LIBP2P_CONN_TLS_H

#include <openssl/ssl.h>
#include "libp2p/conn/noise.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * libp2p TLS 1.3 identity for QUIC (and future TCP/TLS).
 *
 * The identity owns an ephemeral ECDSA P-256 certificate that contains the
 * libp2p Public Key Extension (OID 1.3.6.1.4.1.53594.1.1).  The extension
 * carries the host's protobuf-encoded public key and a self-signature over
 * "libp2p-tls-handshake:" || cert SubjectPublicKeyInfo DER.
 *
 * This implementation requires a BoringSSL-compatible TLS stack and is only
 * built when HAS_LSQUIC is defined.
 */
struct Libp2pTlsIdentity;

/**
 * Create a new TLS identity from the node's private key.
 *
 * @param private_key The node's identity private key (e.g. struct RsaPrivateKey*).
 * @param callbacks   Callbacks used to retrieve the protobuf public key and
 *                    to sign/verify with the node's identity key.
 * @return A new identity, or NULL on error.
 */
struct Libp2pTlsIdentity* libp2p_tls_identity_new(void *private_key,
                                                  const noise_identity_callbacks_t *callbacks);

/**
 * Free a TLS identity and its underlying certificate/key material.
 */
void libp2p_tls_identity_free(struct Libp2pTlsIdentity *identity);

/**
 * Return the shared SSL_CTX configured with the identity certificate and
 * libp2p ALPN.  The context is owned by the identity and must not be freed
 * by the caller.
 */
SSL_CTX* libp2p_tls_identity_ssl_ctx(struct Libp2pTlsIdentity *identity);

/**
 * Verify a peer certificate chain according to the libp2p TLS spec.
 *
 * @param cert              The peer's end-entity certificate.
 * @param expected_peer_id  Optional expected peer ID string.  If non-NULL and
 *                          the certificate authenticates a different peer,
 *                          verification fails.
 * @param callbacks         Callbacks used to decode the peer public key and
 *                          verify the extension signature.
 * @return 1 on success, 0 on failure.
 */
int libp2p_tls_verify_peer_cert(X509 *cert,
                                const char *expected_peer_id,
                                const noise_identity_callbacks_t *callbacks);

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_CONN_TLS_H */
