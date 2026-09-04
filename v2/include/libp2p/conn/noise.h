#ifndef LIBP2P_CONN_NOISE_H
#define LIBP2P_CONN_NOISE_H

#include <stddef.h>
#include <stdint.h>
#include "libp2p/net/tcp.h"

struct Libp2pPeer;

/**
 * Callbacks for libp2p-specific Noise identity payload.
 * The caller (main daemon) provides these to sign/verify
 * using the node's identity key (RSA, Ed25519, etc.).
 */
typedef struct {
    /**
     * Retrieve the protobuf-encoded public identity key.
     * @param private_key The daemon's private key handle.
     * @param out_key     Output buffer (malloc'd by callee, freed by free_buffer).
     * @param out_len     Length of encoded key.
     * @return 1 on success, 0 on failure.
     */
    int (*get_identity_key)(void *private_key, uint8_t **out_key, size_t *out_len);

    /**
     * Sign a message with the identity private key.
     * @param private_key The daemon's private key handle.
     * @param data        Message to sign.
     * @param data_len    Message length.
     * @param out_sig     Output signature buffer (malloc'd by callee, freed by free_buffer).
     * @param out_len     Signature length.
     * @return 1 on success, 0 on failure.
     */
    int (*sign)(void *private_key, const uint8_t *data, size_t data_len, uint8_t **out_sig, size_t *out_len);

    /**
     * Verify a signature against an identity public key.
     * @param identity_key     Protobuf-encoded public key.
     * @param identity_key_len Length of public key.
     * @param data             Signed message.
     * @param data_len         Message length.
     * @param sig              Signature bytes.
     * @param sig_len          Signature length.
     * @return 1 if valid, 0 if invalid.
     */
    int (*verify)(const uint8_t *identity_key, size_t identity_key_len,
                  const uint8_t *data, size_t data_len,
                  const uint8_t *sig, size_t sig_len);

    /** Free a buffer allocated by get_identity_key or sign. */
    void (*free_buffer)(uint8_t *buf);
} noise_identity_callbacks_t;

struct Libp2pV2Stream* libp2p_noise_handshake(struct Libp2pV2Stream* raw_stream, void* private_key,
                                      struct Libp2pPeer* peer,
                                      const noise_identity_callbacks_t *callbacks);

#endif /* LIBP2P_CONN_NOISE_H */
