#ifndef __LIBP2P_CRYPTO_VERIFY_H__
#define __LIBP2P_CRYPTO_VERIFY_H__

#include <stdint.h>
#include <stddef.h>

/**
 * Verify an Ed25519 signature using OpenSSL/BoringSSL EVP.
 *
 * @param pubkey the raw 32-byte public key
 * @param pubkey_len must be 32
 * @param msg the message that was signed
 * @param msg_len the message length
 * @param sig the signature bytes
 * @param sig_len the signature length
 * @returns 1 on valid signature, 0 otherwise
 */
int libp2p_crypto_verify_ed25519(const uint8_t *pubkey, size_t pubkey_len,
                                 const uint8_t *msg, size_t msg_len,
                                 const uint8_t *sig, size_t sig_len);

#endif
