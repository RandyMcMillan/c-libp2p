#include <stdint.h>
#include <stddef.h>

#include <openssl/evp.h>

#include "libp2p/crypto/verify.h"

int libp2p_crypto_verify_ed25519(const uint8_t *pubkey, size_t pubkey_len,
                                 const uint8_t *msg, size_t msg_len,
                                 const uint8_t *sig, size_t sig_len) {
    if (!pubkey || !msg || !sig) return 0;
    if (pubkey_len != 32) return 0;

    EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pubkey, pubkey_len);
    if (!pkey) return 0;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pkey);
        return 0;
    }

    int status = 0;
    if (EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pkey) == 1) {
        if (EVP_DigestVerify(ctx, sig, sig_len, msg, msg_len) == 1) {
            status = 1;
        }
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return status;
}
