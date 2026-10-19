#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libp2p/conn/noise.h"
#include "libp2p/crypto/rsa.h"
#include "libp2p/crypto/key.h"
#include "libp2p/utils/logger.h"
#include "ipfs/crypto/verify.h"

#define NOISE_SIG_PREFIX "noise-libp2p-static-key:"
#define NOISE_SIG_PREFIX_LEN 24

static int noise_cb_get_identity_key(void *private_key, uint8_t **out_key, size_t *out_len) {
    struct RsaPrivateKey *rsa = (struct RsaPrivateKey *)private_key;
    if (!rsa || !rsa->public_key_der || rsa->public_key_length == 0)
        return 0;

    struct PublicKey pub_key = {
        .type = KEYTYPE_RSA,
        .data = (unsigned char *)rsa->public_key_der,
        .data_size = rsa->public_key_length
    };

    size_t protobuf_len = libp2p_crypto_public_key_protobuf_encode_size(&pub_key);
    unsigned char *protobuf = (unsigned char *)malloc(protobuf_len);
    if (!protobuf)
        return 0;

    size_t written = 0;
    if (!libp2p_crypto_public_key_protobuf_encode(&pub_key, protobuf, protobuf_len, &written)) {
        free(protobuf);
        return 0;
    }

    *out_key = protobuf;
    *out_len = written;
    return 1;
}

static int noise_cb_sign(void *private_key, const uint8_t *data, size_t data_len,
                         uint8_t **out_sig, size_t *out_len) {
    struct RsaPrivateKey *rsa = (struct RsaPrivateKey *)private_key;
    if (!rsa)
        return 0;

    char *to_sign = (char *)malloc(NOISE_SIG_PREFIX_LEN + data_len);
    if (!to_sign)
        return 0;

    memcpy(to_sign, NOISE_SIG_PREFIX, NOISE_SIG_PREFIX_LEN);
    memcpy(to_sign + NOISE_SIG_PREFIX_LEN, data, data_len);

    int ret = libp2p_crypto_rsa_sign(rsa, to_sign, NOISE_SIG_PREFIX_LEN + data_len, out_sig, out_len);
    free(to_sign);
    return ret;
}

static int noise_cb_verify(const uint8_t *identity_key, size_t identity_key_len,
                           const uint8_t *data, size_t data_len,
                           const uint8_t *sig, size_t sig_len) {
    (void)sig_len;

    struct PublicKey *pub_key = NULL;
    if (!libp2p_crypto_public_key_protobuf_decode((unsigned char *)identity_key, identity_key_len, &pub_key))
        return 0;

    if (!pub_key || !pub_key->data || pub_key->data_size == 0) {
        if (pub_key)
            libp2p_crypto_public_key_free(pub_key);
        return 0;
    }

    unsigned char *to_verify = (unsigned char *)malloc(NOISE_SIG_PREFIX_LEN + data_len);
    if (!to_verify) {
        libp2p_crypto_public_key_free(pub_key);
        return 0;
    }
    memcpy(to_verify, NOISE_SIG_PREFIX, NOISE_SIG_PREFIX_LEN);
    memcpy(to_verify + NOISE_SIG_PREFIX_LEN, data, data_len);

    int ret = 0;
    if (pub_key->type == KEYTYPE_RSA) {
        struct RsaPublicKey rsa_pub = {
            .der = pub_key->data,
            .der_length = pub_key->data_size
        };
        ret = libp2p_crypto_rsa_verify(&rsa_pub, to_verify, NOISE_SIG_PREFIX_LEN + data_len, sig);
    } else if (pub_key->type == KEYTYPE_ED25519) {
        ret = ipfs_crypto_verify_ed25519(pub_key->data, pub_key->data_size,
                                         to_verify, NOISE_SIG_PREFIX_LEN + data_len,
                                         sig, sig_len);
    }

    free(to_verify);
    libp2p_crypto_public_key_free(pub_key);
    return ret;
}

static void noise_cb_free_buffer(uint8_t *buf) {
    free(buf);
}

void libp2p_noise_identity_callbacks_init(noise_identity_callbacks_t *callbacks) {
    if (!callbacks)
        return;
    callbacks->get_identity_key = noise_cb_get_identity_key;
    callbacks->sign = noise_cb_sign;
    callbacks->verify = noise_cb_verify;
    callbacks->free_buffer = noise_cb_free_buffer;
}
