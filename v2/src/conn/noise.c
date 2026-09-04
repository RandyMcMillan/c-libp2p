#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include "libp2p/conn/noise.h"
#include "libp2p/conn/multistream.h"
#include "libp2p/peer/peerstore.h"
#include "libp2p/utils/logger.h"

#define NOISE_PROTOCOL_ID "/noise"
#define NOISE_CIPHER "ChaChaPoly"
#define NOISE_HASH "SHA256"
#define NOISE_DH_CURVE "25519"

#define NOISE_TAGLEN 16
#define NOISE_KEYLEN 32
#define NOISE_NONCE_LEN 12
#define NOISE_HASHLEN 32
#define NOISE_DHLEN 32

struct NoiseStreamContext {
    struct Stream* raw_stream;
    EVP_CIPHER_CTX* read_ctx;
    EVP_CIPHER_CTX* write_ctx;
    unsigned char read_key[NOISE_KEYLEN];
    unsigned char write_key[NOISE_KEYLEN];
    uint64_t read_nonce;
    uint64_t write_nonce;
};

static int noise_hkdf(const unsigned char* salt, size_t salt_len,
                      const unsigned char* ikm, size_t ikm_len,
                      unsigned char* okm1,
                      unsigned char* okm2, size_t okm2_len) {
    unsigned char prk[NOISE_HASHLEN];
    unsigned int prk_len = NOISE_HASHLEN;

    if (!HMAC(EVP_sha256(), salt, (int)salt_len, ikm, ikm_len, prk, &prk_len))
        return 0;

    unsigned char info1 = 0x01;
    if (!HMAC(EVP_sha256(), prk, prk_len, &info1, 1, okm1, &prk_len))
        return 0;

    if (okm2 != NULL && okm2_len > 0) {
        unsigned char info2[NOISE_HASHLEN + 1];
        memcpy(info2, okm1, NOISE_HASHLEN);
        info2[NOISE_HASHLEN] = 0x02;
        if (!HMAC(EVP_sha256(), prk, prk_len, info2, NOISE_HASHLEN + 1, okm2, &prk_len))
            return 0;
    }

    return 1;
}

static int noise_encrypt(const unsigned char* key, uint64_t nonce,
                         const unsigned char* ad, size_t ad_len,
                         const unsigned char* plaintext, size_t plaintext_len,
                         unsigned char* ciphertext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    unsigned char nonce_bytes[NOISE_NONCE_LEN] = {0};
    for (int i = 0; i < 8; i++) {
        nonce_bytes[4 + i] = (nonce >> (i * 8)) & 0xFF;
    }

    int len;
    int ciphertext_len;

    if (!EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL))
        goto fail;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, NOISE_NONCE_LEN, NULL))
        goto fail;
    if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce_bytes))
        goto fail;
    if (!EVP_EncryptUpdate(ctx, NULL, &len, ad, (int)ad_len))
        goto fail;
    if (!EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, (int)plaintext_len))
        goto fail;
    ciphertext_len = len;
    if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        goto fail;
    ciphertext_len += len;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, NOISE_TAGLEN, ciphertext + ciphertext_len))
        goto fail;

    EVP_CIPHER_CTX_free(ctx);
    return 1;

fail:
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

static int noise_decrypt(const unsigned char* key, uint64_t nonce,
                         const unsigned char* ad, size_t ad_len,
                         const unsigned char* ciphertext, size_t ciphertext_len,
                         unsigned char* plaintext) {
    if (ciphertext_len < NOISE_TAGLEN)
        return 0;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    unsigned char nonce_bytes[NOISE_NONCE_LEN] = {0};
    for (int i = 0; i < 8; i++) {
        nonce_bytes[4 + i] = (nonce >> (i * 8)) & 0xFF;
    }

    int len;
    size_t data_len = ciphertext_len - NOISE_TAGLEN;

    if (!EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL))
        goto fail;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, NOISE_NONCE_LEN, NULL))
        goto fail;
    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce_bytes))
        goto fail;
    if (!EVP_DecryptUpdate(ctx, NULL, &len, ad, (int)ad_len))
        goto fail;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, NOISE_TAGLEN, (void*)(ciphertext + data_len)))
        goto fail;
    if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, (int)data_len))
        goto fail;
    if (!EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        goto fail;

    EVP_CIPHER_CTX_free(ctx);
    return 1;

fail:
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

static ssize_t noise_stream_read(struct Stream* stream, unsigned char* buf, size_t count) {
    if (!stream || !stream->stream_context || !buf)
        return -1;

    struct NoiseStreamContext* ctx = (struct NoiseStreamContext*)stream->stream_context;

    unsigned char frame_header[2];
    ssize_t ret = ctx->raw_stream->read(ctx->raw_stream, frame_header, 2);
    if (ret != 2)
        return -1;

    uint16_t frame_len = (frame_header[0] << 8) | frame_header[1];
    if (frame_len > 65535 || frame_len < NOISE_TAGLEN)
        return -1;

    unsigned char* cipher_buf = malloc(frame_len);
    if (!cipher_buf)
        return -1;

    size_t total_read = 0;
    while (total_read < frame_len) {
        ret = ctx->raw_stream->read(ctx->raw_stream, cipher_buf + total_read, frame_len - total_read);
        if (ret <= 0) {
            free(cipher_buf);
            return -1;
        }
        total_read += ret;
    }

    size_t plaintext_len = frame_len - NOISE_TAGLEN;
    if (plaintext_len > count) {
        free(cipher_buf);
        return -1;
    }

    if (!noise_decrypt(ctx->read_key, ctx->read_nonce, NULL, 0, cipher_buf, frame_len, buf)) {
        free(cipher_buf);
        return -1;
    }

    ctx->read_nonce++;
    free(cipher_buf);
    return (ssize_t)plaintext_len;
}

static ssize_t noise_stream_write(struct Stream* stream, const unsigned char* buf, size_t count) {
    if (!stream || !stream->stream_context || !buf)
        return -1;

    struct NoiseStreamContext* ctx = (struct NoiseStreamContext*)stream->stream_context;

    size_t max_payload = 65535 - NOISE_TAGLEN;
    if (count > max_payload)
        count = max_payload;

    unsigned char ciphertext[65535];
    if (!noise_encrypt(ctx->write_key, ctx->write_nonce, NULL, 0, buf, count, ciphertext))
        return -1;

    unsigned char frame_header[2];
    uint16_t frame_len = (uint16_t)(count + NOISE_TAGLEN);
    frame_header[0] = (frame_len >> 8) & 0xFF;
    frame_header[1] = frame_len & 0xFF;

    if (ctx->raw_stream->write(ctx->raw_stream, frame_header, 2) != 2)
        return -1;

    ssize_t ret = ctx->raw_stream->write(ctx->raw_stream, ciphertext, frame_len);
    if (ret == (ssize_t)frame_len) {
        ctx->write_nonce++;
        return (ssize_t)count;
    }
    return -1;
}

static void noise_stream_close(struct Stream* stream) {
    if (!stream) return;
    struct NoiseStreamContext* ctx = (struct NoiseStreamContext*)stream->stream_context;
    if (ctx) {
        if (ctx->raw_stream)
            ctx->raw_stream->close(ctx->raw_stream);
        free(ctx);
        stream->stream_context = NULL;
    }
    free(stream);
}

static int noise_x25519_generate(unsigned char* private_key, unsigned char* public_key) {
    EVP_PKEY* pkey = EVP_PKEY_new();
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(NID_X25519, NULL);
    if (!pctx || !pkey)
        goto fail;
    if (EVP_PKEY_keygen_init(pctx) <= 0)
        goto fail;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0)
        goto fail;

    size_t priv_len = NOISE_DHLEN;
    size_t pub_len = NOISE_DHLEN;
    if (!EVP_PKEY_get_raw_private_key(pkey, private_key, &priv_len))
        goto fail;
    if (!EVP_PKEY_get_raw_public_key(pkey, public_key, &pub_len))
        goto fail;

    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(pkey);
    return 1;

fail:
    if (pctx) EVP_PKEY_CTX_free(pctx);
    if (pkey) EVP_PKEY_free(pkey);
    return 0;
}

static int noise_x25519_dh(const unsigned char* private_key, const unsigned char* public_key,
                             unsigned char* shared_secret) {
    EVP_PKEY* priv = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, private_key, NOISE_DHLEN);
    EVP_PKEY* pub = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, public_key, NOISE_DHLEN);
    if (!priv || !pub)
        goto fail;

    EVP_PKEY_CTX* ctx = NULL;
    ctx = EVP_PKEY_CTX_new(priv, NULL);
    if (!ctx)
        goto fail;
    if (EVP_PKEY_derive_init(ctx) <= 0)
        goto fail;
    if (EVP_PKEY_derive_set_peer(ctx, pub) <= 0)
        goto fail;

    size_t secret_len = NOISE_DHLEN;
    if (EVP_PKEY_derive(ctx, shared_secret, &secret_len) <= 0)
        goto fail;

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pub);
    EVP_PKEY_free(priv);
    return 1;

fail:
    if (ctx) EVP_PKEY_CTX_free(ctx);
    if (pub) EVP_PKEY_free(pub);
    if (priv) EVP_PKEY_free(priv);
    return 0;
}

static void noise_mix_hash(unsigned char* h, const unsigned char* data, size_t len) {
    unsigned char output[NOISE_HASHLEN];
    SHA256_CTX sha;
    SHA256_Init(&sha);
    SHA256_Update(&sha, h, NOISE_HASHLEN);
    SHA256_Update(&sha, data, len);
    SHA256_Final(output, &sha);
    memcpy(h, output, NOISE_HASHLEN);
}

static void noise_mix_key(unsigned char* ck, unsigned char* k,
                          const unsigned char* input_key_material, size_t ikm_len) {
    unsigned char temp[NOISE_HASHLEN * 2];
    noise_hkdf(ck, NOISE_HASHLEN, input_key_material, ikm_len, temp, temp + NOISE_HASHLEN, NOISE_HASHLEN);
    memcpy(ck, temp, NOISE_HASHLEN);
    memcpy(k, temp + NOISE_HASHLEN, NOISE_HASHLEN);
}

struct Stream* libp2p_noise_handshake(struct Stream* raw_stream, void* private_key, struct Libp2pPeer* peer) {
    (void)private_key;
    (void)peer;

    if (!raw_stream)
        return NULL;

    if (!libp2p_net_multistream_negotiate_protocol(raw_stream, "/noise"))
        return NULL;

    unsigned char h[NOISE_HASHLEN];
    unsigned char ck[NOISE_HASHLEN];
    unsigned char temp_k[NOISE_HASHLEN];
    unsigned char e_private[NOISE_DHLEN];
    unsigned char e_public[NOISE_DHLEN];
    unsigned char re_public[NOISE_DHLEN];
    unsigned char s_private[NOISE_DHLEN];
    unsigned char s_public[NOISE_DHLEN];
    unsigned char dh_result[NOISE_DHLEN];

    memset(h, 0, NOISE_HASHLEN);
    memset(ck, 0, NOISE_HASHLEN);
    memset(temp_k, 0, NOISE_HASHLEN);

    const char* protocol_name = "Noise_XX_25519_ChaChaPoly_SHA256";
    SHA256((const unsigned char*)protocol_name, strlen(protocol_name), h);
    memcpy(ck, h, NOISE_HASHLEN);

    const char* prologue = "";
    SHA256_CTX sha;
    SHA256_Init(&sha);
    SHA256_Update(&sha, h, NOISE_HASHLEN);
    SHA256_Update(&sha, prologue, 0);
    SHA256_Final(h, &sha);

    if (!noise_x25519_generate(e_private, e_public))
        return NULL;

    noise_mix_hash(h, e_public, NOISE_DHLEN);

    if (raw_stream->write(raw_stream, e_public, NOISE_DHLEN) != NOISE_DHLEN)
        return NULL;

    if (raw_stream->read(raw_stream, re_public, NOISE_DHLEN) != NOISE_DHLEN)
        return NULL;

    noise_mix_hash(h, re_public, NOISE_DHLEN);

    if (!noise_x25519_dh(e_private, re_public, dh_result))
        return NULL;
    noise_mix_key(ck, temp_k, dh_result, NOISE_DHLEN);

    if (!noise_x25519_generate(s_private, s_public))
        return NULL;

    unsigned char encrypted_s[NOISE_DHLEN + NOISE_TAGLEN];
    if (!noise_encrypt(temp_k, 0, h, NOISE_HASHLEN, s_public, NOISE_DHLEN, encrypted_s))
        return NULL;
    noise_mix_hash(h, encrypted_s, NOISE_DHLEN + NOISE_TAGLEN);

    if (raw_stream->write(raw_stream, encrypted_s, NOISE_DHLEN + NOISE_TAGLEN) != (ssize_t)(NOISE_DHLEN + NOISE_TAGLEN))
        return NULL;

    if (!noise_x25519_dh(s_private, re_public, dh_result))
        return NULL;
    noise_mix_key(ck, temp_k, dh_result, NOISE_DHLEN);

    unsigned char payload[1] = {0};
    unsigned char encrypted_payload[NOISE_TAGLEN];
    if (!noise_encrypt(temp_k, 0, h, NOISE_HASHLEN, payload, 0, encrypted_payload))
        return NULL;
    noise_mix_hash(h, encrypted_payload, NOISE_TAGLEN);

    if (raw_stream->write(raw_stream, encrypted_payload, NOISE_TAGLEN) != NOISE_TAGLEN)
        return NULL;

    unsigned char remote_encrypted_s[NOISE_DHLEN + NOISE_TAGLEN];
    if (raw_stream->read(raw_stream, remote_encrypted_s, NOISE_DHLEN + NOISE_TAGLEN) != (ssize_t)(NOISE_DHLEN + NOISE_TAGLEN))
        return NULL;

    unsigned char remote_s_public[NOISE_DHLEN];
    if (!noise_decrypt(temp_k, 0, h, NOISE_HASHLEN, remote_encrypted_s, NOISE_DHLEN + NOISE_TAGLEN, remote_s_public))
        return NULL;
    noise_mix_hash(h, remote_encrypted_s, NOISE_DHLEN + NOISE_TAGLEN);

    if (!noise_x25519_dh(e_private, remote_s_public, dh_result))
        return NULL;
    noise_mix_key(ck, temp_k, dh_result, NOISE_DHLEN);

    unsigned char remote_encrypted_payload[NOISE_TAGLEN];
    if (raw_stream->read(raw_stream, remote_encrypted_payload, NOISE_TAGLEN) != NOISE_TAGLEN)
        return NULL;
    unsigned char remote_payload[1];
    if (!noise_decrypt(temp_k, 0, h, NOISE_HASHLEN, remote_encrypted_payload, NOISE_TAGLEN, remote_payload))
        return NULL;
    noise_mix_hash(h, remote_encrypted_payload, NOISE_TAGLEN);

    unsigned char split_keys[NOISE_HASHLEN * 2];
    noise_hkdf(ck, NOISE_HASHLEN, NULL, 0, split_keys, split_keys + NOISE_HASHLEN, NOISE_HASHLEN);

    struct NoiseStreamContext* nctx = calloc(1, sizeof(struct NoiseStreamContext));
    if (!nctx)
        return NULL;

    nctx->raw_stream = raw_stream;
    memcpy(nctx->write_key, split_keys, NOISE_KEYLEN);
    memcpy(nctx->read_key, split_keys + NOISE_HASHLEN, NOISE_KEYLEN);
    nctx->write_nonce = 0;
    nctx->read_nonce = 0;

    struct Stream* stream = calloc(1, sizeof(struct Stream));
    if (!stream) {
        free(nctx);
        return NULL;
    }
    stream->stream_context = nctx;
    stream->read = noise_stream_read;
    stream->write = noise_stream_write;
    stream->close = noise_stream_close;

    return stream;
}
