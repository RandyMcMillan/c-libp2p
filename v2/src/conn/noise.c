#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#ifdef OPENSSL_IS_BORINGSSL
#include <openssl/aead.h>
#endif

#include "libp2p/conn/noise.h"
#include "libp2p/conn/multistream.h"
#include "libp2p/crypto/key.h"
#include "libp2p/crypto/peerutils.h"
#include "libp2p/peer/peer.h"
#include "protobuf.h"
#include "varint.h"
#include "libp2p/utils/logger.h"

#include "libp2p/utils/debug.h"

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
    struct Libp2pV2Stream* raw_stream;
    EVP_CIPHER_CTX* read_ctx;
    EVP_CIPHER_CTX* write_ctx;
    unsigned char read_key[NOISE_KEYLEN];
    unsigned char write_key[NOISE_KEYLEN];
    uint64_t read_nonce;
    uint64_t write_nonce;
    pthread_mutex_t rw_mutex;
};

static void noise_hexdump(const char* label, const unsigned char* data, size_t len) {
    DEBUG_PRINTF("[NOISE] %s (%zu bytes): ", label, len);
    for (size_t i = 0; i < len; i++) {
        DEBUG_PRINTF("%02x", data[i]);
    }
    DEBUG_PRINTF("\n");
}

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
    unsigned char nonce_bytes[NOISE_NONCE_LEN] = {0};
    /* libp2p Noise uses ChaCha20-Poly1305 with a 12-byte nonce where the
     * 64-bit counter is encoded little-endian in the last 8 bytes. */
    for (int i = 0; i < 8; i++) {
        nonce_bytes[4 + i] = (nonce >> (i * 8)) & 0xFF;
    }

#ifdef OPENSSL_IS_BORINGSSL
    EVP_AEAD_CTX ctx;
    if (!EVP_AEAD_CTX_init(&ctx, EVP_aead_chacha20_poly1305(), key, NOISE_KEYLEN, EVP_AEAD_DEFAULT_TAG_LENGTH, NULL))
        return 0;

    size_t out_len;
    int ret = EVP_AEAD_CTX_seal(&ctx, ciphertext, &out_len, plaintext_len + NOISE_TAGLEN,
                                nonce_bytes, NOISE_NONCE_LEN,
                                plaintext, plaintext_len,
                                ad, ad_len);
    EVP_AEAD_CTX_cleanup(&ctx);
    return ret && (out_len == plaintext_len + NOISE_TAGLEN);
#else
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    int len;
    int ciphertext_len;

    if (!EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL))
        goto fail;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, NOISE_NONCE_LEN, NULL))
        goto fail;
    if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce_bytes))
        goto fail;
    if (ad_len > 0 && !EVP_EncryptUpdate(ctx, NULL, &len, ad, (int)ad_len))
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
#endif
}

static int noise_decrypt(const unsigned char* key, uint64_t nonce,
                         const unsigned char* ad, size_t ad_len,
                         const unsigned char* ciphertext, size_t ciphertext_len,
                         unsigned char* plaintext) {
    if (ciphertext_len < NOISE_TAGLEN)
        return 0;

    unsigned char nonce_bytes[NOISE_NONCE_LEN] = {0};
    /* libp2p Noise uses ChaCha20-Poly1305 with a 12-byte nonce where the
     * 64-bit counter is encoded little-endian in the last 8 bytes. */
    for (int i = 0; i < 8; i++) {
        nonce_bytes[4 + i] = (nonce >> (i * 8)) & 0xFF;
    }

#ifdef OPENSSL_IS_BORINGSSL
    EVP_AEAD_CTX ctx;
    if (!EVP_AEAD_CTX_init(&ctx, EVP_aead_chacha20_poly1305(), key, NOISE_KEYLEN, EVP_AEAD_DEFAULT_TAG_LENGTH, NULL))
        return 0;

    size_t out_len;
    int ret = EVP_AEAD_CTX_open(&ctx, plaintext, &out_len, ciphertext_len - NOISE_TAGLEN,
                                nonce_bytes, NOISE_NONCE_LEN,
                                ciphertext, ciphertext_len,
                                ad, ad_len);
    EVP_AEAD_CTX_cleanup(&ctx);
    return ret && (out_len == ciphertext_len - NOISE_TAGLEN);
#else
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    int len;
    size_t data_len = ciphertext_len - NOISE_TAGLEN;

    if (!EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL))
        goto fail;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, NOISE_NONCE_LEN, NULL))
        goto fail;
    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce_bytes))
        goto fail;
    if (ad_len > 0 && !EVP_DecryptUpdate(ctx, NULL, &len, ad, (int)ad_len))
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
#endif
}

static ssize_t noise_stream_read(struct Libp2pV2Stream* stream, unsigned char* buf, size_t count) {
    if (!stream || !stream->stream_context || !buf)
        return -1;

    struct NoiseStreamContext* ctx = (struct NoiseStreamContext*)stream->stream_context;

    pthread_mutex_lock(&ctx->rw_mutex);

    unsigned char frame_header[2];
    ssize_t ret = ctx->raw_stream->read(ctx->raw_stream, frame_header, 2);
    if (ret != 2) {
        pthread_mutex_unlock(&ctx->rw_mutex);
        return -1;
    }

    uint16_t frame_len = (frame_header[0] << 8) | frame_header[1];
    if (frame_len > 65535 || frame_len < NOISE_TAGLEN) {
        pthread_mutex_unlock(&ctx->rw_mutex);
        return -1;
    }

    unsigned char* cipher_buf = malloc(frame_len);
    if (!cipher_buf) {
        pthread_mutex_unlock(&ctx->rw_mutex);
        return -1;
    }

    size_t total_read = 0;
    while (total_read < frame_len) {
        ret = ctx->raw_stream->read(ctx->raw_stream, cipher_buf + total_read, frame_len - total_read);
        if (ret <= 0) {
            free(cipher_buf);
            pthread_mutex_unlock(&ctx->rw_mutex);
            return -1;
        }
        total_read += ret;
    }

    size_t plaintext_len = frame_len - NOISE_TAGLEN;
    if (plaintext_len > count) {
        free(cipher_buf);
        pthread_mutex_unlock(&ctx->rw_mutex);
        return -1;
    }

    if (!noise_decrypt(ctx->read_key, ctx->read_nonce, NULL, 0, cipher_buf, frame_len, buf)) {
        free(cipher_buf);
        pthread_mutex_unlock(&ctx->rw_mutex);
        return -1;
    }

    ctx->read_nonce++;
    free(cipher_buf);
    pthread_mutex_unlock(&ctx->rw_mutex);
    return (ssize_t)plaintext_len;
}

static ssize_t noise_stream_write(struct Libp2pV2Stream* stream, const unsigned char* buf, size_t count) {
    if (!stream || !stream->stream_context || !buf)
        return -1;

    struct NoiseStreamContext* ctx = (struct NoiseStreamContext*)stream->stream_context;

    pthread_mutex_lock(&ctx->rw_mutex);

    size_t max_payload = 65535 - NOISE_TAGLEN;
    if (count > max_payload)
        count = max_payload;

    unsigned char ciphertext[65535];
    if (!noise_encrypt(ctx->write_key, ctx->write_nonce, NULL, 0, buf, count, ciphertext)) {
        pthread_mutex_unlock(&ctx->rw_mutex);
        return -1;
    }

    unsigned char frame_header[2];
    uint16_t frame_len = (uint16_t)(count + NOISE_TAGLEN);
    frame_header[0] = (frame_len >> 8) & 0xFF;
    frame_header[1] = frame_len & 0xFF;

    if (ctx->raw_stream->write(ctx->raw_stream, frame_header, 2) != 2) {
        pthread_mutex_unlock(&ctx->rw_mutex);
        return -1;
    }

    ssize_t ret = ctx->raw_stream->write(ctx->raw_stream, ciphertext, frame_len);
    if (ret == (ssize_t)frame_len) {
        ctx->write_nonce++;
        pthread_mutex_unlock(&ctx->rw_mutex);
        return (ssize_t)count;
    }
    pthread_mutex_unlock(&ctx->rw_mutex);
    return -1;
}

static void noise_stream_close(struct Libp2pV2Stream* stream) {
    if (!stream) return;
    struct NoiseStreamContext* ctx = (struct NoiseStreamContext*)stream->stream_context;
    if (ctx) {
        pthread_mutex_destroy(&ctx->rw_mutex);
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
    EVP_PKEY_CTX* ctx = NULL;
    if (!priv || !pub)
        goto fail;

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

/* Encode a libp2p NoiseHandshakePayload protobuf:
 *   message NoiseHandshakePayload {
 *     bytes identity_key = 1;
 *     bytes identity_sig = 2;
 *     bytes data         = 3;
 *   }
 */
static int noise_payload_encode(const uint8_t *identity_key, size_t identity_key_len,
                                const uint8_t *identity_sig, size_t identity_sig_len,
                                uint8_t *out, size_t max_out, size_t *written) {
    size_t pos = 0, bytes = 0;
    *written = 0;

    if (identity_key && identity_key_len > 0) {
        if (!protobuf_encode_length_delimited(1, WIRETYPE_LENGTH_DELIMITED,
                                              (const char*)identity_key, identity_key_len,
                                              out + pos, max_out - pos, &bytes))
            return 0;
        pos += bytes;
    }
    if (identity_sig && identity_sig_len > 0) {
        if (!protobuf_encode_length_delimited(2, WIRETYPE_LENGTH_DELIMITED,
                                              (const char*)identity_sig, identity_sig_len,
                                              out + pos, max_out - pos, &bytes))
            return 0;
        pos += bytes;
    }
    *written = pos;
    return 1;
}

/* Decode the payload.  Buffers returned in *out_key and *out_sig are
 * pointing into the incoming 'in' buffer (no allocs).  */
static int noise_payload_decode(const uint8_t *in, size_t in_len,
                                const uint8_t **out_key, size_t *out_key_len,
                                const uint8_t **out_sig, size_t *out_sig_len) {
    size_t pos = 0;
    *out_key = NULL; *out_key_len = 0;
    *out_sig = NULL; *out_sig_len = 0;

    while (pos < in_len) {
        int field_no;
        enum WireType field_type;
        size_t hdr_bytes = 0;
        if (!protobuf_decode_field_and_type(in + pos, (int)(in_len - pos), &field_no, &field_type, &hdr_bytes))
            return 0;
        pos += hdr_bytes;

        if (field_type != WIRETYPE_LENGTH_DELIMITED)
            return 0;

        size_t varint_len = 0;
        unsigned long long data_len = varint_decode(in + pos, (int)(in_len - pos), &varint_len);
        if (varint_len == 0 || pos + varint_len + data_len > in_len)
            return 0;

        switch (field_no) {
            case 1:
                *out_key = in + pos + varint_len;
                *out_key_len = data_len;
                break;
            case 2:
                *out_sig = in + pos + varint_len;
                *out_sig_len = data_len;
                break;
            default:
                break;
        }
        pos += varint_len + data_len;
    }
    return 1;
}

/* libp2p Noise uses a 2-byte big-endian length prefix for every handshake message. */
static int noise_write_frame(struct Libp2pV2Stream* stream, const unsigned char* data, size_t len) {
    unsigned char header[2];
    header[0] = (len >> 8) & 0xFF;
    header[1] = len & 0xFF;
    if (stream->write(stream, header, 2) != 2)
        return 0;
    if (stream->write(stream, data, len) != (ssize_t)len)
        return 0;
    return 1;
}

static int noise_read_frame(struct Libp2pV2Stream* stream, unsigned char* buf, size_t max_len, size_t* out_len) {
    unsigned char header[2];
    if (stream->read(stream, header, 2) != 2)
        return 0;
    size_t len = (header[0] << 8) | header[1];
    if (len > max_len)
        return 0;
    size_t total = 0;
    while (total < len) {
        ssize_t ret = stream->read(stream, buf + total, len - total);
        if (ret <= 0)
            return 0;
        total += ret;
    }
    *out_len = len;
    return 1;
}

static int noise_peer_id_from_identity_key(const uint8_t* id_key, size_t id_key_len,
                                            struct Libp2pPeer* peer) {
    if (!id_key || id_key_len == 0 || !peer)
        return 0;
    struct PublicKey* pubkey = NULL;
    if (!libp2p_crypto_public_key_protobuf_decode((unsigned char*)id_key, id_key_len, &pubkey))
        return 0;
    char* peer_id = NULL;
    int ret = libp2p_crypto_public_key_to_peer_id(pubkey, &peer_id);
    libp2p_crypto_public_key_free(pubkey);
    if (!ret || !peer_id)
        return 0;
    peer->id = peer_id;
    peer->id_size = strlen(peer_id);
    return 1;
}

struct Libp2pV2Stream* libp2p_noise_handshake_raw(struct Libp2pV2Stream* raw_stream, void* private_key,
                                                   struct Libp2pPeer* peer,
                                                   const noise_identity_callbacks_t *callbacks) {
    (void)peer;

    if (!raw_stream)
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
    uint64_t nonce = 0;

    memset(h, 0, NOISE_HASHLEN);
    memset(ck, 0, NOISE_HASHLEN);
    memset(temp_k, 0, NOISE_HASHLEN);

    const char* protocol_name = "Noise_XX_25519_ChaChaPoly_SHA256";
    size_t protocol_name_len = strlen(protocol_name);
    if (protocol_name_len <= NOISE_HASHLEN) {
        memcpy(h, protocol_name, protocol_name_len);
        memset(h + protocol_name_len, 0, NOISE_HASHLEN - protocol_name_len);
    } else {
        SHA256((const unsigned char*)protocol_name, protocol_name_len, h);
    }
    memcpy(ck, h, NOISE_HASHLEN);

    const char* prologue = "";
    SHA256_CTX sha;
    SHA256_Init(&sha);
    SHA256_Update(&sha, h, NOISE_HASHLEN);
    SHA256_Update(&sha, prologue, 0);
    SHA256_Final(h, &sha);

    /* ---- Message 1: e ---- */
    DEBUG_PRINTF("[NOISE] Generating ephemeral keypair...\n");
    if (!noise_x25519_generate(e_private, e_public))
        return NULL;
    noise_mix_hash(h, e_public, NOISE_DHLEN);
    DEBUG_PRINTF("[NOISE] Writing Message 1 (e_public, %d bytes)...\n", NOISE_DHLEN);
    if (!noise_write_frame(raw_stream, e_public, NOISE_DHLEN)) {
        DEBUG_PRINTF("[NOISE] Failed to write Message 1\n");
        return NULL;
    }
    noise_mix_hash(h, (unsigned char*)"", 0);

    /* ---- Read remote Message 1: e, s, payload (responder's single message) ---- */
    DEBUG_PRINTF("[NOISE] Reading responder's message (e + s + payload)...\n");
    unsigned char remote_msg[4096];
    size_t remote_msg_len = 0;
    if (!noise_read_frame(raw_stream, remote_msg, sizeof(remote_msg), &remote_msg_len)) {
        DEBUG_PRINTF("[NOISE] Failed to read responder's message (len=%zu)\n", remote_msg_len);
        return NULL;
    }
    DEBUG_PRINTF("[NOISE] Responder's message len=%zu\n", remote_msg_len);
    if (remote_msg_len < NOISE_DHLEN) {
        DEBUG_PRINTF("[NOISE] Responder's message too short for e\n");
        return NULL;
    }
    memcpy(re_public, remote_msg, NOISE_DHLEN);
    noise_mix_hash(h, re_public, NOISE_DHLEN);

    if (!noise_x25519_dh(e_private, re_public, dh_result))
        return NULL;
    noise_mix_key(ck, temp_k, dh_result, NOISE_DHLEN);
    nonce = 0;

    noise_hexdump("h after ee", h, NOISE_HASHLEN);
    noise_hexdump("ck after ee", ck, NOISE_HASHLEN);
    noise_hexdump("temp_k after ee", temp_k, NOISE_KEYLEN);
    noise_hexdump("e_private", e_private, NOISE_DHLEN);
    noise_hexdump("e_public", e_public, NOISE_DHLEN);
    noise_hexdump("re_public", re_public, NOISE_DHLEN);
    noise_hexdump("dh_result (ee)", dh_result, NOISE_DHLEN);

    size_t offset = NOISE_DHLEN;
    if (remote_msg_len < offset + NOISE_DHLEN + NOISE_TAGLEN) {
        DEBUG_PRINTF("[NOISE] Responder's message too short for encrypted s\n");
        return NULL;
    }
    unsigned char remote_encrypted_s[NOISE_DHLEN + NOISE_TAGLEN];
    memcpy(remote_encrypted_s, remote_msg + offset, NOISE_DHLEN + NOISE_TAGLEN);
    offset += NOISE_DHLEN + NOISE_TAGLEN;

    noise_hexdump("remote_encrypted_s", remote_encrypted_s, NOISE_DHLEN + NOISE_TAGLEN);

    unsigned char remote_s_public[NOISE_DHLEN];
    DEBUG_PRINTF("[NOISE] Decrypting responder's s (nonce=%llu)...\n", (unsigned long long)nonce);
    if (!noise_decrypt(temp_k, nonce, h, NOISE_HASHLEN, remote_encrypted_s, NOISE_DHLEN + NOISE_TAGLEN, remote_s_public)) {
        DEBUG_PRINTF("[NOISE] Failed to decrypt responder's s\n");
        return NULL;
    }
    nonce++;
    DEBUG_PRINTF("[NOISE] Decrypted responder's s successfully\n");
    noise_mix_hash(h, remote_encrypted_s, NOISE_DHLEN + NOISE_TAGLEN);

    if (!noise_x25519_dh(e_private, remote_s_public, dh_result))
        return NULL;
    noise_mix_key(ck, temp_k, dh_result, NOISE_DHLEN);
    nonce = 0;

    size_t remote_payload_frame_len = remote_msg_len - offset;
    DEBUG_PRINTF("[NOISE] Responder's payload frame len=%zu\n", remote_payload_frame_len);
    unsigned char remote_encrypted_payload[NOISE_TAGLEN + 2048];
    if (remote_payload_frame_len > sizeof(remote_encrypted_payload)) {
        DEBUG_PRINTF("[NOISE] Responder's payload too large (%zu)\n", remote_payload_frame_len);
        return NULL;
    }
    memcpy(remote_encrypted_payload, remote_msg + offset, remote_payload_frame_len);

    unsigned char remote_payload[2048];
    size_t remote_payload_len = 0;
    if (remote_payload_frame_len >= NOISE_TAGLEN) {
        remote_payload_len = remote_payload_frame_len - NOISE_TAGLEN;
        DEBUG_PRINTF("[NOISE] Decrypting responder's payload (nonce=%llu, len=%zu)...\n", (unsigned long long)nonce, remote_payload_frame_len);
        if (!noise_decrypt(temp_k, nonce, h, NOISE_HASHLEN, remote_encrypted_payload, remote_payload_frame_len, remote_payload)) {
            DEBUG_PRINTF("[NOISE] Failed to decrypt responder's payload\n");
            return NULL;
        }
        nonce++;
        DEBUG_PRINTF("[NOISE] Decrypted responder's payload successfully (plaintext len=%zu)\n", remote_payload_len);
        noise_mix_hash(h, remote_encrypted_payload, remote_payload_frame_len);

        if (callbacks && callbacks->verify) {
            const uint8_t *r_id_key = NULL, *r_id_sig = NULL;
            size_t r_id_key_len = 0, r_id_sig_len = 0;
            if (noise_payload_decode(remote_payload, remote_payload_len,
                                     &r_id_key, &r_id_key_len,
                                     &r_id_sig, &r_id_sig_len)) {
                if (r_id_key && r_id_sig) {
                    if (!callbacks->verify(r_id_key, r_id_key_len,
                                           remote_s_public, NOISE_DHLEN,
                                           r_id_sig, r_id_sig_len)) {
                        libp2p_v2_logger_error("noise", "Remote identity signature verification failed\n");
                        return NULL;
                    }
                    if (peer != NULL && noise_peer_id_from_identity_key(r_id_key, r_id_key_len, peer)) {
                        libp2p_v2_logger_info("noise", "Derived peer id from remote identity key: %s\n", peer->id);
                    }
                }
            }
        }
    } else {
        noise_mix_hash(h, remote_encrypted_payload, remote_payload_frame_len);
    }

    /* ---- Message 2: s, payload (initiator's final message, single frame) ---- */
    DEBUG_PRINTF("[NOISE] Generating static keypair...\n");
    if (!noise_x25519_generate(s_private, s_public)) {
        DEBUG_PRINTF("[NOISE] Failed to generate static keypair\n");
        return NULL;
    }

    unsigned char encrypted_s[NOISE_DHLEN + NOISE_TAGLEN];
    DEBUG_PRINTF("[NOISE] Encrypting static key (nonce=%llu)...\n", (unsigned long long)nonce);
    if (!noise_encrypt(temp_k, nonce, h, NOISE_HASHLEN, s_public, NOISE_DHLEN, encrypted_s)) {
        DEBUG_PRINTF("[NOISE] Failed to encrypt static key\n");
        return NULL;
    }
    nonce++;
    noise_mix_hash(h, encrypted_s, NOISE_DHLEN + NOISE_TAGLEN);

    DEBUG_PRINTF("[NOISE] Computing static DH (se)...\n");
    if (!noise_x25519_dh(s_private, re_public, dh_result)) {
        DEBUG_PRINTF("[NOISE] Failed to compute static DH\n");
        return NULL;
    }
    noise_mix_key(ck, temp_k, dh_result, NOISE_DHLEN);
    nonce = 0;

    /* Build identity payload */
    uint8_t payload[1024];
    size_t payload_len = 0;
    if (callbacks && callbacks->get_identity_key && callbacks->sign) {
        uint8_t *identity_key = NULL;
        size_t identity_key_len = 0;
        uint8_t *identity_sig = NULL;
        size_t identity_sig_len = 0;
        if (callbacks->get_identity_key(private_key, &identity_key, &identity_key_len) &&
            callbacks->sign(private_key, s_public, NOISE_DHLEN, &identity_sig, &identity_sig_len)) {
            noise_payload_encode(identity_key, identity_key_len,
                                 identity_sig, identity_sig_len,
                                 payload, sizeof(payload), &payload_len);
            if (callbacks->free_buffer) {
                callbacks->free_buffer(identity_key);
                callbacks->free_buffer(identity_sig);
            }
        }
    }

    unsigned char encrypted_payload[NOISE_TAGLEN + 1024];
    DEBUG_PRINTF("[NOISE] Encrypting payload (%zu bytes, nonce=%llu)...\n", payload_len, (unsigned long long)nonce);
    if (!noise_encrypt(temp_k, nonce, h, NOISE_HASHLEN, payload, payload_len, encrypted_payload)) {
        DEBUG_PRINTF("[NOISE] Failed to encrypt payload\n");
        return NULL;
    }
    nonce++;
    noise_mix_hash(h, encrypted_payload, NOISE_TAGLEN + payload_len);

    unsigned char msg2[2048];
    size_t msg2_len = 0;
    memcpy(msg2 + msg2_len, encrypted_s, NOISE_DHLEN + NOISE_TAGLEN);
    msg2_len += NOISE_DHLEN + NOISE_TAGLEN;
    memcpy(msg2 + msg2_len, encrypted_payload, NOISE_TAGLEN + payload_len);
    msg2_len += NOISE_TAGLEN + payload_len;

    DEBUG_PRINTF("[NOISE] Writing Message 2 (s + payload, %zu bytes)...\n", msg2_len);
    if (!noise_write_frame(raw_stream, msg2, msg2_len)) {
        DEBUG_PRINTF("[NOISE] Failed to write Message 2\n");
        return NULL;
    }

    /* ---- Split ---- */
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
    pthread_mutex_init(&nctx->rw_mutex, NULL);

    struct Libp2pV2Stream* stream = calloc(1, sizeof(struct Libp2pV2Stream));
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

struct Libp2pV2Stream* libp2p_noise_handshake_responder_raw(struct Libp2pV2Stream* raw_stream, void* private_key,
                                                             struct Libp2pPeer* peer,
                                                             const noise_identity_callbacks_t *callbacks) {
    (void)peer;

    if (!raw_stream)
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
    uint64_t nonce = 0;

    memset(h, 0, NOISE_HASHLEN);
    memset(ck, 0, NOISE_HASHLEN);
    memset(temp_k, 0, NOISE_HASHLEN);

    const char* protocol_name = "Noise_XX_25519_ChaChaPoly_SHA256";
    size_t protocol_name_len = strlen(protocol_name);
    if (protocol_name_len <= NOISE_HASHLEN) {
        memcpy(h, protocol_name, protocol_name_len);
        memset(h + protocol_name_len, 0, NOISE_HASHLEN - protocol_name_len);
    } else {
        SHA256((const unsigned char*)protocol_name, protocol_name_len, h);
    }
    memcpy(ck, h, NOISE_HASHLEN);

    const char* prologue = "";
    SHA256_CTX sha;
    SHA256_Init(&sha);
    SHA256_Update(&sha, h, NOISE_HASHLEN);
    SHA256_Update(&sha, prologue, 0);
    SHA256_Final(h, &sha);

    /* ---- Read remote Message 1: e ---- */
    size_t frame_len = 0;
    DEBUG_PRINTF("[NOISE] Responder reading initiator's e...\n");
    if (!noise_read_frame(raw_stream, re_public, NOISE_DHLEN, &frame_len) || frame_len != NOISE_DHLEN)
        return NULL;
    noise_mix_hash(h, re_public, NOISE_DHLEN);
    noise_mix_hash(h, (unsigned char*)"", 0);

    /* ---- Message 1 (responder): e || encrypted_s || encrypted_payload (single frame) ---- */
    if (!noise_x25519_generate(e_private, e_public))
        return NULL;
    noise_mix_hash(h, e_public, NOISE_DHLEN);

    if (!noise_x25519_dh(e_private, re_public, dh_result))
        return NULL;
    noise_mix_key(ck, temp_k, dh_result, NOISE_DHLEN);
    nonce = 0;

    if (!noise_x25519_generate(s_private, s_public))
        return NULL;

    unsigned char encrypted_s[NOISE_DHLEN + NOISE_TAGLEN];
    if (!noise_encrypt(temp_k, nonce, h, NOISE_HASHLEN, s_public, NOISE_DHLEN, encrypted_s))
        return NULL;
    nonce++;
    noise_mix_hash(h, encrypted_s, NOISE_DHLEN + NOISE_TAGLEN);

    if (!noise_x25519_dh(s_private, re_public, dh_result))
        return NULL;
    noise_mix_key(ck, temp_k, dh_result, NOISE_DHLEN);
    nonce = 0;

    /* Build identity payload */
    uint8_t payload[1024];
    size_t payload_len = 0;
    if (callbacks && callbacks->get_identity_key && callbacks->sign) {
        uint8_t *identity_key = NULL;
        size_t identity_key_len = 0;
        uint8_t *identity_sig = NULL;
        size_t identity_sig_len = 0;
        if (callbacks->get_identity_key(private_key, &identity_key, &identity_key_len) &&
            callbacks->sign(private_key, s_public, NOISE_DHLEN, &identity_sig, &identity_sig_len)) {
            noise_payload_encode(identity_key, identity_key_len,
                                 identity_sig, identity_sig_len,
                                 payload, sizeof(payload), &payload_len);
            if (callbacks->free_buffer) {
                callbacks->free_buffer(identity_key);
                callbacks->free_buffer(identity_sig);
            }
        }
    }

    unsigned char encrypted_payload[NOISE_TAGLEN + 1024];
    if (!noise_encrypt(temp_k, nonce, h, NOISE_HASHLEN, payload, payload_len, encrypted_payload))
        return NULL;
    nonce++;
    noise_mix_hash(h, encrypted_payload, NOISE_TAGLEN + payload_len);

    unsigned char msg1[2048];
    size_t msg1_len = 0;
    memcpy(msg1 + msg1_len, e_public, NOISE_DHLEN);
    msg1_len += NOISE_DHLEN;
    memcpy(msg1 + msg1_len, encrypted_s, NOISE_DHLEN + NOISE_TAGLEN);
    msg1_len += NOISE_DHLEN + NOISE_TAGLEN;
    memcpy(msg1 + msg1_len, encrypted_payload, NOISE_TAGLEN + payload_len);
    msg1_len += NOISE_TAGLEN + payload_len;

    DEBUG_PRINTF("[NOISE] Writing responder Message 1 (e + s + payload, %zu bytes)...\n", msg1_len);
    if (!noise_write_frame(raw_stream, msg1, msg1_len)) {
        DEBUG_PRINTF("[NOISE] Failed to write responder Message 1\n");
        return NULL;
    }

    /* ---- Read remote Message 2: s + payload (single frame) ---- */
    DEBUG_PRINTF("[NOISE] Reading initiator's final message (s + payload)...\n");
    unsigned char remote_msg2[4096];
    size_t remote_msg2_len = 0;
    if (!noise_read_frame(raw_stream, remote_msg2, sizeof(remote_msg2), &remote_msg2_len)) {
        DEBUG_PRINTF("[NOISE] Failed to read initiator's final message\n");
        return NULL;
    }
    DEBUG_PRINTF("[NOISE] Initiator's final message len=%zu\n", remote_msg2_len);
    if (remote_msg2_len < NOISE_DHLEN + NOISE_TAGLEN) {
        DEBUG_PRINTF("[NOISE] Initiator's final message too short for encrypted s\n");
        return NULL;
    }

    unsigned char remote_encrypted_s[NOISE_DHLEN + NOISE_TAGLEN];
    memcpy(remote_encrypted_s, remote_msg2, NOISE_DHLEN + NOISE_TAGLEN);

    unsigned char remote_s_public[NOISE_DHLEN];
    if (!noise_decrypt(temp_k, nonce, h, NOISE_HASHLEN, remote_encrypted_s, NOISE_DHLEN + NOISE_TAGLEN, remote_s_public))
        return NULL;
    nonce++;
    noise_mix_hash(h, remote_encrypted_s, NOISE_DHLEN + NOISE_TAGLEN);

    if (!noise_x25519_dh(e_private, remote_s_public, dh_result))
        return NULL;
    noise_mix_key(ck, temp_k, dh_result, NOISE_DHLEN);
    nonce = 0;

    size_t remote_payload_frame_len = remote_msg2_len - (NOISE_DHLEN + NOISE_TAGLEN);
    unsigned char remote_encrypted_payload[NOISE_TAGLEN + 2048];
    if (remote_payload_frame_len > sizeof(remote_encrypted_payload)) {
        DEBUG_PRINTF("[NOISE] Initiator's payload too large (%zu)\n", remote_payload_frame_len);
        return NULL;
    }
    memcpy(remote_encrypted_payload, remote_msg2 + (NOISE_DHLEN + NOISE_TAGLEN), remote_payload_frame_len);

    unsigned char remote_payload[2048];
    size_t remote_payload_len = 0;
    if (remote_payload_frame_len >= NOISE_TAGLEN) {
        remote_payload_len = remote_payload_frame_len - NOISE_TAGLEN;
        if (!noise_decrypt(temp_k, nonce, h, NOISE_HASHLEN, remote_encrypted_payload, remote_payload_frame_len, remote_payload))
            return NULL;
        nonce++;
        noise_mix_hash(h, remote_encrypted_payload, remote_payload_frame_len);

        if (callbacks && callbacks->verify) {
            const uint8_t *r_id_key = NULL, *r_id_sig = NULL;
            size_t r_id_key_len = 0, r_id_sig_len = 0;
            if (noise_payload_decode(remote_payload, remote_payload_len,
                                     &r_id_key, &r_id_key_len,
                                     &r_id_sig, &r_id_sig_len)) {
                if (r_id_key && r_id_sig) {
                    if (!callbacks->verify(r_id_key, r_id_key_len,
                                           remote_s_public, NOISE_DHLEN,
                                           r_id_sig, r_id_sig_len)) {
                        libp2p_v2_logger_error("noise", "Remote identity signature verification failed\n");
                        return NULL;
                    }
                    if (peer != NULL && noise_peer_id_from_identity_key(r_id_key, r_id_key_len, peer)) {
                        libp2p_v2_logger_info("noise", "Derived peer id from remote identity key: %s\n", peer->id);
                    }
                }
            }
        }
    } else {
        noise_mix_hash(h, remote_encrypted_payload, remote_payload_frame_len);
    }

    /* ---- Split ---- */
    unsigned char split_keys[NOISE_HASHLEN * 2];
    noise_hkdf(ck, NOISE_HASHLEN, NULL, 0, split_keys, split_keys + NOISE_HASHLEN, NOISE_HASHLEN);

    struct NoiseStreamContext* nctx = calloc(1, sizeof(struct NoiseStreamContext));
    if (!nctx)
        return NULL;

    nctx->raw_stream = raw_stream;
    /* Responder swap: read_key = first half, write_key = second half */
    memcpy(nctx->read_key, split_keys, NOISE_KEYLEN);
    memcpy(nctx->write_key, split_keys + NOISE_HASHLEN, NOISE_KEYLEN);
    nctx->write_nonce = 0;
    nctx->read_nonce = 0;
    pthread_mutex_init(&nctx->rw_mutex, NULL);

    struct Libp2pV2Stream* stream = calloc(1, sizeof(struct Libp2pV2Stream));
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

struct Libp2pV2Stream* libp2p_noise_handshake(struct Libp2pV2Stream* raw_stream, void* private_key,
                                      struct Libp2pPeer* peer,
                                      const noise_identity_callbacks_t *callbacks) {
    if (!raw_stream)
        return NULL;

    if (!libp2p_net_multistream_negotiate_protocol(raw_stream, "/noise"))
        return NULL;

    return libp2p_noise_handshake_raw(raw_stream, private_key, peer, callbacks);
}
