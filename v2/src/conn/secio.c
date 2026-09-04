#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include "libp2p/conn/secio.h"
#include "libp2p/conn/multistream.h"
#include "libp2p/peer/peerstore.h"
#include "libp2p/utils/logger.h"

#define SECIO_PROTOCOL_ID "/secio/1.0.0"
#define NONCE_SIZE 16

struct SecioStreamContext {
    struct Stream* raw_stream;
    EVP_CIPHER_CTX* read_ctx;
    EVP_CIPHER_CTX* write_ctx;
    unsigned char local_nonce[NONCE_SIZE];
    unsigned char remote_nonce[NONCE_SIZE];
};

static ssize_t secio_stream_read(struct Stream* stream, unsigned char* buf, size_t count) {
    if (stream == NULL || stream->stream_context == NULL || buf == NULL)
        return -1;

    struct SecioStreamContext* ctx = (struct SecioStreamContext*)stream->stream_context;

    unsigned char cipher_buf[2048];
    if (count > sizeof(cipher_buf))
        count = sizeof(cipher_buf);

    ssize_t bytes_read = ctx->raw_stream->read(ctx->raw_stream, cipher_buf, count);
    if (bytes_read <= 0)
        return bytes_read;

    int out_len = 0;
    if (!EVP_DecryptUpdate(ctx->read_ctx, buf, &out_len, cipher_buf, (int)bytes_read)) {
        libp2p_logger_error("secio", "Decryption failure on read\n");
        return -1;
    }

    return (ssize_t)out_len;
}

static ssize_t secio_stream_write(struct Stream* stream, const unsigned char* buf, size_t count) {
    if (stream == NULL || stream->stream_context == NULL || buf == NULL)
        return -1;

    struct SecioStreamContext* ctx = (struct SecioStreamContext*)stream->stream_context;

    unsigned char cipher_buf[2048];
    int out_len = 0;

    if (!EVP_EncryptUpdate(ctx->write_ctx, cipher_buf, &out_len, buf, (int)count)) {
        libp2p_logger_error("secio", "Encryption failure on write\n");
        return -1;
    }

    return ctx->raw_stream->write(ctx->raw_stream, cipher_buf, (size_t)out_len);
}

static void secio_stream_close(struct Stream* stream) {
    if (stream == NULL)
        return;

    if (stream->stream_context != NULL) {
        struct SecioStreamContext* ctx = (struct SecioStreamContext*)stream->stream_context;
        if (ctx->read_ctx != NULL) EVP_CIPHER_CTX_free(ctx->read_ctx);
        if (ctx->write_ctx != NULL) EVP_CIPHER_CTX_free(ctx->write_ctx);
        if (ctx->raw_stream != NULL) ctx->raw_stream->close(ctx->raw_stream);
        free(ctx);
        stream->stream_context = NULL;
    }
    free(stream);
}

struct Stream* libp2p_secio_handshake(struct Stream* raw_stream, void* private_key, struct Libp2pPeer* peer) {
    (void)private_key;
    (void)peer;

    if (raw_stream == NULL)
        return NULL;

    if (!libp2p_net_multistream_negotiate_protocol(raw_stream, SECIO_PROTOCOL_ID)) {
        libp2p_logger_error("secio", "Failed to negotiate SECIO protocol\n");
        return NULL;
    }

    struct SecioStreamContext* ctx = (struct SecioStreamContext*)calloc(1, sizeof(struct SecioStreamContext));
    if (ctx == NULL)
        return NULL;

    ctx->raw_stream = raw_stream;

    if (RAND_bytes(ctx->local_nonce, NONCE_SIZE) != 1) {
        free(ctx);
        return NULL;
    }

    if (raw_stream->write(raw_stream, ctx->local_nonce, NONCE_SIZE) <= 0 ||
        raw_stream->read(raw_stream, ctx->remote_nonce, NONCE_SIZE) <= 0) {
        libp2p_logger_error("secio", "Failed to exchange SECIO nonces\n");
        free(ctx);
        return NULL;
    }

    ctx->read_ctx = EVP_CIPHER_CTX_new();
    ctx->write_ctx = EVP_CIPHER_CTX_new();

    unsigned char key[32] = {0};
    unsigned char iv[16] = {0};

    EVP_EncryptInit_ex(ctx->write_ctx, EVP_aes_256_ctr(), NULL, key, iv);
    EVP_DecryptInit_ex(ctx->read_ctx, EVP_aes_256_ctr(), NULL, key, iv);

    struct Stream* encrypted_stream = (struct Stream*)calloc(1, sizeof(struct Stream));
    if (encrypted_stream == NULL) {
        EVP_CIPHER_CTX_free(ctx->read_ctx);
        EVP_CIPHER_CTX_free(ctx->write_ctx);
        free(ctx);
        return NULL;
    }

    encrypted_stream->stream_context = ctx;
    encrypted_stream->read = secio_stream_read;
    encrypted_stream->write = secio_stream_write;
    encrypted_stream->close = secio_stream_close;

    return encrypted_stream;
}
