#ifdef HAS_LSQUIC

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/bn.h>
#include <openssl/bytestring.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/objects.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "libp2p/conn/tls.h"
#include "libp2p/crypto/key.h"
#include "libp2p/crypto/rsa.h"
#include "libp2p/utils/debug.h"
#include "libp2p/utils/logger.h"

#define TLS_HANDSHAKE_PREFIX "libp2p-tls-handshake:"
#define TLS_HANDSHAKE_PREFIX_LEN (sizeof(TLS_HANDSHAKE_PREFIX) - 1)
#define TLS_ALPN "libp2p"

/* OID 1.3.6.1.4.1.53594.1.1 allocated to libp2p by IANA. */
#define LIBP2P_TLS_EXTENSION_OID "1.3.6.1.4.1.53594.1.1"

struct Libp2pTlsIdentity {
    SSL_CTX *ssl_ctx;
    EVP_PKEY *cert_key;
    X509 *cert;
    void *private_key;
    const noise_identity_callbacks_t *callbacks;
};

/* Forward declaration: the OpenSSL verify callback uses this. */
static int libp2p_tls_openssl_verify_callback(int preverify_ok, X509_STORE_CTX *ctx);

static int tls_identity_ex_data_index(void)
{
    static int idx = -1;
    if (idx < 0)
        idx = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, NULL);
    return idx;
}

static int tls_debug_scope_enabled(void)
{
    return libp2p_v2_debug_scope_enabled("tls");
}

static void tls_dbg(const char *fmt, ...)
{
    if (!tls_debug_scope_enabled())
        return;
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "[tls] ");
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fflush(stderr);
}

static int tls_alpn_select_cb(SSL *ssl, const uint8_t **out, uint8_t *outlen,
                              const uint8_t *in, unsigned inlen, void *arg)
{
    (void)ssl;
    (void)arg;
    const uint8_t *p = in;
    unsigned remaining = inlen;
    const size_t alpn_len = sizeof(TLS_ALPN) - 1;
    libp2p_v2_logger_info("tls", "ALPN select callback called with %u bytes\n", inlen);
    tls_dbg("ALPN select callback called with %u bytes\n", inlen);
    while (remaining > 0) {
        uint8_t proto_len = *p++;
        if (proto_len > remaining - 1)
            break;
        libp2p_v2_logger_info("tls", "ALPN candidate len=%u '%.*s'\n", proto_len, proto_len, (const char *)p);
        tls_dbg("ALPN candidate len=%u '%.*s'\n", proto_len, proto_len, (const char *)p);
        if (proto_len == alpn_len && memcmp(p, TLS_ALPN, alpn_len) == 0) {
            *out = p;
            *outlen = proto_len;
            libp2p_v2_logger_info("tls", "ALPN selected %s\n", TLS_ALPN);
            tls_dbg("ALPN selected %s\n", TLS_ALPN);
            return SSL_TLSEXT_ERR_OK;
        }
        p += proto_len;
        remaining -= (1 + proto_len);
    }
    libp2p_v2_logger_error("tls", "ALPN no match, rejecting\n");
    tls_dbg("ALPN no match, rejecting\n");
    return SSL_TLSEXT_ERR_NOACK;
}

/* Build the SignedKey ASN.1 structure: SEQUENCE { publicKey OCTET STRING,
 * signature OCTET STRING }. */
static int tls_build_signed_key(const uint8_t *pubkey, size_t pubkey_len,
                                const uint8_t *sig, size_t sig_len,
                                uint8_t **out_der, size_t *out_der_len)
{
    CBB cbb, seq, oct;
    if (!CBB_init(&cbb, 0))
        return 0;
    if (!CBB_add_asn1(&cbb, &seq, CBS_ASN1_SEQUENCE))
        goto err;
    if (!CBB_add_asn1(&seq, &oct, CBS_ASN1_OCTETSTRING))
        goto err;
    if (!CBB_add_bytes(&oct, pubkey, pubkey_len))
        goto err;
    if (!CBB_add_asn1(&seq, &oct, CBS_ASN1_OCTETSTRING))
        goto err;
    if (!CBB_add_bytes(&oct, sig, sig_len))
        goto err;
    if (!CBB_finish(&cbb, out_der, out_der_len))
        goto err;
    return 1;

err:
    CBB_cleanup(&cbb);
    return 0;
}

/* Parse the SignedKey ASN.1 structure.  Pointers point into ext_data and are
 * only valid while ext_data is alive. */
static int tls_parse_signed_key(const uint8_t *ext_data, size_t ext_len,
                                const uint8_t **pubkey, size_t *pubkey_len,
                                const uint8_t **sig, size_t *sig_len)
{
    CBS cbs, seq, oct;
    CBS_init(&cbs, ext_data, ext_len);
    if (!CBS_get_asn1(&cbs, &seq, CBS_ASN1_SEQUENCE))
        return 0;
    if (!CBS_get_asn1(&seq, &oct, CBS_ASN1_OCTETSTRING))
        return 0;
    *pubkey = CBS_data(&oct);
    *pubkey_len = CBS_len(&oct);
    if (!CBS_get_asn1(&seq, &oct, CBS_ASN1_OCTETSTRING))
        return 0;
    *sig = CBS_data(&oct);
    *sig_len = CBS_len(&oct);
    if (CBS_len(&seq) != 0)
        return 0;
    return 1;
}

static EVP_PKEY* tls_generate_ecdsa_key(void)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!ctx)
        return NULL;
    if (EVP_PKEY_keygen_init(ctx) <= 0)
        goto err;
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0)
        goto err;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
        goto err;
    EVP_PKEY_CTX_free(ctx);
    return pkey;

err:
    EVP_PKEY_CTX_free(ctx);
    return NULL;
}

static int tls_sign_cert_key(void *private_key,
                             const noise_identity_callbacks_t *cbs,
                             EVP_PKEY *cert_key,
                             uint8_t **out_sig, size_t *out_sig_len)
{
    int ret = 0;
    uint8_t *spki_der = NULL;
    uint8_t *sig = NULL;
    size_t sig_len = 0;

    int spki_len = i2d_PUBKEY(cert_key, &spki_der);
    if (spki_len <= 0 || !spki_der)
        return 0;

    size_t to_sign_len = TLS_HANDSHAKE_PREFIX_LEN + (size_t)spki_len;
    char *to_sign = (char *)malloc(to_sign_len);
    if (!to_sign)
        goto cleanup;
    memcpy(to_sign, TLS_HANDSHAKE_PREFIX, TLS_HANDSHAKE_PREFIX_LEN);
    memcpy(to_sign + TLS_HANDSHAKE_PREFIX_LEN, spki_der, (size_t)spki_len);

    /* The TLS prefix is already part of to_sign; avoid the Noise prefix. */
    int (*sign_fn)(void *, const uint8_t *, size_t, uint8_t **, size_t *) =
        cbs->sign_raw ? cbs->sign_raw : cbs->sign;
    if (!sign_fn(private_key, (const uint8_t *)to_sign, to_sign_len, &sig, &sig_len))
        goto cleanup;

    *out_sig = sig;
    *out_sig_len = sig_len;
    ret = 1;

cleanup:
    OPENSSL_free(spki_der);
    free(to_sign);
    return ret;
}

static X509* tls_build_certificate(EVP_PKEY *cert_key,
                                   const uint8_t *identity_key,
                                   size_t identity_key_len,
                                   const uint8_t *sig, size_t sig_len)
{
    X509 *cert = NULL;
    ASN1_OBJECT *obj = NULL;
    ASN1_OCTET_STRING *ext_data = NULL;
    X509_EXTENSION *ext = NULL;
    uint8_t *signed_key_der = NULL;
    size_t signed_key_der_len = 0;
    uint8_t serial_bytes[8];
    uint64_t serial_val = 0;
    ASN1_INTEGER *serial_asn1 = NULL;

    if (!tls_build_signed_key(identity_key, identity_key_len, sig, sig_len,
                              &signed_key_der, &signed_key_der_len))
        return NULL;

    cert = X509_new();
    if (!cert)
        goto err;
    if (!X509_set_version(cert, 2))
        goto err;

    if (RAND_bytes(serial_bytes, sizeof(serial_bytes)) != 1)
        goto err;
    for (size_t i = 0; i < sizeof(serial_bytes); i++)
        serial_val = (serial_val << 8) | serial_bytes[i];
    serial_asn1 = ASN1_INTEGER_new();
    if (!serial_asn1 || !ASN1_INTEGER_set_uint64(serial_asn1, serial_val))
        goto err;
    if (!X509_set_serialNumber(cert, serial_asn1))
        goto err;

    X509_NAME *name = X509_get_subject_name(cert);
    if (!X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
                                    (const unsigned char *)"libp2p.io", -1, -1, 0))
        goto err;
    char serial_str[32];
    snprintf(serial_str, sizeof(serial_str), "%llu", (unsigned long long)serial_val);
    if (!X509_NAME_add_entry_by_txt(name, "serialNumber", MBSTRING_ASC,
                                    (const unsigned char *)serial_str, -1, -1, 0))
        goto err;
    if (!X509_set_issuer_name(cert, name))
        goto err;

    if (!X509_gmtime_adj(X509_getm_notBefore(cert), -3600))
        goto err;
    if (!X509_gmtime_adj(X509_getm_notAfter(cert), 100L * 365 * 24 * 3600))
        goto err;

    if (!X509_set_pubkey(cert, cert_key))
        goto err;

    obj = OBJ_txt2obj(LIBP2P_TLS_EXTENSION_OID, 1);
    if (!obj)
        goto err;
    ext_data = ASN1_OCTET_STRING_new();
    if (!ext_data || !ASN1_OCTET_STRING_set(ext_data, signed_key_der, (int)signed_key_der_len))
        goto err;
    ext = X509_EXTENSION_create_by_OBJ(NULL, obj, 0, ext_data);
    if (!ext || !X509_add_ext(cert, ext, -1))
        goto err;

    if (!X509_sign(cert, cert_key, EVP_sha256()))
        goto err;

    goto cleanup;

err:
    X509_free(cert);
    cert = NULL;

cleanup:
    X509_EXTENSION_free(ext);
    ASN1_OCTET_STRING_free(ext_data);
    ASN1_OBJECT_free(obj);
    OPENSSL_free(signed_key_der);
    ASN1_INTEGER_free(serial_asn1);
    return cert;
}

struct Libp2pTlsIdentity* libp2p_tls_identity_new(void *private_key,
                                                  const noise_identity_callbacks_t *callbacks)
{
    if (!private_key || !callbacks)
        return NULL;

    struct Libp2pTlsIdentity *identity = (struct Libp2pTlsIdentity *)calloc(1, sizeof(*identity));
    if (!identity)
        return NULL;

    identity->private_key = private_key;
    identity->callbacks = callbacks;

    uint8_t *identity_key = NULL;
    size_t identity_key_len = 0;
    uint8_t *sig = NULL;
    size_t sig_len = 0;

    if (!callbacks->get_identity_key(private_key, &identity_key, &identity_key_len))
        goto err;

    identity->cert_key = tls_generate_ecdsa_key();
    if (!identity->cert_key)
        goto err;

    if (!tls_sign_cert_key(private_key, callbacks, identity->cert_key, &sig, &sig_len))
        goto err;

    identity->cert = tls_build_certificate(identity->cert_key, identity_key, identity_key_len,
                                           sig, sig_len);
    if (!identity->cert)
        goto err;

    identity->ssl_ctx = SSL_CTX_new(TLS_method());
    if (!identity->ssl_ctx)
        goto err;

    SSL_CTX_set_min_proto_version(identity->ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(identity->ssl_ctx, TLS1_3_VERSION);
    /* Server mode relies on this OpenSSL verify callback because lsquic only
     * installs its custom verify callback for client-side IETF QUIC sessions.
     * The callback performs libp2p peer-certificate verification and returns
     * success so that the handshake can complete for self-signed certs. */
    SSL_CTX_set_ex_data(identity->ssl_ctx, tls_identity_ex_data_index(), identity);
    SSL_CTX_set_verify(identity->ssl_ctx,
                       SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                       libp2p_tls_openssl_verify_callback);

    if (SSL_CTX_use_certificate(identity->ssl_ctx, identity->cert) != 1)
        goto err;
    if (SSL_CTX_use_PrivateKey(identity->ssl_ctx, identity->cert_key) != 1)
        goto err;

    /* ALPN "libp2p" for both client and server. RFC 7301 length-prefixed. */
    const size_t alpn_proto_len = sizeof(TLS_ALPN) - 1;
    uint8_t alpn[1 + sizeof(TLS_ALPN) - 1];
    alpn[0] = (uint8_t)alpn_proto_len;
    memcpy(alpn + 1, TLS_ALPN, alpn_proto_len);
    if (SSL_CTX_set_alpn_protos(identity->ssl_ctx, alpn, sizeof(alpn)) != 0)
        tls_dbg("warning: SSL_CTX_set_alpn_protos failed\n");
    /* Server side: lsquic/BoringSSL needs a select callback to advertise the
     * ALPN response. */
    SSL_CTX_set_alpn_select_cb(identity->ssl_ctx, tls_alpn_select_cb, NULL);

    callbacks->free_buffer(identity_key);
    callbacks->free_buffer(sig);
    return identity;

err:
    if (identity_key)
        callbacks->free_buffer(identity_key);
    if (sig)
        callbacks->free_buffer(sig);
    libp2p_tls_identity_free(identity);
    return NULL;
}

void libp2p_tls_identity_free(struct Libp2pTlsIdentity *identity)
{
    if (!identity)
        return;
    if (identity->ssl_ctx)
        SSL_CTX_free(identity->ssl_ctx);
    if (identity->cert)
        X509_free(identity->cert);
    if (identity->cert_key)
        EVP_PKEY_free(identity->cert_key);
    free(identity);
}

SSL_CTX* libp2p_tls_identity_ssl_ctx(struct Libp2pTlsIdentity *identity)
{
    if (!identity)
        return NULL;
    return identity->ssl_ctx;
}

int libp2p_tls_verify_peer_cert(X509 *cert,
                                const char *expected_peer_id,
                                const noise_identity_callbacks_t *callbacks)
{
    if (!cert || !callbacks)
        return 0;

    /* Chain length is enforced by lsquic (one end-entity cert). */
    EVP_PKEY *pubkey = X509_get_pubkey(cert);
    if (!pubkey)
        return 0;

    int ret = 0;
    if (X509_verify(cert, pubkey) != 1) {
        libp2p_v2_logger_error("tls", "certificate self-signature invalid\n");
        tls_dbg("certificate self-signature invalid\n");
        goto cleanup;
    }

    if (X509_cmp_current_time(X509_get_notBefore(cert)) > 0) {
        libp2p_v2_logger_error("tls", "certificate not yet valid\n");
        tls_dbg("certificate not yet valid\n");
        goto cleanup;
    }
    if (X509_cmp_current_time(X509_get_notAfter(cert)) < 0) {
        libp2p_v2_logger_error("tls", "certificate expired\n");
        tls_dbg("certificate expired\n");
        goto cleanup;
    }

    ASN1_OBJECT *obj = OBJ_txt2obj(LIBP2P_TLS_EXTENSION_OID, 1);
    if (!obj)
        goto cleanup;
    int ext_idx = X509_get_ext_by_OBJ(cert, obj, -1);
    ASN1_OBJECT_free(obj);
    if (ext_idx < 0) {
        libp2p_v2_logger_error("tls", "libp2p public key extension missing\n");
        tls_dbg("libp2p public key extension missing\n");
        goto cleanup;
    }

    X509_EXTENSION *ext = X509_get_ext(cert, ext_idx);
    if (!ext)
        goto cleanup;
    ASN1_OCTET_STRING *ext_value = X509_EXTENSION_get_data(ext);
    if (!ext_value)
        goto cleanup;

    const uint8_t *identity_key = NULL;
    size_t identity_key_len = 0;
    const uint8_t *sig = NULL;
    size_t sig_len = 0;
    if (!tls_parse_signed_key(ASN1_STRING_get0_data(ext_value),
                              (size_t)ASN1_STRING_length(ext_value),
                              &identity_key, &identity_key_len,
                              &sig, &sig_len)) {
        libp2p_v2_logger_error("tls", "failed to parse libp2p SignedKey extension\n");
        tls_dbg("failed to parse libp2p SignedKey extension\n");
        goto cleanup;
    }

    struct PublicKey *pub_key = NULL;
    if (!libp2p_crypto_public_key_protobuf_decode((unsigned char *)identity_key,
                                                  identity_key_len, &pub_key)) {
        libp2p_v2_logger_error("tls", "failed to decode identity public key\n");
        tls_dbg("failed to decode identity public key\n");
        goto cleanup;
    }

    if (expected_peer_id) {
        char *peer_id = NULL;
        if (!libp2p_crypto_public_key_to_peer_id(pub_key, &peer_id)) {
            libp2p_crypto_public_key_free(pub_key);
            goto cleanup;
        }
        int match = (strcmp(peer_id, expected_peer_id) == 0);
        free(peer_id);
        if (!match) {
            libp2p_v2_logger_error("tls", "peer ID mismatch: expected %s\n", expected_peer_id);
            tls_dbg("peer ID mismatch: expected %s\n", expected_peer_id);
            libp2p_crypto_public_key_free(pub_key);
            goto cleanup;
        }
    }

    uint8_t *spki_der = NULL;
    int spki_len = i2d_PUBKEY(pubkey, &spki_der);
    if (spki_len <= 0 || !spki_der) {
        libp2p_crypto_public_key_free(pub_key);
        goto cleanup;
    }

    size_t to_verify_len = TLS_HANDSHAKE_PREFIX_LEN + (size_t)spki_len;
    unsigned char *to_verify = (unsigned char *)malloc(to_verify_len);
    if (!to_verify) {
        OPENSSL_free(spki_der);
        libp2p_crypto_public_key_free(pub_key);
        goto cleanup;
    }
    memcpy(to_verify, TLS_HANDSHAKE_PREFIX, TLS_HANDSHAKE_PREFIX_LEN);
    memcpy(to_verify + TLS_HANDSHAKE_PREFIX_LEN, spki_der, (size_t)spki_len);
    OPENSSL_free(spki_der);

    if (!(callbacks->verify_raw ? callbacks->verify_raw : callbacks->verify)(
            identity_key, identity_key_len, to_verify, to_verify_len, sig, sig_len)) {
        libp2p_v2_logger_error("tls", "libp2p extension signature invalid\n");
        tls_dbg("libp2p extension signature invalid\n");
        free(to_verify);
        libp2p_crypto_public_key_free(pub_key);
        goto cleanup;
    }

    free(to_verify);
    libp2p_crypto_public_key_free(pub_key);
    libp2p_v2_logger_info("tls", "peer certificate verified\n");
    ret = 1;

cleanup:
    EVP_PKEY_free(pubkey);
    return ret;
}

/* OpenSSL/BoringSSL certificate verify callback.  Used in server mode (and
 * harmless in client mode because lsquic installs its own custom verify
 * callback for clients).  We accept only depth 0 and run the libp2p TLS
 * extension check; any other depth is irrelevant because libp2p only sends a
 * single end-entity certificate. */
static int libp2p_tls_openssl_verify_callback(int preverify_ok, X509_STORE_CTX *ctx)
{
    (void)preverify_ok;
    if (!ctx)
        return 0;

    SSL *ssl = X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
    if (!ssl)
        return 0;
    SSL_CTX *ssl_ctx = SSL_get_SSL_CTX(ssl);
    if (!ssl_ctx)
        return 0;
    struct Libp2pTlsIdentity *identity = SSL_CTX_get_ex_data(ssl_ctx, tls_identity_ex_data_index());
    if (!identity)
        return 0;

    int depth = X509_STORE_CTX_get_error_depth(ctx);
    if (depth != 0)
        return 1;

    X509 *cert = X509_STORE_CTX_get_current_cert(ctx);
    if (!cert)
        return 0;

    if (!libp2p_tls_verify_peer_cert(cert, NULL, identity->callbacks)) {
        libp2p_v2_logger_error("tls", "openssl verify callback: peer certificate verification failed\n");
        tls_dbg("openssl verify callback: peer certificate verification failed\n");
        return 0;
    }
    libp2p_v2_logger_info("tls", "openssl verify callback: peer certificate verified\n");
    tls_dbg("openssl verify callback: peer certificate verified\n");
    return 1;
}

#endif /* HAS_LSQUIC */
