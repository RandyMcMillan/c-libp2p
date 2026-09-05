#include <stdlib.h>
#include <string.h>

#include "libp2p/identify/identify_v2.h"
#include "libp2p/identify/identify_v2_ipfs.h"
#include "libp2p/peer/peerstore.h"
#include "libp2p/crypto/key.h"

int libp2p_identify_send_response_ipfs(struct Libp2pV2Stream* stream,
                                        const char* peer_id,
                                        const unsigned char* public_key_der,
                                        size_t public_key_len,
                                        char** listen_addrs,
                                        size_t listen_addrs_count) {
    if (!stream)
        return 0;

    struct Libp2pV2Peerstore* v2_ps = libp2p_v2_peerstore_new(peer_id);
    if (!v2_ps)
        return 0;

    /* Public key (protobuf-encoded RSA) */
    if (public_key_der && public_key_len > 0) {
        struct PublicKey pubkey;
        memset(&pubkey, 0, sizeof(pubkey));
        pubkey.type = KEYTYPE_RSA;
        pubkey.data = (unsigned char*)public_key_der;
        pubkey.data_size = public_key_len;

        size_t pb_len = libp2p_crypto_public_key_protobuf_encode_size(&pubkey);
        v2_ps->public_key = (unsigned char*)malloc(pb_len);
        if (v2_ps->public_key) {
            size_t written = 0;
            if (libp2p_crypto_public_key_protobuf_encode(&pubkey, v2_ps->public_key, pb_len, &written)) {
                v2_ps->public_key_len = written;
            } else {
                free(v2_ps->public_key);
                v2_ps->public_key = NULL;
            }
        }
    }

    /* Listen addresses */
    if (listen_addrs && listen_addrs_count > 0) {
        v2_ps->listen_addrs = (char**)calloc(listen_addrs_count, sizeof(char*));
        v2_ps->listen_addrs_count = 0;
        for (size_t i = 0; i < listen_addrs_count; i++) {
            if (listen_addrs[i]) {
                v2_ps->listen_addrs[v2_ps->listen_addrs_count++] = strdup(listen_addrs[i]);
            }
        }
    }

    int ret = libp2p_identify_send_response(stream, v2_ps);
    libp2p_v2_peerstore_free(v2_ps);
    return ret;
}
