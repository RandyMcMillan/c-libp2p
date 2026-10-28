#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libp2p/identify/identify_v2.h"
#include "libp2p/crypto/key.h"
#include "libp2p/crypto/peerutils.h"
#include "libp2p/utils/logger.h"
#include "protobuf.h"

IdentifyInfo* libp2p_identify_info_new(void) {
    IdentifyInfo* info = (IdentifyInfo*)calloc(1, sizeof(IdentifyInfo));
    return info;
}

void libp2p_identify_info_free(IdentifyInfo* info) {
    if (!info) return;
    if (info->public_key) free(info->public_key);
    if (info->listen_addrs) {
        for (size_t i = 0; i < info->listen_addrs_count; i++)
            free(info->listen_addrs[i]);
        free(info->listen_addrs);
    }
    if (info->protocols) {
        for (size_t i = 0; i < info->protocols_count; i++)
            free(info->protocols[i]);
        free(info->protocols);
    }
    if (info->observed_addr) free(info->observed_addr);
    if (info->protocol_version) free(info->protocol_version);
    if (info->agent_version) free(info->agent_version);
    free(info);
}

static int add_string_to_array(char*** array, size_t* count, char* item) {
    char** new_arr = realloc(*array, (*count + 1) * sizeof(char*));
    if (!new_arr) return 0;
    new_arr[*count] = item;
    *array = new_arr;
    (*count)++;
    return 1;
}

int libp2p_identify_send_response(struct Libp2pV2Stream* stream, struct Libp2pV2Peerstore* peerstore) {
    if (!stream || !peerstore) return 0;

    unsigned char buf[4096];
    size_t written = 0;
    size_t bytes = 0;

    /* Field 5: protocolVersion */
    if (!protobuf_encode_string(5, WIRETYPE_LENGTH_DELIMITED, IDENTIFY_PROTOCOL_VERSION,
                                buf + written, sizeof(buf) - written, &bytes))
        return 0;
    written += bytes;

    /* Field 6: agentVersion */
    if (!protobuf_encode_string(6, WIRETYPE_LENGTH_DELIMITED, IDENTIFY_AGENT_VERSION,
                                buf + written, sizeof(buf) - written, &bytes))
        return 0;
    written += bytes;

    /* Field 1: publicKey */
    if (peerstore->public_key && peerstore->public_key_len > 0) {
        if (!protobuf_encode_length_delimited(1, WIRETYPE_LENGTH_DELIMITED,
                                              (const char*)peerstore->public_key, peerstore->public_key_len,
                                              buf + written, sizeof(buf) - written, &bytes))
            return 0;
        written += bytes;
    }

    /* Field 2: listenAddrs */
    if (peerstore->listen_addrs) {
        for (size_t i = 0; i < peerstore->listen_addrs_count; i++) {
            if (!protobuf_encode_length_delimited(2, WIRETYPE_LENGTH_DELIMITED,
                                                  peerstore->listen_addrs[i], strlen(peerstore->listen_addrs[i]),
                                                  buf + written, sizeof(buf) - written, &bytes))
                return 0;
            written += bytes;
        }
    }

    ssize_t ret = stream->write(stream, buf, written);
    if (ret != (ssize_t)written) {
        libp2p_v2_logger_error("identify", "Failed to write Identify response\n");
        return 0;
    }

    return 1;
}

int libp2p_identify_receive(struct Libp2pV2Stream* stream, struct Libp2pPeer* peer) {
    if (!stream || !peer) return 0;

    unsigned char buf[4096];
    ssize_t total = 0;
    ssize_t ret;

    /* Read up to sizeof(buf) or until stream returns 0/-1 */
    while (total < (ssize_t)sizeof(buf)) {
        ret = stream->read(stream, buf + total, sizeof(buf) - total);
        if (ret <= 0) break;
        total += ret;
    }

    if (total == 0) {
        libp2p_v2_logger_error("identify", "No data received on identify stream\n");
        return 0;
    }

    IdentifyInfo* info = libp2p_identify_info_new();
    if (!info) return 0;

    size_t pos = 0;
    int success = 1;

    while ((size_t)pos < (size_t)total) {
        int field_no;
        enum WireType field_type;
        size_t field_bytes = 0;

        if (!protobuf_decode_field_and_type(buf + pos, (int)(total - pos), &field_no, &field_type, &field_bytes)) {
            success = 0;
            break;
        }
        pos += field_bytes;

        char* str_val = NULL;
        size_t str_len = 0;

        switch (field_no) {
            case 1: /* publicKey */
                if (!protobuf_decode_string(buf + pos, total - pos, &str_val, &str_len)) {
                    success = 0;
                } else {
                    info->public_key = str_val;
                    info->public_key_len = str_len;
                }
                pos += str_len;
                break;

            case 2: /* listenAddrs */
                if (!protobuf_decode_string(buf + pos, total - pos, &str_val, &str_len)) {
                    success = 0;
                } else {
                    add_string_to_array(&info->listen_addrs, &info->listen_addrs_count, str_val);
                }
                pos += str_len;
                break;

            case 3: /* protocols */
                if (!protobuf_decode_string(buf + pos, total - pos, &str_val, &str_len)) {
                    success = 0;
                } else {
                    add_string_to_array(&info->protocols, &info->protocols_count, str_val);
                }
                pos += str_len;
                break;

            case 4: /* observedAddr */
                if (!protobuf_decode_string(buf + pos, total - pos, &str_val, &str_len)) {
                    success = 0;
                } else {
                    info->observed_addr = str_val;
                    info->observed_addr_len = str_len;
                }
                pos += str_len;
                break;

            case 5: /* protocolVersion */
                if (!protobuf_decode_string(buf + pos, total - pos, &str_val, &str_len)) {
                    success = 0;
                } else {
                    info->protocol_version = str_val;
                }
                pos += str_len;
                break;

            case 6: /* agentVersion */
                if (!protobuf_decode_string(buf + pos, total - pos, &str_val, &str_len)) {
                    success = 0;
                } else {
                    info->agent_version = str_val;
                }
                pos += str_len;
                break;

            default:
                /* Skip unknown fields (length-delimited) */
                if (field_type == WIRETYPE_LENGTH_DELIMITED) {
                    size_t skip_len = 0;
                    char* skip = NULL;
                    protobuf_decode_string(buf + pos, total - pos, &skip, &skip_len);
                    if (skip) free(skip);
                    pos += skip_len;
                }
                break;
        }

        if (!success) break;
    }

    if (success) {
        libp2p_v2_logger_info("identify", "Received identify from peer: agent=%s proto=%s\n",
                           info->agent_version ? info->agent_version : "?",
                           info->protocol_version ? info->protocol_version : "?");
        /* Populate peer from public_key and listen_addrs */
        if (peer != NULL && info->public_key != NULL && info->public_key_len > 0) {
            struct PublicKey* pubkey = NULL;
            if (libp2p_crypto_public_key_protobuf_decode((unsigned char*)info->public_key, info->public_key_len, &pubkey)) {
                char* peer_id = NULL;
                if (libp2p_crypto_public_key_to_peer_id(pubkey, &peer_id) && peer_id != NULL) {
                    if (peer->peer_id != NULL)
                        free(peer->peer_id);
                    peer->peer_id = peer_id;
                }
                libp2p_crypto_public_key_free(pubkey);
            }
            if (info->listen_addrs != NULL && info->listen_addrs_count > 0) {
                for (size_t i = 0; i < info->listen_addrs_count; i++) {
                    struct MultiAddress* ma = libp2p_multiaddr_new_from_string(info->listen_addrs[i]);
                    if (ma != NULL) {
                        struct Libp2pLinkedList* node = (struct Libp2pLinkedList*)malloc(sizeof(struct Libp2pLinkedList));
                        if (node != NULL) {
                            node->item = ma;
                            node->next = peer->addr_head;
                            peer->addr_head = node;
                        } else {
                            libp2p_multiaddr_free(ma);
                        }
                    }
                }
            }
        }
    }

    libp2p_identify_info_free(info);
    return success;
}
