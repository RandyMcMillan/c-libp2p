#include <stdlib.h>
#include <string.h>

#include "libp2p/crypto/sha256.h"
#include "libp2p/routing/dht_utils.h"
#include "libp2p/utils/logger.h"

int libp2p_routing_dht_hash_peer_id(const char* peer_id, size_t peer_id_size, unsigned char* hash_out) {
    unsigned char sha[32];
    if (!libp2p_crypto_hashing_sha256((const unsigned char*)peer_id, peer_id_size, sha)) {
        return 0;
    }
    memcpy(hash_out, sha, DHT_ID_SIZE);
    return 1;
}

void libp2p_routing_dht_xor_distance(const unsigned char* a, const unsigned char* b, unsigned char* distance_out) {
    for (int i = 0; i < DHT_ID_SIZE; i++) {
        distance_out[i] = a[i] ^ b[i];
    }
}

int libp2p_routing_dht_distance_cmp(const unsigned char* d1, const unsigned char* d2) {
    for (int i = 0; i < DHT_ID_SIZE; i++) {
        if (d1[i] != d2[i]) {
            return (int)d1[i] - (int)d2[i];
        }
    }
    return 0;
}

int libp2p_routing_dht_find_closest_peers(struct Peerstore* peerstore, const unsigned char* target_key, size_t target_key_size, int num_results, struct Libp2pPeer** results_out) {
    if (peerstore == NULL || num_results <= 0 || results_out == NULL) {
        return 0;
    }

    unsigned char target_hash[DHT_ID_SIZE];
    if (!libp2p_routing_dht_hash_peer_id((const char*)target_key, target_key_size, target_hash)) {
        return 0;
    }

    // Simple selection: keep an array of the N closest peers seen so far
    struct Libp2pPeer** closest = (struct Libp2pPeer**)calloc(num_results, sizeof(struct Libp2pPeer*));
    unsigned char* distances = (unsigned char*)calloc(num_results, DHT_ID_SIZE);
    if (closest == NULL || distances == NULL) {
        free(closest);
        free(distances);
        return 0;
    }

    // Initialize distances to max
    for (int i = 0; i < num_results; i++) {
        memset(&distances[i * DHT_ID_SIZE], 0xFF, DHT_ID_SIZE);
    }

    int found = 0;
    struct Libp2pLinkedList* current_entry = peerstore->head_entry;
    while (current_entry != NULL) {
        struct PeerEntry* entry = (struct PeerEntry*)current_entry->item;
        if (entry == NULL || entry->peer == NULL) {
            current_entry = current_entry->next;
            continue;
        }
        struct Libp2pPeer* peer = entry->peer;
        if (peer->is_local) {
            current_entry = current_entry->next;
            continue;
        }

        unsigned char peer_hash[DHT_ID_SIZE];
        if (!libp2p_routing_dht_hash_peer_id(peer->id, peer->id_size, peer_hash)) {
            current_entry = current_entry->next;
            continue;
        }

        unsigned char distance[DHT_ID_SIZE];
        libp2p_routing_dht_xor_distance(target_hash, peer_hash, distance);

        // Check if this peer is closer than any we have
        int inserted = 0;
        for (int i = 0; i < num_results; i++) {
            if (libp2p_routing_dht_distance_cmp(distance, &distances[i * DHT_ID_SIZE]) < 0) {
                // Shift worse peers down
                for (int j = num_results - 1; j > i; j--) {
                    closest[j] = closest[j - 1];
                    memcpy(&distances[j * DHT_ID_SIZE], &distances[(j - 1) * DHT_ID_SIZE], DHT_ID_SIZE);
                }
                closest[i] = peer;
                memcpy(&distances[i * DHT_ID_SIZE], distance, DHT_ID_SIZE);
                inserted = 1;
                if (found < num_results) {
                    found++;
                }
                break;
            }
        }
        (void)inserted;
        current_entry = current_entry->next;
    }

    // Copy results out (borrowed references, do not free)
    for (int i = 0; i < found; i++) {
        results_out[i] = closest[i];
    }

    free(closest);
    free(distances);
    return found;
}
