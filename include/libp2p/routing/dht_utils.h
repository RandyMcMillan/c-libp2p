#pragma once

#include "libp2p/peer/peerstore.h"
#include "libp2p/peer/peer.h"

#define DHT_ID_SIZE 20

/**
 * Hash a peer ID string to a DHT-compatible 20-byte ID.
 * Uses SHA256 and copies the first 20 bytes, matching dht_hash behavior.
 * @param peer_id the peer ID string
 * @param peer_id_size the length of the string
 * @param hash_out must be at least DHT_ID_SIZE bytes
 * @returns true(1) on success, false(0) otherwise
 */
int libp2p_routing_dht_hash_peer_id(const char* peer_id, size_t peer_id_size, unsigned char* hash_out);

/**
 * Compute XOR distance between two 20-byte hashes.
 * Stores the result in distance_out (DHT_ID_SIZE bytes).
 * @param a first 20-byte hash
 * @param b second 20-byte hash
 * @param distance_out output buffer (DHT_ID_SIZE bytes)
 */
void libp2p_routing_dht_xor_distance(const unsigned char* a, const unsigned char* b, unsigned char* distance_out);

/**
 * Compare two XOR distances (lexicographically, big-endian).
 * @param d1 first distance
 * @param d2 second distance
 * @returns negative if d1 < d2, 0 if equal, positive if d1 > d2
 */
int libp2p_routing_dht_distance_cmp(const unsigned char* d1, const unsigned char* d2);

/**
 * Find the N closest peers in a peerstore to a target key by XOR distance.
 * @param peerstore the peerstore to search
 * @param target_key the target key (any byte array)
 * @param target_key_size size of target_key
 * @param num_results maximum number of peers to return
 * @param results_out caller-allocated array of Libp2pPeer* pointers (num_results entries)
 * @returns the number of peers found (0..num_results)
 */
int libp2p_routing_dht_find_closest_peers(struct Peerstore* peerstore, const unsigned char* target_key, size_t target_key_size, int num_results, struct Libp2pPeer** results_out);
