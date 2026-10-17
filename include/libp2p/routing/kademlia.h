#pragma once

#include "libp2p/utils/vector.h"
#include "multiaddr/multiaddr.h"

/**
 * Compute a bounded exponential backoff delay in microseconds.
 * @param attempt the retry attempt number (0-based)
 * @param base_us the initial delay
 * @param max_us the maximum delay cap
 * @returns a jittered delay in microseconds in the range [base_us, max_us]
 */
unsigned int dht_backoff_delay_us(int attempt, unsigned int base_us, unsigned int max_us);

int start_kademlia(int sock, int family, char* peer_id, int timeout, struct Libp2pVector* bootstrap_addresses);
int start_kademlia_multiaddress(struct MultiAddress* multiaddress, char* peer_id, int timeout, struct Libp2pVector* bootstrap_addresses);
void stop_kademlia (void);

void *kademlia_thread (void *ptr);
void *announce_thread (void *ptr);

int announce_kademlia (char* peer_id, uint16_t port);

/***
 * Search for a hash
 * @param peer_id the hash to search for
 * @param timeout timeout in seconds
 * @returns an array of MultiAddress
 */
struct MultiAddress** search_kademlia(char* peer_id, int timeout);

int ping_kademlia (char *ip, uint16_t port);
