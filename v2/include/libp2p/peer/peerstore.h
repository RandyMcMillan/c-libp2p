#ifndef LIBP2P_PEER_PEERSTORE_H
#define LIBP2P_PEER_PEERSTORE_H

#include "libp2p/net/multiaddr.h"

struct Libp2pLinkedList {
    void* item;
    struct Libp2pLinkedList* next;
};

struct Libp2pPeer {
    char* peer_id;
    struct Libp2pLinkedList* addr_head;
    struct Libp2pV2Stream* connection;
    void* sessionContext;
};

struct PeerEntry {
    struct Libp2pPeer* peer;
    struct PeerEntry* next;
};

struct Libp2pV2Peerstore {
    char* local_peer_id;
    struct PeerEntry* head;
    /* Identity public key (protobuf-encoded) for Identify protocol */
    unsigned char* public_key;
    size_t public_key_len;
    /* Listen addresses for Identify protocol */
    char** listen_addrs;
    size_t listen_addrs_count;
};

struct Libp2pV2Peerstore* libp2p_v2_peerstore_new(const char* local_peer_id);
int libp2p_v2_peerstore_add_peer(struct Libp2pV2Peerstore* peerstore, struct Libp2pPeer* peer);
struct Libp2pPeer* libp2p_v2_peerstore_get_peer(struct Libp2pV2Peerstore* peerstore, const char* peer_id);
int libp2p_v2_peerstore_add_address(struct Libp2pV2Peerstore* peerstore, const char* peer_id, struct MultiAddress* ma);
void libp2p_v2_peerstore_free(struct Libp2pV2Peerstore* peerstore);

#endif /* LIBP2P_PEER_PEERSTORE_H */
