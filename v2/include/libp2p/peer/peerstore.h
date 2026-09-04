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

struct Peerstore {
    char* local_peer_id;
    struct PeerEntry* head;
};

struct Peerstore* libp2p_peerstore_new(const char* local_peer_id);
int libp2p_peerstore_add_peer(struct Peerstore* peerstore, struct Libp2pPeer* peer);
struct Libp2pPeer* libp2p_peerstore_get_peer(struct Peerstore* peerstore, const char* peer_id);
int libp2p_peerstore_add_address(struct Peerstore* peerstore, const char* peer_id, struct MultiAddress* ma);
void libp2p_peerstore_free(struct Peerstore* peerstore);

#endif /* LIBP2P_PEER_PEERSTORE_H */
