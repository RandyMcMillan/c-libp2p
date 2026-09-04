#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libp2p/peer/peerstore.h"
#include "libp2p/utils/logger.h"

struct Peerstore* libp2p_peerstore_new(const char* local_peer_id) {
    struct Peerstore* ps = (struct Peerstore*)malloc(sizeof(struct Peerstore));
    if (ps != NULL) {
        memset(ps, 0, sizeof(struct Peerstore));
        if (local_peer_id != NULL) {
            ps->local_peer_id = strdup(local_peer_id);
        }
        ps->head = NULL;
    }
    return ps;
}

int libp2p_peerstore_add_peer(struct Peerstore* peerstore, struct Libp2pPeer* peer) {
    if (peerstore == NULL || peer == NULL)
        return 0;

    struct PeerEntry* current = peerstore->head;
    while (current != NULL) {
        if (current->peer != NULL && current->peer->peer_id != NULL && peer->peer_id != NULL) {
            if (strcmp(current->peer->peer_id, peer->peer_id) == 0) {
                current->peer = peer;
                return 1;
            }
        }
        current = current->next;
    }

    struct PeerEntry* new_entry = (struct PeerEntry*)malloc(sizeof(struct PeerEntry));
    if (new_entry == NULL)
        return 0;

    new_entry->peer = peer;
    new_entry->next = peerstore->head;
    peerstore->head = new_entry;

    return 1;
}

struct Libp2pPeer* libp2p_peerstore_get_peer(struct Peerstore* peerstore, const char* peer_id) {
    if (peerstore == NULL || peer_id == NULL)
        return NULL;

    struct PeerEntry* current = peerstore->head;
    while (current != NULL) {
        if (current->peer != NULL && current->peer->peer_id != NULL) {
            if (strcmp(current->peer->peer_id, peer_id) == 0) {
                return current->peer;
            }
        }
        current = current->next;
    }
    return NULL;
}

int libp2p_peerstore_add_address(struct Peerstore* peerstore, const char* peer_id, struct MultiAddress* ma) {
    if (peerstore == NULL || peer_id == NULL || ma == NULL)
        return 0;

    struct Libp2pPeer* peer = libp2p_peerstore_get_peer(peerstore, peer_id);
    if (peer == NULL) {
        peer = (struct Libp2pPeer*)calloc(1, sizeof(struct Libp2pPeer));
        if (peer == NULL)
            return 0;
        peer->peer_id = strdup(peer_id);
        libp2p_peerstore_add_peer(peerstore, peer);
    }

    struct Libp2pLinkedList* new_node = (struct Libp2pLinkedList*)malloc(sizeof(struct Libp2pLinkedList));
    if (new_node == NULL)
        return 0;

    new_node->item = ma;
    new_node->next = peer->addr_head;
    peer->addr_head = new_node;

    return 1;
}

void libp2p_peerstore_free(struct Peerstore* peerstore) {
    if (peerstore == NULL)
        return;

    if (peerstore->local_peer_id != NULL) {
        free(peerstore->local_peer_id);
    }

    struct PeerEntry* current = peerstore->head;
    while (current != NULL) {
        struct PeerEntry* next = current->next;
        if (current->peer != NULL) {
            struct Libp2pLinkedList* addr_curr = current->peer->addr_head;
            while (addr_curr != NULL) {
                struct Libp2pLinkedList* addr_next = addr_curr->next;
                free(addr_curr);
                addr_curr = addr_next;
            }
            if (current->peer->peer_id != NULL) {
                free(current->peer->peer_id);
            }
            free(current->peer);
        }
        free(current);
        current = next;
    }
    free(peerstore);
}
