#ifndef LIBP2P_SWARM_SWARM_H
#define LIBP2P_SWARM_SWARM_H

#include "libp2p/peer/peerstore.h"

struct Dialer {
    struct Peerstore* peerstore;
    void* private_key;
};

struct Swarm {
    struct Peerstore* peerstore;
    void* private_key;
    struct Dialer* dialer;
};

struct Swarm* libp2p_swarm_new(struct Peerstore* peerstore, void* private_key);
int libp2p_swarm_connect(struct Swarm* swarm, const char* multiaddr_str);
void libp2p_swarm_free(struct Swarm* swarm);

#endif /* LIBP2P_SWARM_SWARM_H */
