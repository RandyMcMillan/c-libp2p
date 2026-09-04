#ifndef LIBP2P_NET_MULTIADDR_H
#define LIBP2P_NET_MULTIADDR_H

#include <stdint.h>

struct MultiAddress {
    char* raw_string;
    char* ip;
    uint16_t port;
};

struct MultiAddress* libp2p_multiaddr_new_from_string(const char* str);
void libp2p_multiaddr_free(struct MultiAddress* ma);

#endif /* LIBP2P_NET_MULTIADDR_H */
