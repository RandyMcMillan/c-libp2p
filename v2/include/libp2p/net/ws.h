#ifndef LIBP2P_NET_WS_H
#define LIBP2P_NET_WS_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "libp2p/net/tcp.h"

struct Libp2pV2Stream* libp2p_net_ws_dial(const char* ip_address, uint16_t port);

#endif /* LIBP2P_NET_WS_H */
