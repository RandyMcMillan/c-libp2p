#ifndef LIBP2P_CONN_SECIO_H
#define LIBP2P_CONN_SECIO_H

#include "libp2p/net/tcp.h"

struct Libp2pPeer;

struct Stream* libp2p_secio_handshake(struct Stream* raw_stream, void* private_key, struct Libp2pPeer* peer);

#endif /* LIBP2P_CONN_SECIO_H */
