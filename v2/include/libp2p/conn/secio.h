#ifndef LIBP2P_CONN_SECIO_H
#define LIBP2P_CONN_SECIO_H

#include "libp2p/net/tcp.h"

struct Libp2pPeer;

struct Libp2pV2Stream* libp2p_secio_handshake(struct Libp2pV2Stream* raw_stream, void* private_key, struct Libp2pPeer* peer);

#endif /* LIBP2P_CONN_SECIO_H */
