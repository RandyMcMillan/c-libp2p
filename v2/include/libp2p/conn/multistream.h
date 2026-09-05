#ifndef LIBP2P_CONN_MULTISTREAM_H
#define LIBP2P_CONN_MULTISTREAM_H

#include "libp2p/net/tcp.h"

int libp2p_v2_net_multistream_connect(struct Libp2pV2Stream* stream);
int libp2p_net_multistream_negotiate_protocol(struct Libp2pV2Stream* stream, const char* protocol_id);
int libp2p_net_multistream_accept(struct Libp2pV2Stream* stream, const char* expected_protocol);

#endif /* LIBP2P_CONN_MULTISTREAM_H */
