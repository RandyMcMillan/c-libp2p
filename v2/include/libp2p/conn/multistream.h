#ifndef LIBP2P_CONN_MULTISTREAM_H
#define LIBP2P_CONN_MULTISTREAM_H

#include "libp2p/net/tcp.h"

int libp2p_net_multistream_connect(struct Stream* stream);
int libp2p_net_multistream_negotiate_protocol(struct Stream* stream, const char* protocol_id);

#endif /* LIBP2P_CONN_MULTISTREAM_H */
