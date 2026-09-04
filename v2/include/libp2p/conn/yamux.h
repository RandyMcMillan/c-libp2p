#ifndef LIBP2P_CONN_YAMUX_H
#define LIBP2P_CONN_YAMUX_H

#include "libp2p/net/tcp.h"

struct YamuxSession;

struct YamuxSession* libp2p_yamux_session_new(struct Stream* stream, int is_server);
struct Stream* libp2p_yamux_stream_open(struct YamuxSession* session);
void libp2p_yamux_session_free(struct YamuxSession* session);

#endif /* LIBP2P_CONN_YAMUX_H */
