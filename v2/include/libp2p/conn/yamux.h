#ifndef LIBP2P_CONN_YAMUX_H
#define LIBP2P_CONN_YAMUX_H

#include "libp2p/net/tcp.h"

struct YamuxSession;

struct YamuxSession* libp2p_yamux_session_new(struct Libp2pV2Stream* stream, int is_server);
struct Libp2pV2Stream* libp2p_yamux_stream_open(struct YamuxSession* session);
struct Libp2pV2Stream* libp2p_yamux_stream_accept(struct YamuxSession* session);
void libp2p_yamux_session_free(struct YamuxSession* session);

/**
 * Send a Yamux ping and wait for the corresponding pong.
 * @return 1 on success, 0 on failure.
 */
int libp2p_yamux_session_ping(struct YamuxSession* session);

/**
 * Send a Yamux GO_AWAY frame and close the session.
 */
void libp2p_yamux_session_goaway(struct YamuxSession* session, uint32_t code);

#endif /* LIBP2P_CONN_YAMUX_H */
