#ifndef LIBP2P_CONN_MULTISTREAM_H
#define LIBP2P_CONN_MULTISTREAM_H

#include "libp2p/net/tcp.h"

int libp2p_v2_net_multistream_connect(struct Libp2pV2Stream* stream);
int libp2p_net_multistream_negotiate_protocol(struct Libp2pV2Stream* stream, const char* protocol_id);
int libp2p_net_multistream_accept(struct Libp2pV2Stream* stream, const char* expected_protocol);

/**
 * Read a length-prefixed protocol string from a stream.
 * The trailing newline (if present) is preserved in the output.
 */
int libp2p_net_multistream_read_protocol(struct Libp2pV2Stream* stream, char* buffer, size_t max_len);

/**
 * Write a length-prefixed protocol string to a stream.
 */
int libp2p_net_multistream_write_protocol(struct Libp2pV2Stream* stream, const char* protocol);

#endif /* LIBP2P_CONN_MULTISTREAM_H */
