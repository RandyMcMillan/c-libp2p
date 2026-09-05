#ifndef LIBP2P_IDENTIFY_V2_IPFS_H
#define LIBP2P_IDENTIFY_V2_IPFS_H

#include <stddef.h>

struct Libp2pV2Stream;

/**
 * Send an Identify response over a v2 stream using raw identity data.
 * This helper avoids header collisions between v1 and v2 Peerstore structs.
 *
 * @param stream            The Yamux sub-stream to send on.
 * @param peer_id           Local peer ID string (may be NULL).
 * @param public_key_der    Raw RSA public key DER bytes (may be NULL).
 * @param public_key_len    Length of public_key_der.
 * @param listen_addrs      Array of listen multiaddr strings (may be NULL).
 * @param listen_addrs_count Number of entries in listen_addrs.
 * @return 1 on success, 0 on failure.
 */
int libp2p_identify_send_response_ipfs(struct Libp2pV2Stream* stream,
                                        const char* peer_id,
                                        const unsigned char* public_key_der,
                                        size_t public_key_len,
                                        char** listen_addrs,
                                        size_t listen_addrs_count);

#endif
