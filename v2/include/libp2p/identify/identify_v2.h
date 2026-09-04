#ifndef LIBP2P_IDENTIFY_V2_H
#define LIBP2P_IDENTIFY_V2_H

#include "libp2p/net/tcp.h"
#include "libp2p/peer/peerstore.h"

#define IDENTIFY_PROTOCOL_VERSION "ipfs/0.1.0"
#define IDENTIFY_AGENT_VERSION    "c-ipfs/0.1.0"

typedef struct {
    char *public_key;
    size_t public_key_len;
    char **listen_addrs;
    size_t listen_addrs_count;
    char **protocols;
    size_t protocols_count;
    char *observed_addr;
    size_t observed_addr_len;
    char *protocol_version;
    char *agent_version;
} IdentifyInfo;

IdentifyInfo* libp2p_identify_info_new(void);
void libp2p_identify_info_free(IdentifyInfo* info);

/**
 * Send an Identify message over a v2 Stream.
 * @param stream The Yamux sub-stream to send on.
 * @param peerstore The local peerstore (for public key, listen addrs, etc.)
 * @return 1 on success, 0 on failure.
 */
int libp2p_identify_send_response(struct Libp2pV2Stream* stream, struct Peerstore* peerstore);

/**
 * Receive and parse an Identify message from a v2 Stream.
 * @param stream The Yamux sub-stream to read from.
 * @param peer The peer struct to populate with remote identify info.
 * @return 1 on success, 0 on failure.
 */
int libp2p_identify_receive(struct Libp2pV2Stream* stream, struct Libp2pPeer* peer);

#endif /* LIBP2P_IDENTIFY_V2_H */
