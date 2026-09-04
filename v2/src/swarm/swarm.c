#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libp2p/swarm/swarm.h"
#include "libp2p/conn/multistream.h"
#include "libp2p/conn/noise.h"
#include "libp2p/conn/yamux.h"
#include "libp2p/identify/identify_v2.h"
#include "libp2p/net/multiaddr.h"
#include "libp2p/net/tcp.h"
#include "libp2p/utils/logger.h"

struct Swarm* libp2p_swarm_new(struct Peerstore* peerstore, void* private_key) {
    if (peerstore == NULL)
        return NULL;

    struct Swarm* swarm = (struct Swarm*)calloc(1, sizeof(struct Swarm));
    if (swarm != NULL) {
        swarm->peerstore = peerstore;
        swarm->private_key = private_key;

        swarm->dialer = (struct Dialer*)calloc(1, sizeof(struct Dialer));
        if (swarm->dialer != NULL) {
            swarm->dialer->peerstore = peerstore;
            swarm->dialer->private_key = private_key;
        }
    }
    return swarm;
}

int libp2p_swarm_connect(struct Swarm* swarm, const char* multiaddr_str) {
    if (swarm == NULL || multiaddr_str == NULL)
        return 0;

    struct MultiAddress* ma = libp2p_multiaddr_new_from_string(multiaddr_str);
    if (ma == NULL) {
        libp2p_logger_error("swarm", "Invalid multiaddr string passed to swarm_connect\n");
        return 0;
    }

    struct Libp2pV2Stream* tcp_stream = libp2p_net_tcp_dial(ma->ip, ma->port);
    if (tcp_stream == NULL) {
        libp2p_logger_error("swarm", "Failed to establish TCP connection via swarm\n");
        libp2p_multiaddr_free(ma);
        return 0;
    }

    libp2p_logger_info("swarm", "Successfully established physical transport connection\n");

    if (!libp2p_net_multistream_connect(tcp_stream)) {
        tcp_stream->close(tcp_stream);
        libp2p_multiaddr_free(ma);
        return 0;
    }

    struct Libp2pPeer target_peer;
    memset(&target_peer, 0, sizeof(struct Libp2pPeer));

    struct Libp2pV2Stream* noise_stream = libp2p_noise_handshake(tcp_stream, swarm->private_key, &target_peer, NULL);
    if (noise_stream == NULL) {
        tcp_stream->close(tcp_stream);
        libp2p_multiaddr_free(ma);
        return 0;
    }

    struct YamuxSession* session = libp2p_yamux_session_new(noise_stream, 0);
    if (session == NULL) {
        noise_stream->close(noise_stream);
        libp2p_multiaddr_free(ma);
        return 0;
    }

    struct Libp2pV2Stream* id_stream = libp2p_yamux_stream_open(session);
    if (id_stream != NULL) {
        if (libp2p_identify_send_response(id_stream, swarm->peerstore)) {
            libp2p_identify_receive(id_stream, &target_peer);
        }
        id_stream->close(id_stream);
    }

    libp2p_multiaddr_free(ma);
    return 1;
}

void libp2p_swarm_free(struct Swarm* swarm) {
    if (swarm != NULL) {
        if (swarm->dialer != NULL) {
            free(swarm->dialer);
        }
        free(swarm);
    }
}
