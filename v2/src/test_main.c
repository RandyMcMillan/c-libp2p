#include <stdio.h>
#include <stdlib.h>

#include "libp2p/peer/peerstore.h"
#include "libp2p/swarm/swarm.h"
#include "libp2p/utils/logger.h"

int main(int argc, char** argv) {
    const char* target_multiaddr = "/ip4/127.0.0.1/tcp/4001";
    if (argc > 1) {
        target_multiaddr = argv[1];
    }

    printf("=== c-libp2p v2 Node Initializing ===\n");

    const char* local_peer_id = "12D3K3w9B8xL2P5s7V3M9K8J2L1N4Q7R";
    struct Peerstore* peerstore = libp2p_peerstore_new(local_peer_id);
    if (peerstore == NULL) {
        fprintf(stderr, "Failed to initialize peerstore\n");
        return EXIT_FAILURE;
    }

    void* dummy_private_key = NULL;
    struct Swarm* swarm = libp2p_swarm_new(peerstore, dummy_private_key);
    if (swarm == NULL) {
        fprintf(stderr, "Failed to initialize swarm\n");
        libp2p_peerstore_free(peerstore);
        return EXIT_FAILURE;
    }

    printf("Dialing target peer at %s ...\n", target_multiaddr);

    if (libp2p_swarm_connect(swarm, target_multiaddr)) {
        printf("Connection, handshake, and protocol negotiation completed successfully.\n");
    } else {
        fprintf(stderr, "Swarm dial failed for target multiaddress.\n");
    }

    libp2p_swarm_free(swarm);
    libp2p_peerstore_free(peerstore);

    printf("=== c-libp2p v2 Node Shutdown ===\n");
    return EXIT_SUCCESS;
}
