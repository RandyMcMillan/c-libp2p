#ifndef LIBP2P_NET_MDNS_H
#define LIBP2P_NET_MDNS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define MDNS_MULTICAST_IPV4 "224.0.0.251"
#define MDNS_PORT 5353
#define MDNS_MAX_PACKET_SIZE 8966

typedef void (*mdns_peer_found_cb)(const char *peer_id, const char *multiaddr, void *user_data);

typedef struct {
    int sockfd;
    uint16_t port;
    char peer_id[128];
    char multiaddr[256];
    mdns_peer_found_cb cb;
    void *user_data;
    bool running;
} mdns_service_t;

mdns_service_t *mdns_service_new(const char *peer_id, const char *multiaddr, mdns_peer_found_cb cb, void *user_data);
int mdns_service_start(mdns_service_t *service);
int mdns_service_send_announcement(mdns_service_t *service);
int mdns_service_poll(mdns_service_t *service);
void mdns_service_stop(mdns_service_t *service);
void mdns_service_free(mdns_service_t *service);

#endif /* LIBP2P_NET_MDNS_H */
