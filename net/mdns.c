#include "libp2p/net/mdns.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/select.h>

static int mdns_build_packet(const mdns_service_t *service, char *buffer, size_t max_len) {
    if (service == NULL || buffer == NULL || max_len == 0) {
        return 0;
    }
    return snprintf(buffer, max_len, "ipfs-mdns\n%s\n%s\n", service->peer_id, service->multiaddr);
}

static void mdns_handle_packet(mdns_service_t *service, const char *packet, ssize_t len) {
    if (service == NULL || packet == NULL || len <= 0) {
        return;
    }
    const char *prefix = "ipfs-mdns\n";
    size_t prefix_len = strlen(prefix);
    if ((size_t)len <= prefix_len || strncmp(packet, prefix, prefix_len) != 0) {
        return;
    }

    const char *peer = packet + prefix_len;
    const char *addr = strchr(peer, '\n');
    if (addr == NULL) {
        return;
    }
    size_t peer_len = (size_t)(addr - peer);
    if (peer_len == 0 || peer_len >= sizeof(service->peer_id)) {
        return;
    }

    char peer_id[128];
    memcpy(peer_id, peer, peer_len);
    peer_id[peer_len] = '\0';
    if (strcmp(peer_id, service->peer_id) == 0) {
        return;
    }

    const char *multiaddr = addr + 1;
    const char *end = strchr(multiaddr, '\n');
    size_t addr_len = end != NULL ? (size_t)(end - multiaddr) : strnlen(multiaddr, sizeof(service->multiaddr) - 1);
    if (addr_len == 0) {
        return;
    }

    char addr_buf[256];
    if (addr_len >= sizeof(addr_buf)) {
        addr_len = sizeof(addr_buf) - 1;
    }
    memcpy(addr_buf, multiaddr, addr_len);
    addr_buf[addr_len] = '\0';

    if (service->cb != NULL) {
        service->cb(peer_id, addr_buf, service->user_data);
    }
}

mdns_service_t *mdns_service_new(const char *peer_id, const char *multiaddr, mdns_peer_found_cb cb, void *user_data) {
    if (!peer_id || !multiaddr || !cb) return NULL;

    mdns_service_t *service = calloc(1, sizeof(mdns_service_t));
    if (!service) return NULL;

    snprintf(service->peer_id, sizeof(service->peer_id), "%s", peer_id);
    snprintf(service->multiaddr, sizeof(service->multiaddr), "%s", multiaddr);
    service->cb = cb;
    service->user_data = user_data;
    service->sockfd = -1;
    service->port = MDNS_PORT;
    service->running = false;

    return service;
}

int mdns_service_start(mdns_service_t *service) {
    if (!service) return -1;

    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) {
        perror("mdns socket creation failed");
        return -1;
    }

    int reuse = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        perror("setsockopt SO_REUSEADDR failed");
        close(fd);
        return -1;
    }

#if defined(SO_REUSEPORT)
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));
#endif

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(service->port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("mdns bind failed");
        close(fd);
        return -1;
    }

    struct ip_mreq mreq;
    memset(&mreq, 0, sizeof(mreq));
    mreq.imr_multiaddr.s_addr = inet_addr(MDNS_MULTICAST_IPV4);
    mreq.imr_interface.s_addr = INADDR_ANY;

    if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        perror("setsockopt IP_ADD_MEMBERSHIP failed");
        close(fd);
        return -1;
    }

    int loop = 1;
    setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop));

    service->sockfd = fd;
    service->running = true;
    return 0;
}

int mdns_service_send_announcement(mdns_service_t *service) {
    if (!service || service->sockfd < 0 || !service->running) {
        return -1;
    }

    char packet[MDNS_MAX_PACKET_SIZE];
    int packet_len = mdns_build_packet(service, packet, sizeof(packet));
    if (packet_len <= 0) {
        return -1;
    }

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(MDNS_PORT);
    dest.sin_addr.s_addr = inet_addr(MDNS_MULTICAST_IPV4);

    ssize_t sent = sendto(service->sockfd, packet, (size_t)packet_len, 0, (struct sockaddr*)&dest, sizeof(dest));
    return sent == packet_len ? 0 : -1;
}

int mdns_service_poll(mdns_service_t *service) {
    if (!service || service->sockfd < 0 || !service->running) {
        return -1;
    }

    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(service->sockfd, &readfds);
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 0;

    int ret = select(service->sockfd + 1, &readfds, NULL, NULL, &tv);
    if (ret <= 0 || !FD_ISSET(service->sockfd, &readfds)) {
        return 0;
    }

    char buffer[MDNS_MAX_PACKET_SIZE];
    struct sockaddr_in src;
    socklen_t src_len = sizeof(src);
    ssize_t received = recvfrom(service->sockfd, buffer, sizeof(buffer) - 1, 0, (struct sockaddr*)&src, &src_len);
    if (received <= 0) {
        return 0;
    }
    buffer[received] = '\0';
    mdns_handle_packet(service, buffer, received);
    return 1;
}

void mdns_service_stop(mdns_service_t *service) {
    if (!service) return;
    service->running = false;
    if (service->sockfd >= 0) {
        close(service->sockfd);
        service->sockfd = -1;
    }
}

void mdns_service_free(mdns_service_t *service) {
    if (!service) return;
    mdns_service_stop(service);
    free(service);
}
