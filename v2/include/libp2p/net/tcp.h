#ifndef LIBP2P_NET_TCP_H
#define LIBP2P_NET_TCP_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

struct Stream {
    void* stream_context;
    ssize_t (*read)(struct Stream* stream, unsigned char* buf, size_t count);
    ssize_t (*write)(struct Stream* stream, const unsigned char* buf, size_t count);
    void (*close)(struct Stream* stream);
};

struct Stream* libp2p_net_tcp_dial(const char* ip_address, uint16_t port);

#endif /* LIBP2P_NET_TCP_H */
