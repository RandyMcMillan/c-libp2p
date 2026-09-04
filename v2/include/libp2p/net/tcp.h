#ifndef LIBP2P_NET_TCP_H
#define LIBP2P_NET_TCP_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

struct Libp2pV2Stream {
    void* stream_context;
    ssize_t (*read)(struct Libp2pV2Stream* stream, unsigned char* buf, size_t count);
    ssize_t (*write)(struct Libp2pV2Stream* stream, const unsigned char* buf, size_t count);
    void (*close)(struct Libp2pV2Stream* stream);
};

struct Libp2pV2Stream* libp2p_net_tcp_dial(const char* ip_address, uint16_t port);

#endif /* LIBP2P_NET_TCP_H */
