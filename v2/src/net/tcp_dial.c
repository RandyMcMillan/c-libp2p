#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "libp2p/net/tcp.h"
#include "libp2p/utils/logger.h"

struct tcp_stream_context {
    int fd;
};

static ssize_t tcp_stream_read(struct Libp2pV2Stream* stream, unsigned char* buf, size_t count) {
    struct tcp_stream_context* ctx = (struct tcp_stream_context*)stream->stream_context;
    if (ctx == NULL || ctx->fd < 0)
        return -1;
    ssize_t ret = recv(ctx->fd, buf, count, 0);
    return ret;
}

static ssize_t tcp_stream_write(struct Libp2pV2Stream* stream, const unsigned char* buf, size_t count) {
    struct tcp_stream_context* ctx = (struct tcp_stream_context*)stream->stream_context;
    if (ctx == NULL || ctx->fd < 0)
        return -1;
    ssize_t total = 0;
    while ((size_t)total < count) {
        ssize_t ret = send(ctx->fd, buf + total, count - total, 0);
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        total += ret;
    }
    return total;
}

static void tcp_stream_close(struct Libp2pV2Stream* stream) {
    if (stream == NULL)
        return;
    struct tcp_stream_context* ctx = (struct tcp_stream_context*)stream->stream_context;
    if (ctx != NULL) {
        if (ctx->fd >= 0) {
            close(ctx->fd);
        }
        free(ctx);
        stream->stream_context = NULL;
    }
    free(stream);
}

struct Libp2pV2Stream* libp2p_net_tcp_wrap_fd(int fd) {
    if (fd < 0)
        return NULL;

    struct tcp_stream_context* ctx = (struct tcp_stream_context*)malloc(sizeof(struct tcp_stream_context));
    if (ctx == NULL)
        return NULL;
    ctx->fd = fd;

    struct Libp2pV2Stream* stream = (struct Libp2pV2Stream*)calloc(1, sizeof(struct Libp2pV2Stream));
    if (stream == NULL) {
        free(ctx);
        return NULL;
    }

    stream->stream_context = ctx;
    stream->read = tcp_stream_read;
    stream->write = tcp_stream_write;
    stream->close = tcp_stream_close;
    return stream;
}

struct Libp2pV2Stream* libp2p_net_tcp_dial(const char* ip_address, uint16_t port) {
    if (ip_address == NULL)
        return NULL;

    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%u", port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICHOST;

    struct addrinfo* res = NULL;
    int gai_err = getaddrinfo(ip_address, port_str, &hints, &res);
    if (gai_err != 0 || res == NULL) {
        libp2p_v2_logger_error("tcp", "getaddrinfo for %s:%s failed: %s\n", ip_address, port_str, gai_strerror(gai_err));
        return NULL;
    }

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) {
        libp2p_v2_logger_error("tcp", "socket creation failed: %s\n", strerror(errno));
        freeaddrinfo(res);
        return NULL;
    }

    if (connect(fd, res->ai_addr, res->ai_addrlen) < 0) {
        libp2p_v2_logger_error("tcp", "connect to %s:%u failed: %s\n", ip_address, port, strerror(errno));
        close(fd);
        freeaddrinfo(res);
        return NULL;
    }
    freeaddrinfo(res);

    struct tcp_stream_context* ctx = (struct tcp_stream_context*)malloc(sizeof(struct tcp_stream_context));
    if (ctx == NULL) {
        close(fd);
        return NULL;
    }
    ctx->fd = fd;

    struct Libp2pV2Stream* stream = (struct Libp2pV2Stream*)calloc(1, sizeof(struct Libp2pV2Stream));
    if (stream == NULL) {
        free(ctx);
        close(fd);
        return NULL;
    }

    stream->stream_context = ctx;
    stream->read = tcp_stream_read;
    stream->write = tcp_stream_write;
    stream->close = tcp_stream_close;

    return stream;
}
