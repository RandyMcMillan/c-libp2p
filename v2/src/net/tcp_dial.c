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

static ssize_t tcp_stream_read(struct Stream* stream, unsigned char* buf, size_t count) {
    struct tcp_stream_context* ctx = (struct tcp_stream_context*)stream->stream_context;
    if (ctx == NULL || ctx->fd < 0)
        return -1;
    ssize_t ret = recv(ctx->fd, buf, count, 0);
    return ret;
}

static ssize_t tcp_stream_write(struct Stream* stream, const unsigned char* buf, size_t count) {
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

static void tcp_stream_close(struct Stream* stream) {
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

struct Stream* libp2p_net_tcp_dial(const char* ip_address, uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        libp2p_logger_error("tcp", "socket creation failed: %s\n", strerror(errno));
        return NULL;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip_address, &addr.sin_addr) <= 0) {
        libp2p_logger_error("tcp", "invalid IP address: %s\n", ip_address);
        close(fd);
        return NULL;
    }

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        libp2p_logger_error("tcp", "connect to %s:%u failed: %s\n", ip_address, port, strerror(errno));
        close(fd);
        return NULL;
    }

    struct tcp_stream_context* ctx = (struct tcp_stream_context*)malloc(sizeof(struct tcp_stream_context));
    if (ctx == NULL) {
        close(fd);
        return NULL;
    }
    ctx->fd = fd;

    struct Stream* stream = (struct Stream*)calloc(1, sizeof(struct Stream));
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
