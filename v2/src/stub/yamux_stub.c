#include <stdlib.h>
#include "libp2p/v2/yamux.h"

libp2p_yamux_session_t *libp2p_yamux_session_new(int fd, int mode) {
    (void)fd;
    (void)mode;
    return NULL;
}

libp2p_yamux_stream_t *libp2p_yamux_stream_open(libp2p_yamux_session_t *session) {
    (void)session;
    return NULL;
}

int libp2p_yamux_stream_write(libp2p_yamux_stream_t *stream, const uint8_t *buf, size_t len) {
    (void)stream;
    (void)buf;
    (void)len;
    return -1;
}

int libp2p_yamux_stream_read(libp2p_yamux_stream_t *stream, uint8_t *buf, size_t len) {
    (void)stream;
    (void)buf;
    (void)len;
    return -1;
}

void libp2p_yamux_stream_close(libp2p_yamux_stream_t *stream) {
    (void)stream;
}

void libp2p_yamux_session_free(libp2p_yamux_session_t *session) {
    (void)session;
}
