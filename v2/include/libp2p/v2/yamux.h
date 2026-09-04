#ifndef LIBP2P_V2_YAMUX_H
#define LIBP2P_V2_YAMUX_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Stub Yamux types for v2 bridge compatibility */
typedef struct libp2p_yamux_stream libp2p_yamux_stream_t;
typedef struct libp2p_yamux_session libp2p_yamux_session_t;

#define YAMUX_MODE_CLIENT 0
#define YAMUX_MODE_SERVER 1

libp2p_yamux_session_t *libp2p_yamux_session_new(int fd, int mode);
libp2p_yamux_stream_t *libp2p_yamux_stream_open(libp2p_yamux_session_t *session);
int libp2p_yamux_stream_write(libp2p_yamux_stream_t *stream, const uint8_t *buf, size_t len);
int libp2p_yamux_stream_read(libp2p_yamux_stream_t *stream, uint8_t *buf, size_t len);
void libp2p_yamux_stream_close(libp2p_yamux_stream_t *stream);
void libp2p_yamux_session_free(libp2p_yamux_session_t *session);

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_V2_YAMUX_H */
