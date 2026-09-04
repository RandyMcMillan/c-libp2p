#ifndef LIBP2P_V2_NOISE_H
#define LIBP2P_V2_NOISE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Stub Noise types for v2 bridge compatibility */
typedef struct libp2p_noise_session libp2p_noise_session_t;

int libp2p_noise_handshake_raw(int fd, libp2p_noise_session_t **out_session);
void libp2p_noise_session_free(libp2p_noise_session_t *session);

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_V2_NOISE_H */
