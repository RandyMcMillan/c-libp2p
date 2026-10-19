#ifndef LIBP2P_UTILS_DEBUG_H
#define LIBP2P_UTILS_DEBUG_H

/*
 * Debug output helpers.
 *
 * These macros are intentionally left in place for protocol debugging.
 * Future agents should preserve debug prints and keep them gated by the
 * DEBUG environment variable rather than removing them.
 */

#include <stdlib.h>
#include <stdio.h>

static inline int libp2p_debug_enabled(void) {
    const char* env = getenv("DEBUG");
    return env && env[0] != '\0';
}

#define DEBUG_PRINTF(...) do { \
    if (libp2p_debug_enabled()) fprintf(stderr, __VA_ARGS__); \
} while(0)

#endif /* LIBP2P_UTILS_DEBUG_H */
