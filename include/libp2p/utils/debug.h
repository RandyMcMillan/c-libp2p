#ifndef LIBP2P_UTILS_DEBUG_H
#define LIBP2P_UTILS_DEBUG_H

/*
 * Debug output helpers.
 *
 * These macros are intentionally left in place for protocol debugging.
 * Future agents should preserve debug prints and keep them gated by the
 * DEBUG / DEBUG_<SCOPE> environment variables rather than removing them.
 *
 *   DEBUG=1                    enable all debug prints
 *   DEBUG=all                  enable all debug prints
 *   DEBUG_<SCOPE>=true         enable only prints for <SCOPE>
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static inline int libp2p_debug_enabled(void) {
    const char* env = getenv("DEBUG");
    return env && env[0] != '\0';
}

static inline int libp2p_debug_scope_enabled(const char *scope)
{
    char env_name[64];
    if (snprintf(env_name, sizeof(env_name), "DEBUG_%s", scope) >= (int)sizeof(env_name))
        return 0;
    const char *val = getenv(env_name);
    if (val && (strcmp(val, "true") == 0 || strcmp(val, "1") == 0 || strcmp(val, "yes") == 0))
        return 1;
    const char *debug = getenv("DEBUG");
    if (debug && (strcmp(debug, "1") == 0 || strcmp(debug, "true") == 0 || strcmp(debug, "all") == 0))
        return 1;
    return 0;
}

#define DEBUG_PRINTF(...) do { \
    if (libp2p_debug_enabled()) fprintf(stderr, __VA_ARGS__); \
} while(0)

#define DBG_SCOPE(scope, fmt, ...) do { \
    if (libp2p_debug_scope_enabled(scope)) { \
        fprintf(stderr, "[" scope "] " fmt, ##__VA_ARGS__); \
        fflush(stderr); \
    } \
} while (0)

#endif /* LIBP2P_UTILS_DEBUG_H */
