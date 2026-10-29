#ifndef LIBP2P_UTILS_DEBUG_H
#define LIBP2P_UTILS_DEBUG_H

/* Debug print gating.
 *
 * Do not remove debug prints during development.  They are gated by scope so
 * they are silent by default and can be enabled when needed:
 *
 *   DEBUG=1                    enable all debug prints
 *   DEBUG=all                  enable all debug prints
 *   DEBUG_<SCOPE>=true         enable only prints for <SCOPE>
 *
 * Example:
 *   DEBUG_V2_BRIDGE=true ./test/test_v2_kubo ...
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static inline int libp2p_v2_debug_scope_enabled(const char *scope)
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

#define DBG_SCOPE(scope, fmt, ...) do { \
    if (libp2p_v2_debug_scope_enabled(scope)) { \
        fprintf(stderr, "[" scope "] " fmt, ##__VA_ARGS__); \
        fflush(stderr); \
    } \
} while (0)

/* Legacy-style universal debug print. Kept for callers that pre-date the
 * per-scope macros. Enabled when DEBUG=1 / DEBUG=all. Prefer DBG_SCOPE. */
#define DEBUG_PRINTF(fmt, ...) do { \
    const char *_debug = getenv("DEBUG"); \
    if (_debug && (strcmp(_debug, "1") == 0 || strcmp(_debug, "true") == 0 || strcmp(_debug, "all") == 0)) { \
        fprintf(stderr, fmt, ##__VA_ARGS__); \
        fflush(stderr); \
    } \
} while (0)

#endif /* LIBP2P_UTILS_DEBUG_H */
