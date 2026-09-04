#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libp2p/net/multiaddr.h"
#include "libp2p/utils/logger.h"

struct MultiAddress* libp2p_multiaddr_new_from_string(const char* str) {
    if (str == NULL || *str != '/')
        return NULL;

    struct MultiAddress* ma = (struct MultiAddress*)calloc(1, sizeof(struct MultiAddress));
    if (ma == NULL)
        return NULL;

    ma->raw_string = strdup(str);

    char buffer[256];
    strncpy(buffer, str, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';

    char* token = strtok(buffer, "/");
    while (token != NULL) {
        if (strcmp(token, "ip4") == 0) {
            token = strtok(NULL, "/");
            if (token != NULL) {
                ma->ip = strdup(token);
            }
        } else if (strcmp(token, "tcp") == 0) {
            token = strtok(NULL, "/");
            if (token != NULL) {
                ma->port = (uint16_t)atoi(token);
            }
        }
        token = strtok(NULL, "/");
    }

    if (ma->ip == NULL || ma->port == 0) {
        libp2p_logger_error("multiaddr", "Failed to parse multiaddr format\n");
        libp2p_multiaddr_free(ma);
        return NULL;
    }

    return ma;
}

void libp2p_multiaddr_free(struct MultiAddress* ma) {
    if (ma != NULL) {
        if (ma->raw_string != NULL) free(ma->raw_string);
        if (ma->ip != NULL) free(ma->ip);
        free(ma);
    }
}
