#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libp2p/conn/multistream.h"
#include "libp2p/utils/logger.h"

#define MULTISTREAM_MSG_HEADER "/multistream/1.0.0\n"

static int write_length_prefixed_msg(struct Stream* stream, const char* msg) {
    if (stream == NULL || msg == NULL)
        return 0;

    size_t msg_len = strlen(msg);
    unsigned char header[10];
    size_t header_len = 0;

    size_t temp = msg_len;
    do {
        header[header_len] = (unsigned char)(temp & 0x7F);
        temp >>= 7;
        if (temp > 0) {
            header[header_len] |= 0x80;
        }
        header_len++;
    } while (temp > 0);

    if (stream->write(stream, header, header_len) <= 0)
        return 0;

    if (stream->write(stream, (const unsigned char*)msg, msg_len) <= 0)
        return 0;

    return 1;
}

static int read_length_prefixed_msg(struct Stream* stream, char* buffer, size_t max_len) {
    if (stream == NULL || buffer == NULL || max_len == 0)
        return 0;

    size_t msg_len = 0;
    size_t shift = 0;
    unsigned char byte = 0;

    do {
        if (stream->read(stream, &byte, 1) <= 0)
            return 0;
        msg_len |= (size_t)(byte & 0x7F) << shift;
        shift += 7;
    } while (byte & 0x80);

    if (msg_len >= max_len) {
        libp2p_logger_error("multistream", "Protocol string exceeds buffer size\n");
        return 0;
    }

    size_t total_read = 0;
    while (total_read < msg_len) {
        ssize_t ret = stream->read(stream, (unsigned char*)buffer + total_read, msg_len - total_read);
        if (ret <= 0)
            return 0;
        total_read += (size_t)ret;
    }
    buffer[msg_len] = '\0';
    return 1;
}

int libp2p_net_multistream_connect(struct Stream* stream) {
    if (stream == NULL)
        return 0;

    if (!write_length_prefixed_msg(stream, MULTISTREAM_MSG_HEADER)) {
        libp2p_logger_error("multistream", "Failed to send multistream header\n");
        return 0;
    }

    char response[256];
    if (!read_length_prefixed_msg(stream, response, sizeof(response))) {
        libp2p_logger_error("multistream", "Failed to receive multistream ack\n");
        return 0;
    }

    if (strcmp(response, MULTISTREAM_MSG_HEADER) != 0) {
        libp2p_logger_error("multistream", "Peer rejected multistream version\n");
        return 0;
    }

    return 1;
}

int libp2p_net_multistream_negotiate_protocol(struct Stream* stream, const char* protocol_id) {
    if (stream == NULL || protocol_id == NULL)
        return 0;

    char formatted_proto[256];
    snprintf(formatted_proto, sizeof(formatted_proto), "%s\n", protocol_id);

    if (!write_length_prefixed_msg(stream, formatted_proto))
        return 0;

    char response[256];
    if (!read_length_prefixed_msg(stream, response, sizeof(response)))
        return 0;

    return (strcmp(response, formatted_proto) == 0);
}
