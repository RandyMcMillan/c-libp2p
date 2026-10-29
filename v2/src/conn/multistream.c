#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libp2p/conn/multistream.h"
#include "libp2p/utils/logger.h"
#include "libp2p/utils/debug.h"

#define MULTISTREAM_MSG_HEADER "/multistream/1.0.0\n"

static int write_length_prefixed_msg(struct Libp2pV2Stream* stream, const char* msg) {
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

    /* Send the length prefix and the protocol string in one write so the
     * underlying framing transport (e.g. Noise over WebSocket) carries the
     * complete multistream message in a single record. */
    size_t total_len = header_len + msg_len;
    unsigned char *combined = (unsigned char*)malloc(total_len);
    if (combined == NULL)
        return 0;
    memcpy(combined, header, header_len);
    memcpy(combined + header_len, msg, msg_len);

    libp2p_v2_logger_info("multistream", "writing length-prefixed message %zu bytes: %s", total_len, msg);
    ssize_t n = stream->write(stream, combined, total_len);
    free(combined);
    libp2p_v2_logger_info("multistream", "wrote message %zd/%zu bytes\n", n, total_len);
    if (n <= 0 || (size_t)n != total_len)
        return 0;

    return 1;
}

static int read_length_prefixed_msg(struct Libp2pV2Stream* stream, char* buffer, size_t max_len) {
    if (stream == NULL || buffer == NULL || max_len == 0)
        return 0;

    size_t msg_len = 0;
    size_t shift = 0;
    unsigned char byte = 0;

    do {
        ssize_t r = stream->read(stream, &byte, 1);
        libp2p_v2_logger_info("multistream", "read varint byte r=%zd byte=0x%02x\n", r, byte);
        if (r <= 0)
            return 0;
        msg_len |= (size_t)(byte & 0x7F) << shift;
        shift += 7;
    } while (byte & 0x80);

    libp2p_v2_logger_info("multistream", "read_length_prefixed_msg msg_len=%zu\n", msg_len);

    if (msg_len >= max_len) {
        libp2p_v2_logger_error("multistream", "Protocol string exceeds buffer size\n");
        return 0;
    }

    size_t total_read = 0;
    while (total_read < msg_len) {
        ssize_t ret = stream->read(stream, (unsigned char*)buffer + total_read, msg_len - total_read);
        libp2p_v2_logger_info("multistream", "read body ret=%zd total=%zu/%zu\n", ret, total_read, msg_len);
        if (ret <= 0)
            return 0;
        total_read += (size_t)ret;
    }
    buffer[msg_len] = '\0';
    libp2p_v2_logger_info("multistream", "read_length_prefixed_msg complete: %s", buffer);
    return 1;
}

int libp2p_net_multistream_read_protocol(struct Libp2pV2Stream* stream, char* buffer, size_t max_len)
{
    return read_length_prefixed_msg(stream, buffer, max_len);
}

int libp2p_net_multistream_write_protocol(struct Libp2pV2Stream* stream, const char* protocol)
{
    return write_length_prefixed_msg(stream, protocol);
}

int libp2p_v2_net_multistream_connect(struct Libp2pV2Stream* stream) {
    DBG_SCOPE("multistream", "libp2p_v2_net_multistream_connect ENTER stream=%p\n", (void*)stream);
    if (stream == NULL) {
        libp2p_v2_logger_error("multistream", "connect: stream is NULL\n");
        return 0;
    }

    DBG_SCOPE("multistream", "libp2p_v2_net_multistream_connect: about to write header\n");
    if (!write_length_prefixed_msg(stream, MULTISTREAM_MSG_HEADER)) {
        libp2p_v2_logger_error("multistream", "Failed to send multistream header\n");
        return 0;
    }

    DBG_SCOPE("multistream", "libp2p_v2_net_multistream_connect: header written, about to read response\n");

    char response[256];
    if (!read_length_prefixed_msg(stream, response, sizeof(response))) {
        libp2p_v2_logger_error("multistream", "Failed to receive multistream ack\n");
        return 0;
    }

    DBG_SCOPE("multistream", "multistream_connect response read OK, response_len=%zu response[18]=0x%02x response[19]=0x%02x\n",
              strlen(response), (unsigned char)response[18], (unsigned char)response[19]);

    int cmp = strcmp(response, MULTISTREAM_MSG_HEADER);
    DBG_SCOPE("multistream", "multistream_connect strcmp=%d\n", cmp);

    if (cmp != 0) {
        libp2p_v2_logger_error("multistream", "Peer rejected multistream version: got '%s' expected '%s'\n", response, MULTISTREAM_MSG_HEADER);
        return 0;
    }

    libp2p_v2_logger_info("multistream", "connect succeeded, returning 1\n");
    return 1;
}

int libp2p_net_multistream_negotiate_protocol(struct Libp2pV2Stream* stream, const char* protocol_id) {
    DBG_SCOPE("multistream", "negotiate_protocol ENTER stream=%p protocol=%s\n", (void*)stream, protocol_id ? protocol_id : "(null)");
    if (stream == NULL || protocol_id == NULL)
        return 0;

    char formatted_proto[256];
    snprintf(formatted_proto, sizeof(formatted_proto), "%s\n", protocol_id);

    libp2p_v2_logger_info("multistream", "negotiate_protocol: about to propose %s", formatted_proto);
    if (!write_length_prefixed_msg(stream, formatted_proto)) {
        libp2p_v2_logger_error("multistream", "negotiate_protocol: failed to write %s\n", formatted_proto);
        return 0;
    }
    libp2p_v2_logger_info("multistream", "negotiate_protocol: wrote %s, waiting for response\n", formatted_proto);

    char response[256];
    if (!read_length_prefixed_msg(stream, response, sizeof(response))) {
        libp2p_v2_logger_error("multistream", "negotiate_protocol: failed to read response for %s\n", formatted_proto);
        return 0;
    }

    libp2p_v2_logger_info("multistream", "proposed %s got response %s\n", formatted_proto, response);
    return (strcmp(response, formatted_proto) == 0);
}

int libp2p_net_multistream_accept(struct Libp2pV2Stream* stream, const char* expected_protocol) {
    if (stream == NULL)
        return 0;

    char msg[256];

    /* Read and echo multistream header */
    if (!read_length_prefixed_msg(stream, msg, sizeof(msg))) {
        libp2p_v2_logger_error("multistream", "Failed to read multistream header\n");
        return 0;
    }
    if (strcmp(msg, MULTISTREAM_MSG_HEADER) != 0) {
        libp2p_v2_logger_error("multistream", "Unexpected multistream header: %s\n", msg);
        return 0;
    }
    if (!write_length_prefixed_msg(stream, MULTISTREAM_MSG_HEADER)) {
        libp2p_v2_logger_error("multistream", "Failed to echo multistream header\n");
        return 0;
    }

    /* Read protocol proposal */
    if (!read_length_prefixed_msg(stream, msg, sizeof(msg))) {
        libp2p_v2_logger_error("multistream", "Failed to read protocol proposal\n");
        return 0;
    }

    /* Trim trailing newline for comparison */
    size_t len = strlen(msg);
    if (len > 0 && msg[len - 1] == '\n')
        msg[len - 1] = '\0';

    if (expected_protocol != NULL && strcmp(msg, expected_protocol) != 0) {
        libp2p_v2_logger_error("multistream", "Unsupported protocol: %s (expected %s)\n", msg, expected_protocol);
        write_length_prefixed_msg(stream, "na\n");
        return 0;
    }

    /* Confirm protocol */
    char confirm[256];
    snprintf(confirm, sizeof(confirm), "%s\n", msg);
    if (!write_length_prefixed_msg(stream, confirm)) {
        libp2p_v2_logger_error("multistream", "Failed to confirm protocol\n");
        return 0;
    }

    return 1;
}
