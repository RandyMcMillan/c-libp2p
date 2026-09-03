#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "varint.h"
#include "libp2p/mplex/mplex.h"
#include "libp2p/net/connectionstream.h"
#include "libp2p/utils/logger.h"

int libp2p_mplex_can_handle(const struct StreamMessage* msg) {
	if (msg == NULL || msg->data == NULL || msg->data_size == 0)
		return 0;
	const char *protocol = MPLEX_PROTOCOL_ID;
	int protocol_size = strlen(protocol);
	size_t num_bytes = 0;
	if (msg->data[0] != '/' && msg->data[1] != 'm') {
		varint_decode(msg->data, msg->data_size, &num_bytes);
	}
	if (msg->data_size >= protocol_size - num_bytes) {
		if (strncmp(protocol, (char*)&msg->data[num_bytes], protocol_size) == 0)
			return 1;
	}
	return 0;
}

int libp2p_mplex_send_protocol(struct Stream* stream) {
	const char* protocol = MPLEX_PROTOCOL_ID;
	struct StreamMessage outgoing;
	outgoing.data = (uint8_t*)protocol;
	outgoing.data_size = strlen(protocol);
	return stream != NULL && stream->write != NULL && stream->write(stream->stream_context, &outgoing);
}

int libp2p_mplex_receive_protocol(struct Stream* stream) {
	struct StreamMessage* results = NULL;
	if (stream == NULL || stream->read == NULL)
		return 0;
	if (!stream->read(stream->stream_context, &results, 30) || results == NULL) {
		return 0;
	}
	int retVal = libp2p_mplex_can_handle(results);
	libp2p_stream_message_free(results);
	return retVal;
}

static ssize_t libp2p_mplex_read_passthrough(libp2p_stream_t *stream, uint8_t *buf, size_t len) {
	struct Stream *parent = (struct Stream*)stream->user_data;
	if (parent == NULL || parent->read_raw == NULL) {
		return -1;
	}
	return parent->read_raw(parent->stream_context, buf, (int)len, 30);
}

static ssize_t libp2p_mplex_write_passthrough(libp2p_stream_t *stream, const uint8_t *buf, size_t len) {
	struct Stream *parent = (struct Stream*)stream->user_data;
	if (parent == NULL || parent->write == NULL) {
		return -1;
	}
	struct StreamMessage msg;
	msg.data = (uint8_t*)buf;
	msg.data_size = len;
	return parent->write(parent->stream_context, &msg) ? (ssize_t)len : -1;
}

static void libp2p_mplex_stream_close(libp2p_stream_t *stream) {
	struct Stream *parent = (struct Stream*)stream->user_data;
	free(stream);
	(void)parent;
}

int libp2p_mplex_handle_message(const struct StreamMessage* msg, struct Stream* stream, void* protocol_context) {
	(void)msg;
	struct MplexContext* ctx = (struct MplexContext*)protocol_context;
	if (stream == NULL || ctx == NULL) {
		return -1;
	}
	ctx->status = mplex_status_ack;
	return 1;
}

int libp2p_mplex_shutdown(void* protocol_context) {
	if (protocol_context != NULL) {
		free(protocol_context);
	}
	return 1;
}

struct Stream* libp2p_mplex_stream_new(struct Stream* parent_stream, int theyRequested) {
	if (parent_stream == NULL) {
		return NULL;
	}
	struct Stream* out = libp2p_stream_new();
	if (out != NULL) {
		out->stream_type = STREAM_TYPE_MPLEX;
		out->parent_stream = parent_stream;
		out->close = NULL;
		out->read = NULL;
		out->read_raw = NULL;
		out->write = NULL;
		out->peek = NULL;
		out->handle_upgrade = parent_stream->handle_upgrade;
		out->address = parent_stream->address;
		out->socket_mutex = parent_stream->socket_mutex;
		out->channel = parent_stream->channel;

		struct MplexContext* ctx = (struct MplexContext*)malloc(sizeof(struct MplexContext));
		if (ctx == NULL) {
			libp2p_stream_free(out);
			return NULL;
		}
		ctx->stream = out;
		ctx->protocol_handlers = NULL;
		ctx->status = mplex_status_initialized;
		out->stream_context = ctx;

		libp2p_stream_t *compat = (libp2p_stream_t*)calloc(1, sizeof(libp2p_stream_t));
		if (compat == NULL) {
			free(ctx);
			libp2p_stream_free(out);
			return NULL;
		}
		compat->read = libp2p_mplex_read_passthrough;
		compat->write = libp2p_mplex_write_passthrough;
		compat->close = libp2p_mplex_stream_close;
		compat->user_data = parent_stream;
		out->stream_context = ctx;
		out->close = (int (*)(struct Stream*))libp2p_mplex_stream_free;
		out->read = parent_stream->read;
		out->read_raw = parent_stream->read_raw;
		out->write = parent_stream->write;
		parent_stream->handle_upgrade(parent_stream, out);
		if (!theyRequested) {
			ctx->status = mplex_status_syn;
		} else {
			ctx->status = mplex_status_ack;
		}
	}
	return out;
}

void libp2p_mplex_stream_free(struct Stream* stream) {
	if (stream != NULL) {
		struct MplexContext* ctx = (struct MplexContext*)stream->stream_context;
		if (ctx != NULL) {
			free(ctx);
		}
		free(stream);
	}
}

int libp2p_mplex_ready(struct SessionContext* session_context, int timeout_secs) {
	int counter = 0;
	if (session_context == NULL || session_context->default_stream == NULL)
		return 0;
	while (session_context->default_stream->stream_type != STREAM_TYPE_MPLEX && counter <= timeout_secs) {
		counter++;
		sleep(1);
	}
	return session_context->default_stream->stream_type == STREAM_TYPE_MPLEX;
}

struct Libp2pProtocolHandler* libp2p_mplex_build_protocol_handler(struct Libp2pVector* handlers) {
	struct Libp2pProtocolHandler* handler = libp2p_protocol_handler_new();
	if (handler != NULL) {
		struct MplexContext* ctx = (struct MplexContext*)malloc(sizeof(struct MplexContext));
		if (ctx == NULL) {
			libp2p_protocol_handler_free(handler);
			return NULL;
		}
		ctx->protocol_handlers = handlers;
		ctx->stream = NULL;
		ctx->status = mplex_status_initialized;
		handler->context = ctx;
		handler->CanHandle = libp2p_mplex_can_handle;
		handler->HandleMessage = libp2p_mplex_handle_message;
		handler->Shutdown = libp2p_mplex_shutdown;
	}
	return handler;
}
