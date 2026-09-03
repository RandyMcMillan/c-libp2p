#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "varint.h"
#include "libp2p/mplex/mplex.h"
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

static int libp2p_mplex_close(struct Stream* stream);
static int libp2p_mplex_peek(void* stream_context);
static int libp2p_mplex_read(void* stream_context, struct StreamMessage** results, int timeout_secs);
static int libp2p_mplex_read_raw(void* stream_context, uint8_t* buffer, int buffer_len, int timeout_secs);
static int libp2p_mplex_write(void* stream_context, struct StreamMessage* msg);

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

static int libp2p_mplex_close(struct Stream* stream) {
	if (stream == NULL) {
		return 0;
	}
	struct MplexContext* ctx = (struct MplexContext*)stream->stream_context;
	if (ctx != NULL) {
		free(ctx);
	}
	free(stream);
	return 1;
}

static int libp2p_mplex_peek(void* stream_context) {
	struct MplexContext* ctx = (struct MplexContext*)stream_context;
	if (ctx == NULL || ctx->stream == NULL || ctx->stream->parent_stream == NULL || ctx->stream->parent_stream->peek == NULL) {
		return -1;
	}
	return ctx->stream->parent_stream->peek(ctx->stream->parent_stream->stream_context);
}

static int libp2p_mplex_read(void* stream_context, struct StreamMessage** results, int timeout_secs) {
	struct MplexContext* ctx = (struct MplexContext*)stream_context;
	if (ctx == NULL || ctx->stream == NULL || ctx->stream->parent_stream == NULL || ctx->stream->parent_stream->read == NULL) {
		return 0;
	}
	return ctx->stream->parent_stream->read(ctx->stream->parent_stream->stream_context, results, timeout_secs);
}

static int libp2p_mplex_read_raw(void* stream_context, uint8_t* buffer, int buffer_len, int timeout_secs) {
	struct MplexContext* ctx = (struct MplexContext*)stream_context;
	if (ctx == NULL || ctx->stream == NULL || ctx->stream->parent_stream == NULL || ctx->stream->parent_stream->read_raw == NULL) {
		return -1;
	}
	return ctx->stream->parent_stream->read_raw(ctx->stream->parent_stream->stream_context, buffer, buffer_len, timeout_secs);
}

static int libp2p_mplex_write(void* stream_context, struct StreamMessage* msg) {
	struct MplexContext* ctx = (struct MplexContext*)stream_context;
	if (ctx == NULL || ctx->stream == NULL || ctx->stream->parent_stream == NULL || ctx->stream->parent_stream->write == NULL) {
		return 0;
	}
	return ctx->stream->parent_stream->write(ctx->stream->parent_stream->stream_context, msg);
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
		out->close = libp2p_mplex_close;
		out->read = libp2p_mplex_read;
		out->read_raw = libp2p_mplex_read_raw;
		out->write = libp2p_mplex_write;
		out->peek = libp2p_mplex_peek;
		out->address = parent_stream->address;
		out->socket_mutex = parent_stream->socket_mutex;
		out->channel = parent_stream->channel;
		parent_stream->handle_upgrade(parent_stream, out);
		if (!theyRequested) {
			if (parent_stream->write != NULL) {
				libp2p_mplex_send_protocol(parent_stream);
			}
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
