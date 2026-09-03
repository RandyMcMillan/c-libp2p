#pragma once

#include <stdlib.h>
#include <string.h>

#include "mock_stream.h"
#include "libp2p/mplex/mplex.h"

static struct StreamMessage* build_mplex_message(const char* data) {
	struct StreamMessage* out = libp2p_stream_message_new();
	if (out != NULL) {
		out->data_size = strlen(data);
		out->data = (uint8_t*)malloc(out->data_size);
		memcpy(out->data, data, out->data_size);
	}
	return out;
}

int test_mplex_protocol_handler(void) {
	struct Libp2pProtocolHandler* handler = libp2p_mplex_build_protocol_handler(NULL);
	if (handler == NULL || handler->CanHandle == NULL || handler->HandleMessage == NULL || handler->Shutdown == NULL) {
		return 0;
	}
	struct StreamMessage* msg = build_mplex_message(MPLEX_PROTOCOL_ID);
	if (msg == NULL || !handler->CanHandle(msg)) {
		if (msg != NULL) {
			libp2p_stream_message_free(msg);
		}
		handler->Shutdown(handler->context);
		free(handler);
		return 0;
	}
	libp2p_stream_message_free(msg);
	handler->Shutdown(handler->context);
	free(handler);
	return 1;
}

int test_mplex_stream_new(void) {
	struct Stream* mock = mock_stream_new();
	if (mock == NULL) {
		return 0;
	}
	struct Stream* mplex = libp2p_mplex_stream_new(mock, 0);
	if (mplex == NULL || mplex->stream_type != STREAM_TYPE_MPLEX) {
		if (mock != NULL) {
			mock_stream_free(mock);
		}
		return 0;
	}
	mplex->close(mplex);
	mock_stream_free(mock);
	return 1;
}
