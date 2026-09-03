#pragma once

#include "libp2p/net/protocol.h"
#include "libp2p/net/stream.h"

#define MPLEX_PROTOCOL_ID "/mplex/6.7.0\n"

enum MplexStatus {
	mplex_status_initialized,
	mplex_status_syn,
	mplex_status_ack
};

struct MplexContext {
	struct Stream* stream;
	struct Libp2pVector* protocol_handlers;
	volatile enum MplexStatus status;
};

int libp2p_mplex_can_handle(const struct StreamMessage* msg);
int libp2p_mplex_send_protocol(struct Stream* stream);
int libp2p_mplex_receive_protocol(struct Stream* stream);
struct Stream* libp2p_mplex_stream_new(struct Stream* parent_stream, int theyRequested);
void libp2p_mplex_stream_free(struct Stream* stream);
int libp2p_mplex_ready(struct SessionContext* session_context, int timeout_secs);
int libp2p_mplex_handle_message(const struct StreamMessage* msg, struct Stream* stream, void* protocol_context);
int libp2p_mplex_shutdown(void* protocol_context);
struct Libp2pProtocolHandler* libp2p_mplex_build_protocol_handler(struct Libp2pVector* handlers);
