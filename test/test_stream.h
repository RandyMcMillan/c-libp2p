#include <string.h>
#include "libp2p/net/multistream.h"

#include "libp2p/net/stream.h"

int test_stream_latest_raw_null_fallback() {
	struct Stream* raw = libp2p_stream_new();
	if (raw == NULL)
		return 0;

	raw->stream_type = STREAM_TYPE_RAW;
	raw->stream_context = NULL;
	raw->parent_stream = NULL;

	struct Stream* latest = libp2p_stream_get_latest_stream(raw);
	int retVal = (latest == raw);

	libp2p_stream_free(raw);
	return retVal;
}

int test_stream_latest_bridge_passthrough() {
	struct Stream* bridge = libp2p_stream_new();
	if (bridge == NULL)
		return 0;

	bridge->stream_type = STREAM_TYPE_BRIDGE;

	struct Stream* latest = libp2p_stream_get_latest_stream(bridge);
	int retVal = (latest == bridge);

	libp2p_stream_free(bridge);
	return retVal;
}

int test_stream_latest_poly_passthrough() {
	struct Stream* multistream = libp2p_stream_new();
	if (multistream == NULL)
		return 0;

	multistream->stream_type = STREAM_TYPE_MULTISTREAM;

	struct Stream* latest = libp2p_stream_get_latest_stream(multistream);
	int retVal = (latest == multistream);

	libp2p_stream_free(multistream);
	return retVal;
}

int test_stream_latest_raw_session_default() {
	struct Stream* default_child = libp2p_stream_new();
	struct Stream* raw = libp2p_stream_new();
	struct ConnectionContext* ctx = (struct ConnectionContext*)malloc(sizeof(struct ConnectionContext));
	if (default_child == NULL || raw == NULL || ctx == NULL) {
		if (default_child != NULL) libp2p_stream_free(default_child);
		if (raw != NULL) libp2p_stream_free(raw);
		free(ctx);
		return 0;
	}

	memset(ctx, 0, sizeof(struct ConnectionContext));
	ctx->socket_descriptor = 1;
	ctx->session_context = NULL;

	struct SessionContext session;
	memset(&session, 0, sizeof(session));
	session.default_stream = default_child;

	ctx->session_context = &session;
	raw->stream_type = STREAM_TYPE_RAW;
	raw->stream_context = ctx;

	struct Stream* latest = libp2p_stream_get_latest_stream(raw);
	int retVal = (latest == default_child);

	free(ctx);
	libp2p_stream_free(raw);
	libp2p_stream_free(default_child);
	return retVal;
}
