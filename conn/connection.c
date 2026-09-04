#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libp2p/conn/connection.h"

struct Connection* libp2p_conn_connection_new(struct TransportDialer* transport_dialer, struct MultiAddress* multiaddress) {
	struct Connection* out = NULL;
	(void)multiaddress;

	if (transport_dialer != NULL) {
		out = (struct Connection*)malloc(sizeof(struct Connection));
		if (out != NULL) {
			memset(out, 0, sizeof(struct Connection));
			out->socket_handle = -1;
			out->read = NULL;
			out->write = NULL;
		}
	}
	return out;
}

void libp2p_conn_connection_free(struct Connection* connection) {
	if (connection != NULL) {
		if (connection->socket_handle >= 0) {
			close(connection->socket_handle);
			connection->socket_handle = -1;
		}
		free(connection);
	}
}

