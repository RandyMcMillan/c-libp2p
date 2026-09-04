#include <stdlib.h>
#include <string.h>

#include "libp2p/conn/connection.h"

struct Connection* libp2p_conn_connection_new(struct TransportDialer* transport_dialer, struct MultiAddress* multiaddress) {
	struct Connection* out = NULL;

	if (transport_dialer != NULL && multiaddress != NULL) {
		out = (struct Connection*)malloc(sizeof(struct Connection));
		if (out != NULL) {
			memset(out, 0, sizeof(struct Connection));
			out->transport_dialer = transport_dialer;
			out->address = multiaddress;
			out->socket_fd = -1;
		}
	}
	return out;
}

void libp2p_conn_connection_free(struct Connection* connection) {
	if (connection != NULL) {
		if (connection->socket_fd >= 0) {
			close(connection->socket_fd);
			connection->socket_fd = -1;
		}
		free(connection);
	}
}

