#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
/**
 * Functions for handling the local dialer
 */

#include "libp2p/crypto/encoding/x509.h"
#include "libp2p/conn/dialer.h"
#include "libp2p/conn/connection.h"
#include "libp2p/conn/transport_dialer.h"
#include "libp2p/crypto/key.h"
#include "libp2p/utils/linked_list.h"
#include "libp2p/utils/logger.h"
#include "multiaddr/multiaddr.h"
#include "libp2p/net/multistream.h"
int libp2p_net_multistream_handle_message(const struct StreamMessage* msg, struct Stream* stream, void* protocol_context);
#include "libp2p/secio/secio.h"
#include "libp2p/yamux/yamux.h"
#include "libp2p/identify/identify.h"
#include "libp2p/peer/peerstore.h"
#include "libp2p/crypto/peerutils.h"

#include "libp2p/utils/debug.h"

struct TransportDialer* libp2p_conn_tcp_transport_dialer_new(char* peer_id, struct RsaPrivateKey* private_key);
int libp2p_yamux_read(void* stream_context, struct StreamMessage** message, int timeout_secs);

/**
 * Pump yamux frames until the requested channel has data in its buffer.
 * Used during the synchronous outbound Identify exchange, before the swarm
 * listener thread is started.
 */
static int dialer_pump_yamux_for_channel(struct YamuxContext* ctx, struct YamuxChannelContext* channel, int timeout_secs) {
	if (ctx == NULL || channel == NULL || channel->buffer == NULL)
		return 0;
	time_t start = time(NULL);
	while (difftime(time(NULL), start) < timeout_secs) {
		if (channel->buffer->buffer_size > 0)
			return 1;
		struct StreamMessage* msg = NULL;
		if (libp2p_yamux_read(ctx, &msg, 1)) {
			if (msg != NULL)
				libp2p_stream_message_free(msg);
			if (channel->buffer->buffer_size > 0)
				return 1;
		} else {
			usleep(100000);
		}
	}
	return channel->buffer->buffer_size > 0;
}

/**
 * Create a Dialer with the specified local information
 * @param peer the local peer
 * @param peerstore the local peerstore
 * @param private_key the local private key
 * @returns a new Dialer struct
 */
struct Dialer* libp2p_conn_dialer_new(struct Libp2pPeer* peer, struct Peerstore* peerstore, struct RsaPrivateKey* rsa_private_key, struct SwarmContext* swarm) {
	struct Dialer* dialer = (struct Dialer*)malloc(sizeof(struct Dialer));
	if (dialer != NULL) {
		dialer->peerstore = peerstore;
		dialer->private_key = rsa_private_key;
		dialer->transport_dialers = NULL;
		dialer->swarm = swarm;
		dialer->peer_id = NULL;
		if (peer != NULL) {
			dialer->peer_id = malloc(peer->id_size + 1);
			if (dialer->peer_id != NULL) {
				memset(dialer->peer_id, 0, peer->id_size + 1);
				strncpy(dialer->peer_id, peer->id, peer->id_size);
			}
		}
		dialer->fallback_dialer = libp2p_conn_tcp_transport_dialer_new(dialer->peer_id, rsa_private_key);
		dialer->noise_handshake = NULL;
		return dialer;
	}
	libp2p_conn_dialer_free(dialer);
	return NULL;
}

/**
 * Free resources from the Dialer
 * NOTE: this frees the fallback dialer too (should we be doing this?
 * @param in the Dialer struct to free
 */
void libp2p_conn_dialer_free(struct Dialer* in) {
	if (in != NULL) {
		if (in->peer_id != NULL)
			free(in->peer_id);
		libp2p_crypto_rsa_rsa_private_key_free(in->private_key);
		if (in->transport_dialers != NULL) {
			struct Libp2pLinkedList* current = in->transport_dialers;
			while(current != NULL) {
				libp2p_conn_transport_dialer_free((struct TransportDialer*)current->item);
				current = current->next;
			}
		}
		if (in->fallback_dialer != NULL)
			libp2p_conn_transport_dialer_free((struct TransportDialer*)in->fallback_dialer);
		free(in);
	}
	return;
}

/**
 * Retrieve a Connection struct from the dialer
 * NOTE: This should no longer be used. _get_stream should
 * be used instead (which calls this method internally).
 * @param dialer the dialer to use
 * @param muiltiaddress who to connect to
 * @returns a stream that is a ConnectionStream, or NULL
 */
struct Stream* libp2p_conn_dialer_get_connection(const struct Dialer* dialer, const struct MultiAddress* multiaddress) {
	struct Stream* conn = libp2p_conn_transport_dialer_get(dialer->transport_dialers, multiaddress);
	if (conn == NULL) {
		conn = dialer->fallback_dialer->dial(dialer->fallback_dialer, multiaddress);
	}
	return conn;
}

/***
 * Attempt to connect to a particular peer. This will negotiate several protocols
 * @param dialer the dialer
 * @param peer the peer to join
 * @returns true(1) on success, false(0) otherwise
 */
int libp2p_conn_dialer_join_swarm(const struct Dialer* dialer, struct Libp2pPeer* peer, int timeout_secs) {
	DEBUG_PRINTF("[dialer debug] join_swarm start for peer %s\n", peer->id ? peer->id : "(null)");
	if (dialer == NULL || peer == NULL)
		return 0;
	// find the right Multiaddress
	struct Libp2pLinkedList* current_entry = peer->addr_head;
	struct Stream* conn_stream = NULL;
	while (current_entry != NULL) {
		struct MultiAddress* ma = current_entry->item;
		conn_stream = libp2p_conn_dialer_get_connection(dialer, ma);
		if (conn_stream != NULL) {
			if (peer->sessionContext == NULL) {
				peer->sessionContext = libp2p_session_context_new();
				struct ConnectionContext* conn_ctx = conn_stream->stream_context;
				conn_ctx->session_context = peer->sessionContext;
			}
			peer->sessionContext->insecure_stream = conn_stream;
			peer->sessionContext->default_stream = conn_stream;
			peer->sessionContext->port = multiaddress_get_ip_port(ma);
			multiaddress_get_ip_address(ma, &peer->sessionContext->host);
			break;
		}
		current_entry = current_entry->next;
	}
	if (conn_stream == NULL) {
		DEBUG_PRINTF("[dialer debug] no conn_stream, bailing\n");
		return 0;
	}
	DEBUG_PRINTF("[dialer debug] TCP connected, fd=%d\n", ((struct ConnectionContext*)conn_stream->stream_context)->socket_descriptor);
	// Negotiate multistream on the raw TCP connection synchronously before
	// handing the peer off to the swarm listener, so we don't race with the
	// swarm thread for bytes on the raw TCP socket.
	struct Stream* multistream = libp2p_net_multistream_stream_new(conn_stream, 0);
	if (multistream == NULL) {
		libp2p_logger_error("dialer", "Multistream negotiation failed.\n");
		DEBUG_PRINTF("[dialer debug] initial multistream stream_new failed\n");
		return 0;
	}
	DEBUG_PRINTF("[dialer debug] initial multistream wrapper created\n");
	// Read the multistream protocol ack synchronously. libp2p_net_multistream_stream_new
	// already sent "/multistream/1.0.0\n"; the remote should reply with the same.
	{
		struct StreamMessage* ms_ack = NULL;
		int ms_ack_ok = 0;
		if (multistream->read != NULL)
			ms_ack_ok = multistream->read(multistream->stream_context, &ms_ack, 5);
		if (!ms_ack_ok || ms_ack == NULL) {
			DEBUG_PRINTF("[dialer debug] initial multistream ack read failed\n");
			return 0;
		}
		DEBUG_PRINTF("[dialer debug] initial multistream ack data_size=%zu data=%.*s\n", ms_ack->data_size, (int)ms_ack->data_size, (char*)ms_ack->data);
		if (ms_ack->data_size != 19 || strncmp((char*)ms_ack->data, "/multistream/1.0.0\n", 19) != 0) {
			DEBUG_PRINTF("[dialer debug] initial multistream ack unexpected\n");
			libp2p_stream_message_free(ms_ack);
			return 0;
		}
		libp2p_net_multistream_handle_message(ms_ack, multistream, NULL);
		libp2p_stream_message_free(ms_ack);
	}
	// Keep the peer off the swarm until the multistream-over-noise handshake
	// is complete. Adding the peer earlier spawns a swarm listener thread that
	// races with the dialer for reads on the Noise stream, causing nonce desync
	// and failed decryption.
	// wait for multistream
	if (!libp2p_net_multistream_ready(peer->sessionContext, 5)) {
		DEBUG_PRINTF("[dialer debug] initial multistream not ready\n");
		return 0;
	}
	DEBUG_PRINTF("[dialer debug] initial multistream ready\n");
	struct Stream* new_stream = peer->sessionContext->default_stream;
	if (new_stream != NULL) {
		// Skip secio (not supported by Kubo v0.43.0), go straight to Noise
		new_stream = NULL;
		if (dialer->noise_handshake != NULL) {
			struct StreamMessage noise_msg;
			noise_msg.data = (uint8_t*)"/noise\n";
			noise_msg.data_size = 7;
			struct Stream* root_stream = peer->sessionContext->default_stream;
			while (root_stream->parent_stream != NULL) root_stream = root_stream->parent_stream;
			pthread_mutex_lock(root_stream->socket_mutex);
			if (peer->sessionContext->default_stream->write(peer->sessionContext->default_stream->stream_context, &noise_msg)) {
				struct StreamMessage* resp = NULL;
				if (peer->sessionContext->default_stream->read(peer->sessionContext->default_stream->stream_context, &resp, 5) && resp != NULL) {
					DEBUG_PRINTF("[dialer debug] /noise proposal ack data_size=%zu data=%.*s\n", resp->data_size, (int)resp->data_size, (char*)resp->data);
					if (strncmp((char*)resp->data, "/noise\n", 7) == 0) {
						/* Use the raw TCP stream for Noise to avoid multistream framing corrupting the 2-byte BE length prefixes. */
						DEBUG_PRINTF("[dialer debug] calling noise_handshake on insecure_stream\n");
						struct Stream* noise_stream = dialer->noise_handshake(peer->sessionContext->insecure_stream, dialer->private_key);
						DEBUG_PRINTF("[dialer debug] noise_handshake returned %p\n", (void*)noise_stream);
						if (noise_stream != NULL) {
							new_stream = noise_stream;
							peer->sessionContext->default_stream = noise_stream;
							libp2p_logger_debug("dialer", "We successfully negotiated noise.\n");
						}
					}
				}
			}
			pthread_mutex_unlock(root_stream->socket_mutex);
		}
		if (new_stream == NULL) {
			DEBUG_PRINTF("[dialer debug] noise negotiation failed\n");
			libp2p_logger_error("dialer", "Unable to do noise negotiation.\n");
			return 0;
		}
		// multistream over noise
		DEBUG_PRINTF("[dialer debug] creating multistream over noise, parent stream type=%d\n", new_stream->stream_type);
		struct Stream* ms_over_noise = libp2p_net_multistream_stream_new(new_stream, 0);
		if (ms_over_noise == NULL) {
			libp2p_logger_error("dialer", "Unable to negotiate multistream over noise.\n");
			return 0;
		}
		DEBUG_PRINTF("[dialer debug] multistream over noise created, default_stream type=%d\n", peer->sessionContext->default_stream->stream_type);
		// wait for multistream-over-noise ack before proceeding to yamux
		// (use a longer timeout because the swarm thread read may block for
		// up to 10 seconds via the v2 raw stream wrapper)
		/* Process multistream-over-noise ack synchronously. */
		{
			struct StreamMessage* __ms_ack = NULL;
			int __read_ok = 0;
			DEBUG_PRINTF("[dialer debug] reading multistream ack synchronously\n");
			if (ms_over_noise->parent_stream != NULL && ms_over_noise->parent_stream->read != NULL)
				__read_ok = ms_over_noise->parent_stream->read(ms_over_noise->parent_stream->stream_context, &__ms_ack, 5);
			DEBUG_PRINTF("[dialer debug] synchronous read returned %d, ack=%p\n", __read_ok, (void*)__ms_ack);
			if (__read_ok && __ms_ack != NULL) {
				DEBUG_PRINTF("[dialer debug] got ack of %zu bytes: %.*s\n", __ms_ack->data_size, (int)__ms_ack->data_size, (char*)__ms_ack->data);
				libp2p_net_multistream_handle_message(__ms_ack, ms_over_noise, NULL);
				libp2p_stream_message_free(__ms_ack);
			}
		}
		DEBUG_PRINTF("[dialer debug] waiting for multistream ready\n");
		if (!libp2p_net_multistream_ready(peer->sessionContext, 15)) {
			DEBUG_PRINTF("[dialer debug] multistream over noise NOT ready\n");
			libp2p_logger_error("dialer", "Multistream over noise not ready.\n");
			return 0;
		}
		DEBUG_PRINTF("[dialer debug] multistream over noise ready\n");
		// yamux over multistream
		DEBUG_PRINTF("[dialer debug] creating yamux, default_stream type=%d\n", peer->sessionContext->default_stream->stream_type);
		new_stream = libp2p_yamux_stream_new(peer->sessionContext->default_stream, 0, dialer->swarm->protocol_handlers);
		if (new_stream != NULL) {
			// Drive the yamux protocol ack synchronously before adding the peer to
			// the swarm, so we don't depend on the swarm thread scheduling for this
			// final negotiation step.
			{
				struct StreamMessage* yamux_ack = NULL;
				int yamux_read_ok = 0;
				if (peer->sessionContext->default_stream != NULL && peer->sessionContext->default_stream->read != NULL) {
					for (int i = 0; i < 5; i++) {
						yamux_read_ok = peer->sessionContext->default_stream->read(peer->sessionContext->default_stream->stream_context, &yamux_ack, 2);
						if (yamux_read_ok)
							break;
					}
				}
				if (yamux_ack != NULL)
					libp2p_stream_message_free(yamux_ack);
			}
			if (!libp2p_yamux_stream_ready(peer->sessionContext, 5)) {
				DEBUG_PRINTF("[dialer debug] yamux not ready\n");
				libp2p_logger_error("dialer", "Unable to get yamux into the ready status.\n");
				return 0;
			}
			DEBUG_PRINTF("[dialer debug] yamux ready, default_stream type=%d\n", peer->sessionContext->default_stream->stream_type);
			// Run Identify over yamux synchronously before handing the peer to the
			// swarm.  If the swarm listener starts first, it races with the dialer
			// for reads on the shared Noise/Yamux stream and corrupts the session.
			const struct Libp2pProtocolHandler* handler = libp2p_protocol_get_handler(dialer->swarm->protocol_handlers, "/ipfs/id/1.0.0\n");
			if (handler != NULL) {
				Identify* identify = handler->context;
				if (peer->sessionContext->default_stream->stream_type == STREAM_TYPE_YAMUX) {
					struct YamuxContext* ctx = libp2p_yamux_get_context(peer->sessionContext->default_stream->stream_context);
					// first get a new frame. It should be ready to go
					struct Stream* new_channel = yamux_channel_new(ctx, 0, NULL);
					if (new_channel != NULL && new_channel->channel > 0) {
						struct YamuxChannelContext* channel_ctx = libp2p_yamux_get_channel_context(new_channel->stream_context);
						// then get a multistream
						struct Stream* yamux_multistream = libp2p_net_multistream_stream_new(new_channel, 0);
						// Wait for the remote's multistream ack and mark the
						// multistream ready.  We cannot rely on the swarm listener
						// because the peer has not been added to the swarm yet.
						if (!dialer_pump_yamux_for_channel(ctx, channel_ctx, 10)) {
							libp2p_logger_error("dialer", "Timed out waiting for multistream ack over yamux.\n");
							return 0;
						}
						struct StreamMessage* ms_ack = NULL;
						if (!yamux_multistream->read(yamux_multistream->stream_context, &ms_ack, 5) || ms_ack == NULL) {
							libp2p_logger_error("dialer", "Unable to read multistream ack over yamux.\n");
							return 0;
						}
						libp2p_net_multistream_handle_message(ms_ack, yamux_multistream, NULL);
						libp2p_stream_message_free(ms_ack);
						DEBUG_PRINTF("[dialer debug] multistream over yamux ready (channel %d)\n", new_channel->channel);
						// Send our Identify (protocol id + protobuf)
						struct Stream* identify_stream = libp2p_identify_stream_new(yamux_multistream, identify, 0);
						if (identify_stream != NULL) {
							// Read remote's protocol ack
							if (!dialer_pump_yamux_for_channel(ctx, channel_ctx, 10)) {
								libp2p_logger_error("dialer", "Timed out waiting for Identify ack over yamux.\n");
								return 0;
							}
							struct StreamMessage* ack = NULL;
							if (yamux_multistream->read(yamux_multistream->stream_context, &ack, 5) && ack != NULL) {
								libp2p_stream_message_free(ack);
								// Read remote's Identify protobuf
								if (!dialer_pump_yamux_for_channel(ctx, channel_ctx, 10)) {
									libp2p_logger_error("dialer", "Timed out waiting for Identify message over yamux.\n");
									return 0;
								}
								struct StreamMessage* remote_identify = NULL;
								if (yamux_multistream->read(yamux_multistream->stream_context, &remote_identify, 5) && remote_identify != NULL) {
									Identify* remote = NULL;
									if (libp2p_identify_protobuf_decode(remote_identify->data, remote_identify->data_size, &remote)) {
										// Update peerstore with received listen addresses
										if (dialer->peerstore != NULL && peer->id != NULL && peer->id_size > 0 && remote->ListenAddrs != NULL) {
											struct Libp2pPeer temp_peer;
											memset(&temp_peer, 0, sizeof(temp_peer));
											temp_peer.id = peer->id;
											temp_peer.id_size = peer->id_size;
											for (int i = 0; remote->ListenAddrs[i] != NULL; i++) {
												struct MultiAddress* ma = multiaddress_new_from_string(remote->ListenAddrs[i]);
												if (ma != NULL) {
													struct Libp2pLinkedList* node = libp2p_utils_linked_list_new();
													if (node != NULL) {
														node->item = ma;
														node->next = temp_peer.addr_head;
														temp_peer.addr_head = node;
													} else {
														multiaddress_free(ma);
													}
												}
											}
											struct Libp2pPeer* stored = libp2p_peerstore_get_peer(dialer->peerstore, (unsigned char*)peer->id, peer->id_size);
											if (stored != NULL) {
												libp2p_peerstore_update_addresses(stored, &temp_peer);
											}
											// free temp address list
											struct Libp2pLinkedList* cur = temp_peer.addr_head;
											while (cur != NULL) {
												struct Libp2pLinkedList* next = cur->next;
												if (cur->item != NULL)
													multiaddress_free((struct MultiAddress*)cur->item);
												free(cur);
												cur = next;
											}
										}
										libp2p_identify_free(remote);
									}
									libp2p_stream_message_free(remote_identify);
								}
							}
						}
					}
				} else {
					libp2p_logger_error("dialer", "Expected a yamux context, but got a context of type %d.\n", peer->sessionContext->default_stream->stream_type);
				}
			}
			// Now that Identify is complete, hand the peer off to the swarm.
			// The swarm thread will drive yamux frame I/O for the remaining lifetime.
			libp2p_swarm_add_peer(dialer->swarm, peer);
			// kademlia over yamux
			//libp2p_yamux_stream_add(new_stream->stream_context, libp2p_kademlia_stream_new(new_stream));
			// circuit relay over yamux
			//libp2p_yamux_stream_add(new_stream->stream_context, libp2p_circuit_relay_stream_new(new_stream));
			peer->connection_type = CONNECTION_TYPE_CONNECTED;
			if (dialer->peerstore != NULL && peer->id != NULL && peer->id_size > 0) {
				struct Libp2pPeer* stored = libp2p_peerstore_get_peer(dialer->peerstore, (unsigned char*)peer->id, peer->id_size);
				if (stored != NULL) {
					if (stored->sessionContext != NULL && stored->sessionContext != peer->sessionContext)
						libp2p_session_context_free(stored->sessionContext);
					stored->sessionContext = peer->sessionContext;
					stored->connection_type = CONNECTION_TYPE_CONNECTED;
					libp2p_peerstore_update_addresses(stored, peer);
				} else {
					libp2p_peerstore_add_peer(dialer->peerstore, peer);
				}
			}
			DEBUG_PRINTF("[dialer debug] join_swarm returning success\n");
			return 1;
		} else {
			DEBUG_PRINTF("[dialer debug] yamux_stream_new returned NULL\n");
			libp2p_logger_error("dialer", "Unable to do yamux negotiation.\n");
		}
	} else {
		libp2p_logger_error("dialer", "Unable to do initial multistream negotiation.\n");
	}

	return 0;
}

/**
 * return a Stream that is already set up to use the passed in protocol
 * @param dialer the dialer to use
 * @param multiaddress the host to dial
 * @param protocol the protocol to use (right now only 'multistream' is supported)
 * @returns the ready-to-use stream
 */
struct Stream* libp2p_conn_dialer_get_stream(const struct Dialer* dialer, const struct Libp2pPeer* peer, const char* protocol) {
	// TODO: Implement this method
	return NULL;
}
