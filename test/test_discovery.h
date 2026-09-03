#pragma once

#include <stdlib.h>
#include <string.h>

#include "libp2p/discovery/discovery.h"
#include "libp2p/autonat/autonat.h"
#include "libp2p/net/mdns.h"

int test_discovery_new_free(void) {
	struct Libp2pDiscovery* discovery = libp2p_discovery_new();
	if (discovery == NULL) {
		return 0;
	}
	libp2p_discovery_free(discovery);
	return 1;
}

int test_discovery_private_address_classification(void) {
	if (!libp2p_discovery_is_private_address("/ip4/10.1.2.3/tcp/4001")) {
		return 0;
	}
	if (!libp2p_discovery_is_private_address("/ip4/192.168.1.2/tcp/4001")) {
		return 0;
	}
	if (libp2p_discovery_is_private_address("/ip4/8.8.8.8/tcp/4001")) {
		return 0;
	}
	return 1;
}

int test_discovery_hole_punch_hint(void) {
	struct Libp2pDiscovery* discovery = libp2p_discovery_new();
	if (discovery == NULL) {
		return 0;
	}
	libp2p_discovery_config_t config = {
		.mdns_enabled = 1,
		.mdns_interval = 1,
		.relay_enabled = 1,
		.relay_hop = 1,
		.autonat_enabled = 1,
		.hole_punch_enabled = 1
	};
	libp2p_discovery_configure(discovery, &config);
	libp2p_discovery_add_relay_hint(discovery, "/ip4/127.0.0.1/tcp/4001/p2p/QmRelay");
	libp2p_discovery_record_observed_address(discovery, "/ip4/10.0.0.5/tcp/4001");
	if (!libp2p_discovery_should_hole_punch(discovery, "/ip4/10.0.0.5/tcp/4001")) {
		libp2p_discovery_free(discovery);
		return 0;
	}
	libp2p_discovery_free(discovery);
	return 1;
}

static void test_mdns_peer_found_cb(const char *peer_id, const char *multiaddr, void *user_data) {
	(void)peer_id;
	(void)multiaddr;
	int *called = (int*)user_data;
	if (called != NULL) {
		*called = 1;
	}
}

int test_mdns_service_new(void) {
	int called = 0;
	mdns_service_t *service = mdns_service_new("QmTestPeer", "/ip4/127.0.0.1/tcp/4001", test_mdns_peer_found_cb, &called);
	if (service == NULL) {
		return 0;
	}
	mdns_service_free(service);
	return 1;
}

int test_autonat_encode_dial_response(void) {
	uint8_t buffer[16];
	autonat_dial_response_t resp = {
		.status = AUTONAT_STATUS_OK,
		.status_text = "OK",
		.ma_addr = NULL,
		.ma_addr_len = 0
	};
	size_t encoded_len = autonat_encode_dial_response(&resp, buffer, sizeof(buffer));
	if (encoded_len != 6) {
		return 0;
	}
	uint8_t expected[] = { 0x08, 0x01, 0x1A, 0x02, 0x08, 0x00 };
	return memcmp(buffer, expected, sizeof(expected)) == 0;
}
