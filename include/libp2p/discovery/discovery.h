#pragma once

#include <pthread.h>

#include "libp2p/net/stream.h"
#include "libp2p/utils/vector.h"

typedef struct {
	int mdns_enabled;
	int mdns_interval;
	int relay_enabled;
	int relay_hop;
	int autonat_enabled;
	int hole_punch_enabled;
} libp2p_discovery_config_t;

struct Libp2pDiscovery {
	libp2p_discovery_config_t config;
	struct Libp2pVector* relay_hints;
	struct Libp2pVector* observed_addresses;
	pthread_t worker;
	int worker_started;
	volatile int running;
};

struct Libp2pDiscovery* libp2p_discovery_new(void);
int libp2p_discovery_configure(struct Libp2pDiscovery* discovery, const libp2p_discovery_config_t* config);
int libp2p_discovery_start(struct Libp2pDiscovery* discovery);
int libp2p_discovery_stop(struct Libp2pDiscovery* discovery);
int libp2p_discovery_free(struct Libp2pDiscovery* discovery);
int libp2p_discovery_add_relay_hint(struct Libp2pDiscovery* discovery, const char* multiaddr);
int libp2p_discovery_record_observed_address(struct Libp2pDiscovery* discovery, const char* multiaddr);
int libp2p_discovery_should_hole_punch(struct Libp2pDiscovery* discovery, const char* multiaddr);
int libp2p_discovery_is_private_address(const char* multiaddr);
