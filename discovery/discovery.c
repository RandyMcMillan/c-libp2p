#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

#include "libp2p/discovery/discovery.h"
#include "libp2p/utils/logger.h"
#include "libp2p/utils/logger.h"

static char* discovery_strdup(const char* value) {
	if (value == NULL) {
		return NULL;
	}
	size_t len = strlen(value);
	char* copy = (char*)malloc(len + 1);
	if (copy != NULL) {
		memcpy(copy, value, len + 1);
	}
	return copy;
}

static void discovery_vector_free_strings(struct Libp2pVector* vector) {
	if (vector == NULL) {
		return;
	}
	for (int i = 0; i < vector->total; i++) {
		char* item = (char*)libp2p_utils_vector_get(vector, i);
		free(item);
	}
	libp2p_utils_vector_free(vector);
}

static int discovery_is_private_ipv4(const char* ip) {
	unsigned int a = 0, b = 0;
	if (ip == NULL) {
		return 0;
	}
	if (sscanf(ip, "%u.%u", &a, &b) < 2) {
		return 0;
	}
	if (a == 10 || a == 127) {
		return 1;
	}
	if (a == 192 && b == 168) {
		return 1;
	}
	if (a == 172 && b >= 16 && b <= 31) {
		return 1;
	}
	return 0;
}

static int discovery_is_private_ipv6(const char* ip) {
	if (ip == NULL) {
		return 0;
	}
	return strncmp(ip, "fc", 2) == 0 || strncmp(ip, "fd", 2) == 0 || strncmp(ip, "fe80", 4) == 0;
}

int libp2p_discovery_is_private_address(const char* multiaddr) {
	if (multiaddr == NULL) {
		return 0;
	}
	const char* ip4 = strstr(multiaddr, "/ip4/");
	if (ip4 != NULL) {
		ip4 += 5;
		char ip[64] = {0};
		size_t i = 0;
		while (ip4[i] != '\0' && ip4[i] != '/' && i < sizeof(ip) - 1) {
			ip[i] = ip4[i];
			i++;
		}
		return discovery_is_private_ipv4(ip);
	}
	const char* ip6 = strstr(multiaddr, "/ip6/");
	if (ip6 != NULL) {
		ip6 += 5;
		char ip[128] = {0};
		size_t i = 0;
		while (ip6[i] != '\0' && ip6[i] != '/' && i < sizeof(ip) - 1) {
			ip[i] = ip6[i];
			i++;
		}
		return discovery_is_private_ipv6(ip);
	}
	return 0;
}

static void* discovery_worker(void* arg) {
	struct Libp2pDiscovery* discovery = (struct Libp2pDiscovery*)arg;
	if (discovery == NULL) {
		return NULL;
	}
	while (discovery->running) {
		if (discovery->config.mdns_enabled) {
			libp2p_logger_debug("discovery", "mDNS discovery tick (interval %d).\n", discovery->config.mdns_interval);
		}
		if (discovery->config.relay_enabled && discovery->relay_hints != NULL && discovery->relay_hints->total > 0) {
			libp2p_logger_debug("discovery", "Relay hints available: %d\n", discovery->relay_hints->total);
		}
#ifdef DEBUG
		if (discovery->config.mdns_enabled) {
			libp2p_logger_debug("discovery", "mDNS discovery tick (interval %d).\n", discovery->config.mdns_interval);
		}
		if (discovery->config.relay_enabled && discovery->relay_hints != NULL && discovery->relay_hints->total > 0) {
			libp2p_logger_debug("discovery", "Relay hints available: %d\n", discovery->relay_hints->total);
		}
#endif
		int interval = discovery->config.mdns_interval > 0 ? discovery->config.mdns_interval : 1;
		for (int i = 0; i < interval && discovery->running; i++) {
			sleep(1);
		}
	}
	return NULL;
}

struct Libp2pDiscovery* libp2p_discovery_new(void) {
	struct Libp2pDiscovery* discovery = (struct Libp2pDiscovery*)calloc(1, sizeof(struct Libp2pDiscovery));
	if (discovery != NULL) {
		discovery->relay_hints = libp2p_utils_vector_new(4);
		discovery->observed_addresses = libp2p_utils_vector_new(4);
		discovery->config.mdns_interval = 10;
	}
	return discovery;
}

int libp2p_discovery_configure(struct Libp2pDiscovery* discovery, const libp2p_discovery_config_t* config) {
	if (discovery == NULL || config == NULL) {
		return 0;
	}
	discovery->config = *config;
	return 1;
}

int libp2p_discovery_start(struct Libp2pDiscovery* discovery) {
	if (discovery == NULL) {
		return 0;
	}
	if (discovery->worker_started) {
		return 1;
	}
	discovery->running = 1;
	if (pthread_create(&discovery->worker, NULL, discovery_worker, discovery) != 0) {
		discovery->running = 0;
		return 0;
	}
	discovery->worker_started = 1;
	return 1;
}

int libp2p_discovery_stop(struct Libp2pDiscovery* discovery) {
	if (discovery == NULL) {
		return 0;
	}
	discovery->running = 0;
	if (discovery->worker_started) {
		pthread_join(discovery->worker, NULL);
		discovery->worker_started = 0;
	}
	return 1;
}

int libp2p_discovery_add_relay_hint(struct Libp2pDiscovery* discovery, const char* multiaddr) {
	if (discovery == NULL || multiaddr == NULL || discovery->relay_hints == NULL) {
		return 0;
	}
	char* copy = discovery_strdup(multiaddr);
	if (copy == NULL) {
		return 0;
	}
	libp2p_utils_vector_add(discovery->relay_hints, copy);
	return 1;
}

int libp2p_discovery_record_observed_address(struct Libp2pDiscovery* discovery, const char* multiaddr) {
	if (discovery == NULL || multiaddr == NULL || discovery->observed_addresses == NULL) {
		return 0;
	}
	char* copy = discovery_strdup(multiaddr);
	if (copy == NULL) {
		return 0;
	}
	libp2p_utils_vector_add(discovery->observed_addresses, copy);
	return 1;
}

int libp2p_discovery_should_hole_punch(struct Libp2pDiscovery* discovery, const char* multiaddr) {
	if (discovery == NULL || !discovery->config.hole_punch_enabled) {
		return 0;
	}
	if (multiaddr != NULL && libp2p_discovery_is_private_address(multiaddr)) {
		return 1;
	}
	if (discovery->config.relay_enabled && discovery->observed_addresses != NULL) {
		for (int i = 0; i < discovery->observed_addresses->total; i++) {
			const char* observed = (const char*)libp2p_utils_vector_get(discovery->observed_addresses, i);
			if (libp2p_discovery_is_private_address(observed)) {
				return 1;
			}
		}
	}
	return 0;
}

int libp2p_discovery_free(struct Libp2pDiscovery* discovery) {
	if (discovery == NULL) {
		return 1;
	}
	libp2p_discovery_stop(discovery);
	discovery_vector_free_strings(discovery->relay_hints);
	discovery_vector_free_strings(discovery->observed_addresses);
	free(discovery);
	return 1;
}
