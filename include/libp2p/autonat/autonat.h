#pragma once

#include <stddef.h>
#include <stdint.h>

typedef enum {
	AUTONAT_STATUS_OK = 0,
	AUTONAT_STATUS_E_DIAL_ERROR = 100,
	AUTONAT_STATUS_E_DIAL_REFUSED = 101,
	AUTONAT_STATUS_E_BAD_REQUEST = 200,
	AUTONAT_STATUS_E_INTERNAL_ERROR = 300
} autonat_status_t;

typedef struct {
	uint8_t *peer_id;
	size_t peer_id_len;
	uint8_t *target_addr;
	size_t target_addr_len;
} autonat_dial_request_t;

typedef struct {
	autonat_status_t status;
	const char *status_text;
	uint8_t *ma_addr;
	size_t ma_addr_len;
} autonat_dial_response_t;

size_t autonat_encode_dial_response(const autonat_dial_response_t *resp, uint8_t *out_buf, size_t max_buf_len);
size_t autonat_encode_dial_request(const autonat_dial_request_t *req, uint8_t *out_buf, size_t max_buf_len);
