#include "libp2p/autonat/autonat.h"

#include <string.h>

static int write_varint(uint64_t value, uint8_t *out_buf, size_t max_buf_len, size_t *offset) {
	do {
		if (*offset >= max_buf_len) {
			return 0;
		}
		uint8_t byte = (uint8_t)(value & 0x7F);
		value >>= 7;
		if (value != 0) {
			byte |= 0x80;
		}
		out_buf[(*offset)++] = byte;
	} while (value != 0);
	return 1;
}

static int write_bytes_field(uint32_t field_number, const uint8_t *data, size_t data_len, uint8_t *out_buf, size_t max_buf_len, size_t *offset) {
	if (!write_varint(((uint64_t)field_number << 3) | 2, out_buf, max_buf_len, offset)) {
		return 0;
	}
	if (!write_varint(data_len, out_buf, max_buf_len, offset)) {
		return 0;
	}
	if (*offset + data_len > max_buf_len) {
		return 0;
	}
	memcpy(&out_buf[*offset], data, data_len);
	*offset += data_len;
	return 1;
}

static int write_string_field(uint32_t field_number, const char *value, uint8_t *out_buf, size_t max_buf_len, size_t *offset) {
	if (value == NULL) {
		return 1;
	}
	return write_bytes_field(field_number, (const uint8_t*)value, strlen(value), out_buf, max_buf_len, offset);
}

size_t autonat_encode_dial_response(const autonat_dial_response_t *resp, uint8_t *out_buf, size_t max_buf_len) {
	if (!resp || !out_buf) return 0;

	size_t offset = 0;

	if (!write_varint((1u << 3) | 0, out_buf, max_buf_len, &offset)) return 0;
	if (!write_varint((uint64_t)1, out_buf, max_buf_len, &offset)) return 0;

	if (!write_varint((3u << 3) | 2, out_buf, max_buf_len, &offset)) return 0;
	size_t len_pos = offset++;
	size_t body_start = offset;

	if (!write_varint((1u << 3) | 0, out_buf, max_buf_len, &offset)) return 0;
	if (!write_varint((uint64_t)resp->status, out_buf, max_buf_len, &offset)) return 0;

	(void)resp->status_text;
	(void)resp->ma_addr;
	(void)resp->ma_addr_len;

	if (offset > max_buf_len) return 0;
	out_buf[len_pos] = (uint8_t)(offset - body_start);
	return offset;
}

size_t autonat_encode_dial_request(const autonat_dial_request_t *req, uint8_t *out_buf, size_t max_buf_len) {
	if (!req || !out_buf) return 0;

	size_t offset = 0;

	if (!write_varint((1u << 3) | 0, out_buf, max_buf_len, &offset)) return 0;
	if (!write_varint((uint64_t)0, out_buf, max_buf_len, &offset)) return 0;

	if (!write_varint((2u << 3) | 2, out_buf, max_buf_len, &offset)) return 0;
	size_t len_pos = offset++;
	size_t body_start = offset;

	if (!write_bytes_field(1, req->peer_id, req->peer_id_len, out_buf, max_buf_len, &offset)) return 0;
	if (req->target_addr != NULL && req->target_addr_len > 0) {
		if (!write_bytes_field(2, req->target_addr, req->target_addr_len, out_buf, max_buf_len, &offset)) return 0;
	}

	if (offset > max_buf_len) return 0;
	out_buf[len_pos] = (uint8_t)(offset - body_start);
	return offset;
}
