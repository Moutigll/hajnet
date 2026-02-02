#include "../../includes/icmp.h"

uint16_t icmpChecksum(const void *data, uint32_t len) {
	uint32_t sum = 0;
	const uint16_t *ptr = (const uint16_t *)data;

	while (len > 1) {
		sum += *ptr++;	/* Add 16-bit words */
		len -= 2;
	}

	if (len == 1)
		sum += *(const uint8_t *)ptr;

	// Fold 32-bit sum to 16 bits
	while (sum >> 16) {
		sum = (sum & 0xFFFF) + (sum >> 16);
	}

	return (uint16_t)(~sum);
}