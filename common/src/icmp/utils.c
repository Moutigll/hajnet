#include <string.h>

#include "../../includes/ip.h"
#include "../../includes/icmp.h"

uint16_t icmpChecksum(const void *data, uint32_t len) {
	uint32_t sum = 0;
	const uint16_t *ptr = (const uint16_t *)data;

	while (len > 1) {
		sum += *ptr++;	/* Add 16-bit words */
		len -= 2;
	}

	if (len == 1)
		sum += *(const uint8_t *)ptr << 8;	/* Add remaining byte */

	// Fold 32-bit sum to 16 bits
	while (sum >> 16) {
		sum = (sum & 0xFFFF) + (sum >> 16);
	}

	return (uint16_t)(~sum);
}

/**
 * @brief Build ICMPv4 header
 * @param hdr - pointer to ICMPv4 header to fill
 * @param type - ICMP type
 * @param code - ICMP code
 */
static void
buildIcmpv4Hdr(tIcmp4Hdr *hdr, uint8_t type, uint8_t code)
{
	if (!hdr)
		return;
	hdr->type = type;
	hdr->code = code;
	hdr->checksum = 0;
}

uint32_t
buildIcmpv4EchoRequest(
	tIcmp4Echo	*req,
	uint32_t	bufferSize,
	uint16_t	id,
	uint16_t	seq,
	const void	*payload,
	uint32_t	payloadLen)
{
	uint32_t	totalLen;

	if (!req)
		return (0);
	totalLen = sizeof(tIcmp4Hdr) + 4 + payloadLen;
	if (bufferSize < totalLen)
		return (0);
	buildIcmpv4Hdr(&req->hdr, ICMP4_ECHO_REQUEST, 0);
	req->id = ipHtons(id);
	req->sequence = ipHtons(seq);
	if (payload && payloadLen > 0)
		memcpy(req->data, payload, payloadLen);
	req->hdr.checksum = icmpChecksum(req, totalLen);
	return (totalLen);
}

const tIcmp4Hdr
*icmp4ParseHeader(const void *data, uint32_t len)
{
	if (!data || len < sizeof(tIcmp4Hdr))
		return (NULL);
	return ((const tIcmp4Hdr *)data);
}

const tIcmp4Echo
*icmp4ParseEcho(const void *data, uint32_t len)
{
	const tIcmp4Echo	*echo;

	if (!data)
		return (NULL);
	if (len < sizeof(tIcmp4Hdr) + 4)
		return (NULL);
	echo = (const tIcmp4Echo *)data;
	if (echo->hdr.type != ICMP4_ECHO_REPLY
		&& echo->hdr.type != ICMP4_ECHO_REQUEST)
		return (NULL);
	return (echo);
}
