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

/* ----------------- ICMP V6 ----------------- */

uint16_t
icmpv6Checksum(
	const struct in6_addr	*src,
	const struct in6_addr	*dst,
	const void				*icmp,
	uint32_t				icmpLen)
{
	uint32_t		sum;
	uint32_t		len;
	const uint16_t	*ptr;
	uint32_t		tmp;
	uint8_t			buf[40]; /* pseudo-header */

	if (!src || !dst || !icmp)
		return (0);

	memset(buf, 0, sizeof(buf));
	memcpy(buf, src, 16);
	memcpy(buf + 16, dst, 16);

	tmp = ipHtonl(icmpLen);
	memcpy(buf + 32, &tmp, 4);
	buf[39] = IP_PROTO_ICMPV6;

	sum = 0;
	ptr = (const uint16_t *)buf;
	len = sizeof(buf);

	while (len > 1)
	{
		sum += *ptr++;
		len -= 2;
	}

	ptr = (const uint16_t *)icmp;
	len = icmpLen;

	while (len > 1)
	{
		sum += *ptr++;
		len -= 2;
	}

	if (len == 1)
		sum += (*(const uint8_t *)ptr << 8);

	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	return ((uint16_t)(~sum));
}

static void
buildIcmpv6Hdr(tIcmp6Hdr *hdr, uint8_t type, uint8_t code)
{
	if (!hdr)
		return;
	hdr->type = type;
	hdr->code = code;
	hdr->checksum = 0;
}

uint32_t
buildIcmpv6EchoRequest(
	tIcmp6Echo				*req,
	uint32_t				bufferSize,
	uint16_t				id,
	uint16_t				seq,
	const void				*payload,
	uint32_t				payloadLen,
	const struct in6_addr	*src,
	const struct in6_addr	*dst,
	int						doChecksum)
{
	uint32_t	totalLen;

	if (!req)
		return (0);

	totalLen = sizeof(tIcmp6Hdr) + 4 + payloadLen;
	if (bufferSize < totalLen)
		return (0);

	buildIcmpv6Hdr(&req->hdr, ICMP6_ECHO_REQUEST, 0);
	req->id = ipHtons(id);
	req->sequence = ipHtons(seq);

	if (payload && payloadLen > 0)
		memcpy(req->data, payload, payloadLen);

	if (doChecksum)
	{
		req->hdr.checksum = icmpv6Checksum(
			src,
			dst,
			req,
			totalLen
		);
	}

	return (totalLen);
}

const tIcmp6Hdr
*icmp6ParseHeader(const void *data, uint32_t len)
{
	if (!data || len < sizeof(tIcmp6Hdr))
		return (NULL);
	return ((const tIcmp6Hdr *)data);
}
