#include "../../includes/ip.h"
#include <string.h>

size_t
parseIpHeaderFromBuffer(const void *buf, size_t len, tIpHdr *outHdr)
{
	const unsigned char *b;
	unsigned int verIhl;
	size_t ihl;

	if (!buf || !outHdr || len < 20)
		return (0);

	b = (const unsigned char *)buf;

	verIhl = b[0];	/* first byte: version (4 bits) + IHL (4 bits) */
	ihl = (size_t)(verIhl & 0x0F) * 4;

	if (ihl < 20 || len < ihl)
		return (0);

	/* fill output structure */
	outHdr->ihl  = (uint8_t)(verIhl & 0x0F);
	outHdr->version = (uint8_t)((verIhl >> 4) & 0x0F);
	outHdr->tos  = (tIpTos)b[1];
	outHdr->tot_len = ipNtohs((uint16_t)((b[2] << 8) | b[3]));
	outHdr->id = ipNtohs((uint16_t)((b[4] << 8) | b[5]));
	outHdr->fragOff.raw = ipNtohs((uint16_t)((b[6] << 8) | b[7]));
	outHdr->ttl = b[8];
	outHdr->protocol = (tIpProtocol)b[9];
	outHdr->check = ipNtohs((uint16_t)((b[10] << 8) | b[11]));
	outHdr->saddr = *(uint32_t *)&b[12];
	outHdr->daddr = *(uint32_t *)&b[16];

	/* options : if ihl > 20, we could copy option bytes if needed */
	return (ihl);
}

void
parseIp4Opts(const unsigned char *buf, size_t ipHeaderLen, tIpHdr *hdr)
{
	size_t optsLen;
	size_t i = 0;
	int slot = 0;

	if (!hdr || ipHeaderLen <= 20)
		return;

	optsLen = ipHeaderLen - 20;
	const unsigned char *opts = buf + 20;

	/* zero out options */
	for (int s = 0; s < 10; s++)
	{
		hdr->options[s].type = 0;
		hdr->options[s].length = 0;
		memset(hdr->options[s].data, 0, sizeof(hdr->options[s].data));
	}

	while (i < optsLen && slot < 10)
	{
		unsigned char opt = opts[i];

		if (opt == 0) /* EOL */
		{
			hdr->options[slot].type = 0;
			hdr->options[slot].length = 0;
			break;
		}
		if (opt == 1) /* NOP */
		{
			hdr->options[slot].type = 1;
			hdr->options[slot].length = 0;
			i++;
			slot++;
			continue;
		}

		/* Option multi-octets */
		if (i + 1 >= optsLen)
			break; /* malformed */

		unsigned char optlen = opts[i + 1];
		if (optlen < 2 || (i + optlen) > optsLen)
			break;

		hdr->options[slot].type = opt;
		hdr->options[slot].length = optlen - 2;

		/* copy data (max 40 bytes) */
		size_t copyLen = hdr->options[slot].length;
		if (copyLen > sizeof(hdr->options[slot].data))
			copyLen = sizeof(hdr->options[slot].data);
		memcpy(hdr->options[slot].data, opts + i + 2, copyLen);

		i += optlen;
		slot++;
	}
}

static size_t
parseIp6Extensions(const unsigned char *buf, size_t len, tIp6Hdr *hdr)
{
	size_t offset = 40; /* start after base header */
	uint8_t nextHdr = hdr->next_header;

	/* check minimum length for base header */
	if (len < 40)
		return (0);

	while (offset < len)
	{
		/* if nextHdr is a payload (TCP, UDP, ICMPv6), stop */
		if (nextHdr == 6 /* TCP */ ||
			nextHdr == 17 /* UDP */ ||
			nextHdr == IP_PROTO_ICMPV6)
		{
			break; /* payload reached */
		}

		/* ensure at least 2 bytes available for NextHeader + HdrExtLen (where applicable) */
		if (offset + 2 > len)
			return (0); /* malformed header */

		switch (nextHdr)
		{
			case 0:  /* Hop-by-Hop Options */
			case 43: /* Routing */
			case 60: /* Destination Options */
			{
				/* format: NextHdr(1), HdrExtLen(1), ... ; total length = (HdrExtLen + 1) * 8 bytes */
				uint8_t hdrExtLen = buf[offset + 1];
				size_t thisLen = (size_t)(hdrExtLen + 1) * 8;
				if (thisLen == 0 || offset + thisLen > len)
					return (0); /* malformed */
				nextHdr = buf[offset]; /* next header field */
				offset += thisLen;
				continue;
			}
			case 44: /* Fragment header: fixed 8 bytes */
			{
				if (offset + 8 > len)
					return (0);
				nextHdr = buf[offset]; /* NextHeader field */
				offset += 8;
				continue;
			}
			case 51: /* Authentication Header (AH) */
			{
				/* AH: NextHdr(1), PayloadLen(1), total bytes = (PayloadLen + 2) * 4 */
				uint8_t ahLenField = buf[offset + 1];
				size_t thisLen = (size_t)(ahLenField + 2) * 4;
				if (thisLen < 8 || offset + thisLen > len)
					return (0);
				nextHdr = buf[offset]; /* NextHeader field */
				offset += thisLen;
				continue;
			}
			case 50: /* ESP: cannot parse length -> stop */
			default:
				goto done; /* stop at unknown extension */
		}
	}

done:
	/* store final next_header after all extensions */
	hdr->next_header = nextHdr;
	return (offset); /* total header length including extensions */
}

size_t
parseIp6HeaderFromBuffer(const void *buf, size_t len, tIp6Hdr *outHdr)
{
	if (!buf || !outHdr || len < 40)
		return (0);

	const unsigned char *b = (const unsigned char *)buf;

	/* first 32 bits: version(4) | traffic_class(8) | flow_label(20) */
	uint32_t vtf;
	memcpy(&vtf, b, sizeof(vtf));
	vtf = ipNtohl(vtf);

	outHdr->version = (uint8_t)((vtf >> 28) & 0x0F);
	outHdr->traffic_class = (uint8_t)((vtf >> 20) & 0xFF);
	outHdr->flow_label = vtf & 0x000FFFFF;

	/* payload length (16 bits) */
	uint16_t payloadLen;
	memcpy(&payloadLen, b + 4, sizeof(payloadLen));
	outHdr->payload_len = ipNtohs(payloadLen);

	/* next header and hop limit */
	outHdr->next_header = (tIpProtocol)b[6];
	outHdr->hop_limit = b[7];

	/* source and destination addresses (16 bytes each) */
	memcpy(outHdr->saddr, b + 8, 16);
	memcpy(outHdr->daddr, b + 24, 16);

	/* parse any extension headers and return total length */
	size_t totalHdrLen = parseIp6Extensions(b, len, outHdr);

	/* if parsing failed, return 0 */
	if (totalHdrLen == 0)
		return (0);

	return (totalHdrLen);
}