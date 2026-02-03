#include "../../includes/ip.h"

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
