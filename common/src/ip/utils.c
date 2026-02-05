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
