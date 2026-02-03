#include <stdio.h>

#include "../../includes/ip.h"

#define IP4_TAB_HEADER "\n\
Oct - Bits 0                       1                      2                       3\n\
           0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31\n\
          ┌───────────┬───────────┬───────────────────────┬───────────────────────────────────────────────┐\n"


static const char *
ipV4FlagToStr(uint16_t flags)
{
	if (flags & IP_FRAG_EVIL)
		return " ( ◺˰◿ )";
	if (flags & IP_FRAG_DF && flags & IP_FRAG_MF)
		return " DF + MF ";
	if (flags & IP_FRAG_DF)
		return "   DF   ";
	if (flags & IP_FRAG_MF)
		return "   MF   ";
	return "  NONE  ";
}

static const char *
ipProtoToStr(tIpProtocol proto)
{
	switch (proto)
	{
		case IP_PROTO_ICMP: return "ICMP";
		case IP_PROTO_TCP:  return "TCP";
		case IP_PROTO_UDP:  return "UDP";
		case IP_PROTO_IPV6: return "IPv6";
		case IP_PROTO_ICMPV6: return "ICMPv6";
		default:           return "UNKNOWN";
	}
}

static const char
*ipV4ToStr(uint32_t addr)
{
	static char	str[16];
	snprintf(str, sizeof(str), "%u.%u.%u.%u",
		(addr >> 24) & 0xFF,
		(addr >> 16) & 0xFF,
		(addr >> 8) & 0xFF,
		addr & 0xFF);
	return (str);
}

static const char
*ip4OptToStr(tIpOptionType type)
{
	switch (type)
	{
		case IP_OPT_EOL:		return "End of Option List";
		case IP_OPT_NOP:		return "No Operation";
		case IP_OPT_RR:			return "Record Route";
		case IP_OPT_TS:			return "Timestamp";
		case IP_OPT_SECURITY:	return "Security";
		case IP_OPT_LSRR:		return "Loose Source and Record Route";
		default:			return "Unknown Option";
	}
}

static void
printIp4Options(const tIpHdr *hdr)
{
	int i;
	printf("IPv4 Options:\n");
	for (i = 0; i < 10; i++)
	{
		if (hdr->options[i].length == 0)
			continue;
		printf(" Option %d: Type=0x%02X - %s\n    Length=%u\n    Data=[", i, hdr->options[i].type, ip4OptToStr(hdr->options[i].type), hdr->options[i].length);
		for (int j = 0; j < hdr->options[i].length; j++)
		{
			printf("0x%02X", hdr->options[i].data[j]);
			if (j < hdr->options[i].length - 1)
				printf(" ");
		}
		printf("]\n");
	}
}

void printIpv4Header(const tIpHdr *hdr)
{
	uint8_t	dscp = ipTosGetDscp(hdr->tos);
	uint8_t	ecn  = ipTosGetEcn(hdr->tos);

	printf("IPv4 Header:\n%s", IP4_TAB_HEADER);
	printf("          │  Version  │    IHL    │          TOS          │                 Total Length                  │\n");
	printf("  0 -   0 ├───────────┼───────────┼────────────────┬──────┼───────────────────────────────────────────────┤\n");
	printf("          │     %-3u   │  %-2u bytes │ DSCP:0x%02X  ECN:│ 0x%02X │		   %-5u bytes                    │\n",
		hdr->version,
		hdr->ihl,
		dscp, ecn,
		ipNtohs(hdr->tot_len));
	printf("          ├───────────┴───────────┴────────────────┴──────┼────────┬──────────────────────────────────────┤\n");
	printf("          │                Identification                 │  Flags │           Fragment Offset            │\n");
	printf("  4 -  32 ├───────────────────────────────────────────────┼────────┼──────────────────────────────────────┤\n");
	printf("          │    dec: %-5u    hex: 0x%04X  ascii: [%-4s]   │%s│              %-5u                   │\n",
		ipNtohs(hdr->id),
		ipNtohs(hdr->id),
		(char *)&hdr->id,
		ipV4FlagToStr(hdr->fragOff.raw & 0xF000),
		ipNtohs(hdr->fragOff.raw & 0x1FFF));
	printf("          ├───────────────────────┬───────────────────────┼────────┴──────────────────────────────────────┤\n");
	printf("          │         TTL           │      Protocol         │                  Header Checksum              │\n");
	printf("  8 -  64 ├───────────────────────┼───────────────────────┼───────────────────────────────────────────────┤\n");
	printf("          │         %-3u           │     0x%02X - %-10s │                  0x%04X                       │\n",
		hdr->ttl,
		hdr->protocol,
		ipProtoToStr(hdr->protocol),
		ipNtohs(hdr->check));
	printf("          ├───────────────────────┴───────────────────────┴───────────────────────────────────────────────┤\n");
	printf("          │                                        Source Address                                         │\n");
	printf(" 12 -  96 ├───────────────────────────────────────────────────────────────────────────────────────────────┤\n");
	printf("          │                                    %15s                                            │\n",
		ipV4ToStr(ipNtohl(hdr->saddr)));
	printf("          ├───────────────────────────────────────────────────────────────────────────────────────────────┤\n");
	printf("          │                                     Destination Address                                       │\n");
	printf(" 16 - 128 ├───────────────────────────────────────────────────────────────────────────────────────────────┤\n");
	printf("          │                                    %15s                                            │\n",
		ipV4ToStr(ipNtohl(hdr->daddr)));
	printf("          └───────────────────────────────────────────────────────────────────────────────────────────────┘\n");
	printIp4Options(hdr);
}
