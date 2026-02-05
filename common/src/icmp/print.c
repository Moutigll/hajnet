#include <stdio.h>
#include <string.h>

#include "../../includes/ip.h"
#include "../../includes/icmp.h"

#define ICMP_HEX_BYTES_PER_LINE 10

/* ----------------- ASCII BOX ----------------- */
#define ICMP4_TAB_HEADER "\
Oct - Bits 0                       1                      2                       3\n\
           0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31\n\
          ┌───────────────────────┬───────────────────────┬─────────────────────────────────────────────┐\n"

#define ICMP4_TAB_FOOTER "          └─────────────────────────────────────────────────────────────────────────────────────────────┘\n"
#define ICMP4_ROW_SEPARATOR " ├───────────────────────┼───────────────────────┼─────────────────────────────────────────────┤\n"

/* -------------------- Type / Code Name -------------------- */
const char
*icmp4TypeName(uint8_t type)
{
	switch (type)
	{
		case ICMP4_ECHO_REPLY:		return "Echo Reply";
		case ICMP4_ECHO_REQUEST:	return "Echo Request";
		case ICMP4_DEST_UNREACH:	return "Dest Unreach";
		case ICMP4_TIME_EXCEEDED:	return "Time Exceeded";
		case ICMP4_REDIRECT:		return "Redirect";
		default:					return "Unknown";
	}
}

const char
*icmp4CodeName(uint8_t type, uint8_t code)
{
	if (type == ICMP4_DEST_UNREACH)
	{
		switch (code)
		{
			case ICMP4_NET_UNREACH:	return "Net Unreach";
			case ICMP4_HOST_UNREACH:return "Host Unreach";
			case ICMP4_PORT_UNREACH:return "Port Unreach";
			default:				return "Unknown DU";
		}
	}
	if (type == ICMP4_TIME_EXCEEDED)
	{
		switch (code)
		{
			case ICMP4_TTL_EXCEEDED:	return "Time to live Exceeded";
			default:					return "Unknown TE";
		}
	}
	return "No code";
}

/* -------------------- Hex Dump -------------------- */

static void
printHexData(const uint8_t *data, size_t len)
{
	size_t offset = 0;

	while (offset < len)
	{
		size_t count = (len - offset > ICMP_HEX_BYTES_PER_LINE)
			? ICMP_HEX_BYTES_PER_LINE
			: len - offset;

		printf("          │      HEX: ");
		for (size_t i = 0; i < count; ++i)
			printf("%02X ", data[offset + i]);
		printf("                     ASCII: [");
		for (size_t i = 0; i < count; ++i)
		{
			uint8_t byte = data[offset + i];
			if (byte >= 32 && byte <= 126)
				printf("%c", byte);
			else
				printf(".");
		}
		printf("]            │\n");
		offset += count;
	}
}

/* -------------------- ICMPv4 Content Printers -------------------- */

static void
printIcmp4Echo(const tIcmp4Echo *echo, size_t dataLen)
{
	printf("          ├───────────────────────┴───────────────────────┼─────────────────────────────────────────────┤\n");
	printf("          │                  Identifier                   │                  Sequence                   │\n");
	printf("  4 -  32 ├───────────────────────────────────────────────┼─────────────────────────────────────────────┤\n");
	printf("          │	              0x%04X                      │                   0x%04X                    │\n",
		ipNtohs(echo->id),
		ipNtohs(echo->sequence));
	printf("          ├───────────────────────────────────────────────┴─────────────────────────────────────────────┤\n");
	printf("          │                                              Data                                           │\n");
	printf("  8 -  64 ├─────────────────────────────────────────────────────────────────────────────────────────────┤\n");
	printHexData(echo->data, dataLen);
	printf(ICMP4_TAB_FOOTER);
}

static void
printIcmp4Error(const tIcmp4Error *err)
{
	printf("          ├───────────────────────┴───────────────────────┼─────────────────────────────────────────────┤\n");
	printf("          │                       Unused                  │                     Original IP             │\n");
	printf("  4 -  32 ├───────────────────────────────────────────────┼─────────────────────────────────────────────┤\n");
	printf("          │                       0x%08X              │                                             │\n",
		ipNtohl(err->unused));
	printf("          ├───────────────────────────────────────────────┴─────────────────────────────────────────────┤\n");
	printf("          │                                        Original IP Data                                     │\n");
	printf("  8 -  64 ├─────────────────────────────────────────────────────────────────────────────────────────────┤\n");
	printHexData(err->original_ip, sizeof(err->original_ip));
	printf(ICMP4_TAB_FOOTER);
}

static void
printIcmp4Redirect(const tIcmp4Redirect *redir, size_t origLen)
{
	printf(" │ Gateway │\n");
	printf(" │ %u.%u.%u.%u │\n",
		(redir->gateway >> 24) & 0xFF,
		(redir->gateway >> 16) & 0xFF,
		(redir->gateway >> 8) & 0xFF,
		redir->gateway & 0xFF);
	printf(ICMP4_ROW_SEPARATOR);
	printHexData(redir->original_ip, origLen);
	printf(ICMP4_TAB_FOOTER);
}

/* -------------------- ICMPv4 Header -------------------- */

void
printIcmp4Header(const tIcmp4Hdr *hdr)
{
	if (!hdr)
		return;

	const char *typeText = icmp4TypeName(hdr->type);
	const char *codeText = icmp4CodeName(hdr->type, hdr->code);

	printf(ICMP4_TAB_HEADER);
	printf("          │         Type          │         Code          │                  Checksum                   │\n");
	printf("  0 -   0" ICMP4_ROW_SEPARATOR);
	printf("          │ %-3u %-13s     │ %-3u %-15s   │                   0x%04X                    │\n",
		hdr->type, typeText,
		hdr->code, codeText,
		ipNtohs(hdr->checksum));
}

/* -------------------- Dispatcher -------------------- */

void
printIcmp4Packet(const void *pkt, uint32_t len)
{
	const tIcmp4Hdr *hdr = (const tIcmp4Hdr *)pkt;

	printIcmp4Header(hdr);

	switch (hdr->type)
	{
		case ICMP4_ECHO_REQUEST:
		case ICMP4_ECHO_REPLY:
		{
			if (len < sizeof(tIcmp4Echo))
				break;
			printIcmp4Echo((const tIcmp4Echo *)pkt, len - sizeof(tIcmp4Echo));
			break;
		}
		case ICMP4_DEST_UNREACH:
		case ICMP4_TIME_EXCEEDED:
		{
			if (len < sizeof(tIcmp4Error))
				break;
			printIcmp4Error((const tIcmp4Error *)pkt);
			break;
		}
		case ICMP4_REDIRECT:
		{
			if (len < sizeof(tIcmp4Redirect))
				break;
			printIcmp4Redirect((const tIcmp4Redirect *)pkt, len - sizeof(tIcmp4Redirect));
			break;
		}
		default:
			break;
	}
}

const char *
icmp6TypeName(uint8_t type)
{
	switch (type)
	{
		case ICMP6_ECHO_REQUEST:	return "Echo Request";
		case ICMP6_ECHO_REPLY:		return "Echo Reply";
		case ICMP6_DEST_UNREACH:		return "Destination Unreachable";
		case ICMP6_PACKET_TOO_BIG:	return "Packet Too Big";
		case ICMP6_TIME_EXCEEDED:	return "Time Exceeded";
		case ICMP6_PARAM_PROBLEM:		return "Parameter Problem";
		default:					return "Unknown";
	}
}

const char *
icmp6CodeName(uint8_t type, uint8_t code)
{
	if (type == ICMP6_TIME_EXCEEDED)
	{
		switch (code)
		{
			case ICMP6_HOP_LIMIT_EXCEEDED:
				return "Hop limit exceeded";
			case ICMP6_REASSEMBLY_EXCEEDED:
				return "Fragment reassembly time exceeded";
			default:
				return "Unknown TE";
		}
	}
	if (type == ICMP6_DEST_UNREACH)
	{
		switch (code)
		{
			case ICMP6_NO_ROUTE:			return "No route to destination";
			case ICMP6_ADMIN_PROHIBITED:	return "Administratively prohibited";
			case ICMP6_BEYOND_SCOPE:		return "Beyond scope";
			case ICMP6_ADDR_UNREACH:		return "Address unreachable";
			case ICMP6_PORT_UNREACH:		return "Port unreachable";
			default:						return "Unknown DU";
		}
	}
	return "No code";
}
