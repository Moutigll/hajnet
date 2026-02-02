#ifndef HAJ_IP_H
#define HAJ_IP_H

#include "stdint.h"

#define INET_ADDRSTRLEN 16
#define INET6_ADDRSTRLEN 46

/**
 * @brief IP Protocol Numbers
 * Follows [IANA Protocol Numbers](https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml)
 */
typedef enum eIpProtocol
{
	IPPROTO_ICMP	= 1,		/* Internet Control Message Protocol */
	IPPROTO_TCP		= 6,		/* Transmission Control Protocol */
	IPPROTO_UDP		= 17,		/* User Datagram Protocol */
	IPPROTO_IPV6	= 41,		/* Internet Protocol version 6 */
	IPPROTO_ICMPV6	= 58,	/* Internet Control Message Protocol for IPv6 */
} tIpProtocol;

/**
 * @brief IP Differentiated Services Code Point (DSCP) values
 * Follows [RFC 2474](https://datatracker.ietf.org/doc/html/rfc2474#section-3)
 * DSCP is represented by the six most significant bits of the TOS/DS field.
 * It is used for packet classification and quality of service (QoS) handling.
 */
typedef enum eIpDscp
{
	IP_DSCP_DEFAULT	= 0x00, /* Best Effort */
	IP_DSCP_CS1		= 0x08, /* Class Selector 1 */
	IP_DSCP_AF11	= 0x0A, /* Assured Forwarding 11 */
	IP_DSCP_AF12	= 0x0C, /* Assured Forwarding 12 */
	IP_DSCP_AF13	= 0x0E, /* Assured Forwarding 13 */
	IP_DSCP_CS2		= 0x10, /* Class Selector 2 */
	IP_DSCP_AF21	= 0x12, /* Assured Forwarding 21 */
	IP_DSCP_AF22	= 0x14, /* Assured Forwarding 22 */
	IP_DSCP_AF23	= 0x16, /* Assured Forwarding 23 */
	IP_DSCP_CS3		= 0x18, /* Class Selector 3 */
	IP_DSCP_AF31	= 0x1A, /* Assured Forwarding 31 */
	IP_DSCP_AF32	= 0x1C, /* Assured Forwarding 32 */
	IP_DSCP_AF33	= 0x1E, /* Assured Forwarding 33 */
	IP_DSCP_CS4		= 0x20, /* Class Selector 4 */
	IP_DSCP_AF41	= 0x22, /* Assured Forwarding 41 */
	IP_DSCP_AF42	= 0x24, /* Assured Forwarding 42 */
	IP_DSCP_AF43	= 0x26, /* Assured Forwarding 43 */
	IP_DSCP_CS5		= 0x28, /* Class Selector 5 */
	IP_DSCP_EF		= 0x2E, /* Expedited Forwarding */
	IP_DSCP_CS6		= 0x30, /* Class Selector 6 */
	IP_DSCP_CS7		= 0x38, /* Class Selector 7 */
} tIpDscp;

/**
 * @brief IP Explicit Congestion Notification (ECN) values
 * Follows [RFC 3168](https://datatracker.ietf.org/doc/html/rfc3168#section-2.1)
 * ECN is represented by the two least significant bits of the TOS/DS field.
 * It indicates the congestion handling capabilities of the packet.
 */
typedef enum eIpEcn
{
	IP_ECN_NOT_ECT	= 0x00, /* Not ECN-Capable Transport */
	IP_ECN_ECT1		= 0x01, /* ECN Capable Transport (1) */
	IP_ECN_ECT0		= 0x02, /* ECN Capable Transport (0) */
	IP_ECN_CE		= 0x03, /* Congestion Experienced */
} tIpEcn;

/**
 * @brief IP Fragmentation Flags
 * Follows [RFC 791](https://datatracker.ietf.org/doc/html/rfc791#section-3.1)
 * These flags are used in the Fragment Offset field of the IPv4 header to control fragmentation.
 */
typedef enum eIpFragFlag
{
	IP_FRAG_RESERVED	= 0x8000, /* bit 0: reserved, must be 0 */
	IP_FRAG_DF			= 0x4000, /* bit 1: Don't Fragment */
	IP_FRAG_MF			= 0x2000, /* bit 2: More Fragments */
	IP_FRAG_EVIL		= 0x1000, /* Evil bit (RFC 3514) */
} tIpFragFlag;


/* -------------------- ToS/DS field ---------------- */

/**
 * @brief IPv4 Type of Service / Differentiated Services field type
 * Used to represent the TOS/DS field in IPv4 headers.
 * It is an 8-bit field combining DSCP and ECN values.
 * @enum  tIpDscp - Differentiated Services Code Point (upper 6 bits)
 * @enum  tIpEcn  - Explicit Congestion Notification (lower 2 bits)
 */
typedef uint8_t tIpTos;

/**
 * @brief Retrieve the DSCP value from a TOS byte
 * @param tos - TOS byte
 * @return DSCP value (upper 6 bits)
 */
static inline tIpDscp ipTosGetDscp(tIpTos tos) { return (tIpDscp)(tos >> 2); }

/**
 * @brief Retrieve the ECN value from a TOS byte
 * @param tos - TOS byte
 * @return ECN value (lower 2 bits)
 */
static inline tIpEcn   ipTosGetEcn(tIpTos tos)  { return (tIpEcn)(tos & 0x03); }

/**
 * @brief Create a TOS byte from DSCP and ECN values
 * @param dscp - DSCP value (upper 6 bits)
 * @param ecn - ECN value (lower 2 bits)
 * @return TOS byte combining DSCP and ECN
 */
static inline tIpTos   ipTosMake(tIpDscp dscp, tIpEcn ecn) { return (tIpTos)((dscp << 2) | (ecn & 0x03)); }


/* -------------------- Fragment Offset field ---------------- */

/**
 * @brief IP Fragment Offset union
 * Represents the Fragment Offset field in the IPv4 header.
 * Contains bit fields for offset and fragmentation flags.
 */
typedef union uIpFragOff
{
	uint16_t raw;
	struct
	{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
		uint16_t offset :13;
		uint16_t evil   :1;
		uint16_t mf     :1;
		uint16_t df     :1;
#else
		uint16_t df     :1;
		uint16_t mf     :1;
		uint16_t evil   :1;
		uint16_t offset :13;
#endif
	} bits;
} tIpFragOff;

/* ------------------- IPV4 OPTIONS ------------------ */

/**
 * @brief IP Option Types
 * Follows [RFC 791](https://datatracker.ietf.org/doc/html/rfc791#section-3.1)
 * These are the standard option types that can be included in the IPv4 header.
 */
typedef enum eIpOptionType
{
	IP_OPT_EOL		= 0,	/* End of Option List */
	IP_OPT_NOP		= 1,	/* No Operation */
	IP_OPT_RR		= 7,	/* Record Route */
	IP_OPT_TS		= 68,	/* Timestamp */
	IP_OPT_SS		= 137,	/* Strict Source Route */
	IP_OPT_LSRR		= 131,	/* Loose Source Route */
	IP_OPT_SECURITY	= 130	/* Security - see RFC 1108 */
} tIpOptionType;

/**
 * @brief IP Option structure
 * Represents an IPv4 option.
 * - type: Option Type
 * - length: Option Length
 * - data: Option Data (up to 40 bytes)
 */
typedef struct sIpOption
{
	tIpOptionType	type;		/* Option Type */
	uint8_t			length;		/* Option Length */
	uint8_t			data[40];	/* Option Data (max 40 bytes) */
} tIpOption;

/* -------------------- IP Headers ------------------- */

/**
 * @brief IPv4 Header structure
 * Follows [RFC 791](https://datatracker.ietf.org/doc/html/rfc791#section-3.1)
 * Contains the fields of an IPv4 header.
 * - version: IP version (4 bits)
 * - ihl: Internet Header Length (4 bits)
 * - tos: Type of Service
 * - tot_len: Total Length of the IP packet
 * - id: Identification
 * - frag_off: Fragment Offset
 * - ttl: Time to Live
 * - protocol: Protocol
 * - check: Header Checksum
 * - saddr: Source Address
 * - daddr: Destination Address
 */
typedef struct sIpHdr
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ /* Arrange IPv4 version and IHL fields according to host byte order */
	uint8_t		ihl:4;		/* Internet Header Length */
	uint8_t 	version:4;	/* IP version */
#else
	uint8_t		version:4;
	uint8_t		ihl:4;
#endif
	tIpTos		tos;		/* Type of Service (8 bits, byte 1): indicates the quality of service desired, now used for DSCP and ECN. */
	uint16_t	tot_len;	/* Total Length (16 bits, bytes 2–3): total size of IPv4 datagram including header + payload, min=20, max=65535, used for fragmentation and to determine packet boundaries. */
	uint16_t	id;			/* Identification (16 bits, bytes 4–5): unique value to identify fragments of the same original IPv4 datagram; used during fragmentation/reassembly, wraps around at 65535. */
	tIpFragOff fragOff;		/* Fragment Offset (16 bits, bytes 6–7): indicates where in the datagram this fragment belongs; also contains flags for fragmentation control. */
	uint8_t		ttl;		/* Time to Live (8 bits, byte 8): limits the packet's lifetime to prevent infinite looping; decremented by each router, packet discarded when it reaches 0. */
	tIpProtocol	protocol;	/* Protocol (8 bits, byte 9): indicates the protocol used in the data portion (e.g., TCP=6, UDP=17, ICMP=1). */
	uint16_t	check;		/* Header Checksum (16 bits, bytes 10–11): used for error-checking of the header. */
	uint32_t	saddr;		/* Source Address (32 bits, bytes 12–15): IPv4 address of the sender. */
	uint32_t	daddr;		/* Destination Address (32 bits, bytes 16–19): IPv4 address of the receiver. */
	tIpOption	options[10];/* IPv4 Options (up to 40 bytes) */

} tIpHdr;

/**
 * @brief IPv6 Header structure
 * Follows [RFC 8200](https://datatracker.ietf.org/doc/html/rfc8200#section-3)
 * Contains the fields of an IPv6 header.
 * - version: IP version (4 bits)
 * - traffic_class: Traffic Class (8 bits)
 * - flow_label: Flow Label (20 bits)
 * - payload_len: Payload Length
 * - next_header: Next Header
 * - hop_limit: Hop Limit
 * - saddr: Source Address
 * - daddr: Destination Address
 */
typedef struct sIp6Hdr
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	uint32_t	flow_label:20;		/* Flow Label (20 bits): used for labeling sequences of packets for special handling, such as real-time services. */
	uint32_t	traffic_class:8;	/* Traffic Class (8 bits): used for differentiated services and explicit congestion notification. */
	uint32_t	version:4;			/* IP version (4 bits): set to 6 for IPv6. */
#else
	uint32_t	version:4;		/* IP version (4 bits): set to 6 for IPv6. */
	uint32_t	traffic_class:8;/* Traffic Class (8 bits): used for differentiated services and explicit congestion notification. */
	uint32_t	flow_label:20;	/* Flow Label (20 bits): used for labeling sequences of packets for special handling, such as real-time services. */
#endif
	uint16_t	payload_len;	/* Length of payload following IPv6 header */
	tIpProtocol	next_header;	/* Type of next header in the OSI model eg. TCP, UDP, ICMPv6 */
	uint8_t		hop_limit;		/* Maximum number of hops packet can traverse */
	uint8_t		saddr[16];		/* Source IPv6 address */
	uint8_t		daddr[16];		/* Destination IPv6 address */
} tIp6Hdr;



/* ----------------- Byte Order Conversion ----------------- */

/**
 * @brief Host to Network Short conversion
 * Converts a 16-bit integer from host byte order to network byte order (big-endian).
 * @param x - value to convert
 * @return The converted value
 */
static inline uint16_t htons(uint16_t x)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	return ((x << 8) | (x >> 8));
#else
	return (x);
#endif
}

/**
 * @brief Network to Host Short conversion
 * Converts a 16-bit integer from network byte order (big-endian) to host byte order.
 * @param x - value to convert
 * @return The converted value
 */
static inline uint16_t ntohs(uint16_t x)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	return ((x << 8) | (x >> 8));
#else
	return (x);
#endif
}

/**
 * @brief Host to Network Long conversion
 * Converts a 32-bit integer from host byte order to network byte order (big-endian).
 * @param x - value to convert
 * @return The converted value
 */
static inline uint32_t htonl(uint32_t x)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	return (
			((x << 24) & 0xFF000000) |
			((x << 8)  & 0x00FF0000) |
			((x >> 8)  & 0x0000FF00) |
			((x >> 24) & 0x000000FF) );
#else
	return (x);
#endif
}

/**
 * @brief Network to Host Long conversion
 * Converts a 32-bit integer from network byte order (big-endian) to host byte order.
 * @param x - value to convert
 * @return The converted value
 */
static inline uint32_t ntohl(uint32_t x)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	return (
			((x << 24) & 0xFF000000) |
			((x << 8)  & 0x00FF0000) |
			((x >> 8)  & 0x0000FF00) |
			((x >> 24) & 0x000000FF) );
#else
	return (x);
#endif
}

/* ------------------ IP Header Printing ------------------ */

/**
 * @brief Print IPv4 header information in a human-readable format
 * @param hdr - pointer to IPv4 header
 */
void printIpv4Header(const tIpHdr *hdr);

#endif /* HAJ_IP_H */