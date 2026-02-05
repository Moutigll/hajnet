#ifndef HAJ_ICMP_H
#define HAJ_ICMP_H


#include <netinet/in.h>
#include <sys/time.h>

#include "stdint.h"

/* ----------------- ICMPv4 Definitions ----------------- */

#define ICMP_TIMESTAMP_SIZE 8
#define ICMP4_HDR_LEN 8
#define ICMP6_HDR_LEN 8

/**
 * @brief ICMPv4 Message Types
 * RFC 792
 * - The following are the standard ICMPv4 message types.
 */
typedef enum eIcmp4Type
{
	ICMP4_ECHO_REPLY			= 0,	/* Echo Reply, used to respond to an Echo Request message. */
	/* The values 1-2 are unassigned and reserved */
	ICMP4_DEST_UNREACH			= 3,	/* Destination Unreachable, indicates that a destination is unreachable for various reasons. */
	ICMP4_SOURCE_QUENCH			= 4,	/* Source Quench, used to inform a sender to reduce its transmission rate. */
	ICMP4_REDIRECT				= 5,	/* Redirect, used to inform a host of a better route for a particular destination. */
	/* The value 6 is reserved for alternate host address (obsolete) */
	/* The value 7 is unassigned and reserved */
	ICMP4_ECHO_REQUEST			= 8,	/* Echo Request, used to test reachability of a host. */
	ICMP4_ROUTER_ADVERT			= 9,	/* Router Advertisement, used by routers to advertise their presence along with various link and Internet parameters. */
	ICMP4_ROUTER_SOLICIT		= 10,	/* Router Solicitation, used by hosts to request routers to generate Router Advertisements immediately rather than at their next scheduled time. */
	ICMP4_TIME_EXCEEDED			= 11,	/* Time Exceeded, indicates that the Time to Live (TTL) of a packet has expired. */
	ICMP4_PARAM_PROBLEM			= 12,	/* Parameter Problem, indicates that there was an error in the header parameters of a packet. */
	ICMP4_TIMESTAMP				= 13,	/* Timestamp Request, used to request the current time from a host. */
	ICMP4_TIMESTAMP_REPLY		= 14,	/* Timestamp Reply, used to respond to a Timestamp Request message. */
	ICMP4_INFO_REQUEST			= 15,	/* Information Request, used to request information from a host. */
	ICMP4_INFO_REPLY			= 16,	/* Information Reply, used to respond to an Information Request message. */
	ICMP4_ADDRESS_MASK_REQUEST	= 17,	/* Address Mask Request, used to request the subnet mask from a host. */
	ICMP4_ADDRESS_MASK_REPLY	= 18,	/* Address Mask Reply, used to respond to an Address Mask Request message. */
	/* The value 19 is reserved for security */
	/* The values 20-29 are unassigned and reserved */
	ICMP4_TRACEROUTE			= 30,	/* Traceroute, used to trace the route packets take to a destination. */
	ICMP4_CONVERSION_ERROR		= 31,	/* Conversion Error, indicates an error in converting between different address formats. */
	ICMP4_MOBILE_REDIRECT		= 32,	/* Mobile Redirect, used in mobile IP to inform a mobile node of a better care-of address. */
	/* The values 33-39 are mostly deprecated */
	ICMP4_PHOTURIS				= 40,	/* Photuris, used for security association management (deprecated). */
	ICMP4_EXPERIMENTAL_41		= 41,	/* Experimental Measurement */
	ICMP4_EXTENDED_ECHO_REQUEST = 42,	/* Extended Echo Request, used for enhanced echo functionality. */
	ICMP4_EXTENDED_ECHO_REPLY   = 43,	/* Extended Echo Reply, used to respond to an Extended Echo Request message. */
	/* The values 44-252 are unassigned and reserved */
	/* The values 253-254 are reserved for experimentation and testing */
	/* The value 255 is reserved */
} tIcmp4Type;

/**
 * @brief ICMPv4 Destination Unreachable Codes
 */
typedef enum eIcmp4DestUnreachCode
{
	ICMP4_NET_UNREACH			= 0,	/* Network Unreachable, indicates that the destination network is unreachable. */
	ICMP4_HOST_UNREACH			= 1,	/* Host Unreachable, indicates that the destination host is unreachable. */
	ICMP4_PROTO_UNREACH			= 2,	/* Protocol Unreachable, indicates that the specified protocol is not supported at the destination. */
	ICMP4_PORT_UNREACH			= 3,	/* Port Unreachable, indicates that the specified port is not open at the destination. */
	ICMP4_FRAG_NEEDED			= 4,	/* Fragmentation Needed and Don't Fragment was Set, indicates that fragmentation is required but the Don't Fragment flag is set. */
	ICMP4_SR_FAILED				= 5,	/* Source Route Failed, indicates that the source route specified in the packet could not be followed. */
	ICMP4_NET_UNKNOWN			= 6,	/* Network Unknown, indicates that the destination network is unknown. */
	ICMP4_HOST_UNKNOWN			= 7,	/* Host Unknown, indicates that the destination host is unknown. */
	ICMP4_HOST_ISOLATED			= 8,	/* Host Isolated, indicates that the destination host is isolated and cannot be reached. */
	ICMP4_NET_PROHIBITED		= 9,	/* Network Administratively Prohibited, indicates that the destination network is administratively prohibited. */
	ICMP4_HOST_PROHIBITED		= 10,	/* Host Administratively Prohibited, indicates that the destination host is administratively prohibited. */
	ICMP4_TOS_NET_UNREACH		= 11,	/* Network Unreachable for Type of Service, indicates that the destination network is unreachable for the specified type of service. */
	ICMP4_TOS_HOST_UNREACH		= 12,	/* Host Unreachable for Type of Service, indicates that the destination host is unreachable for the specified type of service. */
	ICMP4_COMM_PROHIBITED		= 13,	/* Communication Administratively Prohibited, indicates that communication is administratively prohibited. */
	ICMP4_HOST_PRECEDENCE_VIO	= 14,	/* Host Precedence Violation, indicates that the precedence of the packet is not allowed. */
	ICMP4_PRECEDENCE_CUTOFF		= 15	/* Precedence Cutoff in Effect, indicates that the packet's precedence is below the cutoff level. */
} tIcmp4DestUnreachCode;

/**
 * @brief ICMPv4 Redirect Messages Codes
 */
typedef enum eIcmp4RedirectCode
{
	ICMP4_REDIRECT_NET		= 0,	/* Redirect Datagram for the Network */
	ICMP4_REDIRECT_HOST		= 1,	/* Redirect Datagram for the Host */
	ICMP4_REDIRECT_TOS_NET	= 2,	/* Redirect Datagram for the Type of Service and Network */
	ICMP4_REDIRECT_TOS_HOST	= 3		/* Redirect Datagram for the Type of Service and Host */
} tIcmp4RedirectCode;

/**
 * @brief ICMPv4 Time Exceeded Codes
 */
typedef enum eIcmp4TimeExceededCode
{
	ICMP4_TTL_EXCEEDED			= 0,
	ICMP4_REASSEMBLY_EXCEEDED	= 1
} tIcmp4TimeExceededCode;

/**
 * @brief ICMPv4 Generic Header
 * Follows [RFC 792](https://datatracker.ietf.org/doc/html/rfc792#section-3)
 * Contains the common fields for all ICMPv4 messages.
 */
typedef struct sIcmp4Hdr
{
	uint8_t		type;		/* ICMPv4 Message Type */
	uint8_t		code;		/* ICMPv4 Message Code */
	uint16_t	checksum;	/* ICMPv4 Checksum */
} tIcmp4Hdr;

/**
 * @brief ICMPv4 Echo (Request / Reply)
 */
typedef struct sIcmp4Echo
{
	tIcmp4Hdr	hdr;
	uint16_t	id;			/* Identifier */
	uint16_t	sequence;	/* Sequence Number */
	uint8_t		data[];
} tIcmp4Echo;

/**
 * @brief ICMPv4 Destination Unreachable
 */
typedef struct sIcmp4DestUnreach
{
	tIcmp4Hdr	hdr;
	uint32_t	unused;			/* Unused field, set to zero */
	uint8_t		original_ip[];	/* Original IP header and first 8 bytes of original payload */
} tIcmp4DestUnreach;

/**
 * @brief ICMPv4 Time Exceeded
 */
typedef struct sIcmp4TimeExceeded
{
	tIcmp4Hdr	hdr;
	uint32_t	unused;			/* Unused field, set to zero */
	uint8_t		original_ip[];	/* Original IP header and first 8 bytes of original payload */
} tIcmp4TimeExceeded;

/**
 * @brief ICMPv4 Redirect
 */
typedef struct sIcmp4Redirect
{
	tIcmp4Hdr	hdr;
	uint32_t	gateway;		/* Gateway Internet Address */
	uint8_t		original_ip[];	/* Original IP header and first 8 bytes of original payload */
} tIcmp4Redirect;

/**
 * @brief ICMPv4 Error Message
 */
typedef struct sIcmp4Error
{
	tIcmp4Hdr	hdr;
	uint32_t	unused;				/* Unused field, set to zero */
	uint8_t		original_ip[16];	/* Original IP header and first 8 bytes of original payload */
} tIcmp4Error;

/**
 * @brief ICMPv4 Timestamp Request / Reply
 */
typedef struct sIcmp4Timestamp
{
	tIcmp4Hdr	hdr;			/* ICMP Header */
	uint16_t	id;				/* Identifier */
	uint16_t	sequence;		/* Sequence number */
	uint32_t	originateTs;	/* Originate Timestamp (ms since midnight UTC) */
	uint32_t	receiveTs;		/* Receive Timestamp */
	uint32_t	transmitTs;		/* Transmit Timestamp */
} tIcmp4Timestamp;


/* ----------------- ICMPv6 Definitions ----------------- */

/**
 * @brief ICMPv6 Message Types
 * RFC 4443 / 4861
 */
typedef enum eIcmp6Type
{
	ICMP6_DEST_UNREACH		= 1,
	ICMP6_PACKET_TOO_BIG	= 2,
	ICMP6_TIME_EXCEEDED		= 3,
	ICMP6_PARAM_PROBLEM		= 4,
	ICMP6_ECHO_REQUEST		= 128,
	ICMP6_ECHO_REPLY		= 129,
	ICMP6_ROUTER_SOLICIT	= 133,
	ICMP6_ROUTER_ADVERT		= 134,
	ICMP6_NEIGHBOR_SOLICIT	= 135,
	ICMP6_NEIGHBOR_ADVERT	= 136,
	ICMP6_REDIRECT			= 137
} tIcmp6Type;

/**
 * @brief ICMPv6 Destination Unreachable Codes
 */
typedef enum eIcmp6DestUnreachCode
{
	ICMP6_NO_ROUTE			= 0,
	ICMP6_ADMIN_PROHIBITED	= 1,
	ICMP6_BEYOND_SCOPE		= 2,
	ICMP6_ADDR_UNREACH		= 3,
	ICMP6_PORT_UNREACH		= 4
} tIcmp6DestUnreachCode;

/**
 * @brief ICMPv6 Time Exceeded Codes
 */
typedef enum eIcmp6TimeExceededCode
{
	ICMP6_HOP_LIMIT_EXCEEDED	= 0,
	ICMP6_REASSEMBLY_EXCEEDED	= 1
} tIcmp6TimeExceededCode;

/**
 * @brief ICMPv6 Generic Header
 */
typedef struct sIcmp6Hdr
{
	uint8_t		type;
	uint8_t		code;
	uint16_t	checksum;
} tIcmp6Hdr;

/**
 * @brief ICMPv6 Echo
 */
typedef struct sIcmp6Echo
{
	tIcmp6Hdr	hdr;
	uint16_t	id;
	uint16_t	sequence;
	uint8_t		data[];
} tIcmp6Echo;

/* ---------------- ICMPv6 Neighbor Discovery ----------------- */

/**
 * @brief ND Options Types
 * RFC 4861
 * - These are the standard Neighbor Discovery option types.
 */
typedef enum eIcmp6NdOptionType
{
	ICMP6_ND_OPT_SRC_LL_ADDR	= 1,	/* Source Link-Layer Address */
	ICMP6_ND_OPT_TGT_LL_ADDR	= 2,	/* Target Link-Layer Address */
	ICMP6_ND_OPT_PREFIX_INFO	= 3,	/* Prefix Information */
	ICMP6_ND_OPT_REDIRECT_HDR	= 4,	/* Redirected Header */
	ICMP6_ND_OPT_MTU			= 5		/* MTU, Maximum Transmission Unit */
} tIcmp6NdOptionType;

/**
 * @brief ICMPv6 Neighbor Solicitation
 */
typedef struct sIcmp6NeighborSolicit
{
	tIcmp6Hdr	hdr;
	uint32_t	reserved;			/* Reserved */
	uint8_t		target_addr[16];	/* Target Address */
	uint8_t		options[];			/* Options */
} tIcmp6NeighborSolicit;

/**
 * @brief ICMPv6 Neighbor Advertisement
 */
typedef struct sIcmp6NeighborAdvert
{
	tIcmp6Hdr	hdr;
	uint32_t	flags;				/* Flags, including Router, Solicited, and Override */
	uint8_t		target_addr[16];	/* Target Address */
	uint8_t		options[];			/* Options */
} tIcmp6NeighborAdvert;

/**
 * @brief ICMPv6 Router Solicitation
 */
typedef struct sIcmp6RouterSolicit
{
	tIcmp6Hdr	hdr;
	uint32_t	reserved;	/* Reserved */
	uint8_t		options[];	/* Options */
} tIcmp6RouterSolicit;

/**
 * @brief ICMPv6 Router Advertisement
 */
typedef struct sIcmp6RouterAdvert
{
	tIcmp6Hdr	hdr;
	uint8_t		curHopLimit;	/* Current Hop Limit */
	uint8_t		flags;			/* Flags */
	uint16_t	routerLifetime;	/* Router Lifetime */
	uint32_t	reachableTime;	/* Reachable Time */
	uint32_t	retransTimer;	/* Retransmission Timer */
	uint8_t		options[];		/* Options */
} tIcmp6RouterAdvert;

/* ----------------- ICMP Functions ----------------- */

/**
 * @brief Compute ICMP checksum (v4 / v6 payload only)
 * @param data - pointer to ICMP message
 * @param len - length in bytes
 * @return checksum
 */
uint16_t icmpChecksum(const void *data, uint32_t len);

/**
 * @brief Build ICMPv4 Echo Request packet
 * @param req - pointer to ICMPv4 Echo structure to fill
 * @param bufferSize - size of the buffer pointed to by req
 * @param id - Identifier
 * @param seq - Sequence Number
 * @param payload - pointer to payload data
 * @param payloadLen - length of payload data in bytes
 * @return total length of the ICMPv4 Echo Request packet, or 0 on error
 */
uint32_t buildIcmpv4EchoRequest(
	tIcmp4Echo	*req,
	uint32_t	bufferSize,
	uint16_t	id,
	uint16_t	seq,
	const void	*payload,
	uint32_t	payloadLen);

/**
 * @brief Parse ICMPv4 header from raw data
 * @param data - pointer to raw data
 * @param len - length of the data in bytes
 * @return pointer to ICMPv4 header structure, or NULL on error
 */
const tIcmp4Hdr *icmp4ParseHeader(const void *data, uint32_t len);

/**
 * @brief Parse ICMPv4 Echo message from raw data
 * @param data - pointer to raw data
 * @param len - length of the data in bytes
 * @return pointer to ICMPv4 Echo structure, or NULL on error
 */
const tIcmp4Echo *icmp4ParseEcho(const void *data, uint32_t len);

/**
 * @brief Build ICMPv4 Timestamp Request packet
 * @param req - pointer to ICMPv4 Timestamp structure to fill
 * @param bufferSize - size of the buffer pointed to by req
 * @param id - Identifier
 * @param seq - Sequence Number
 * @param originateTs - Originate Timestamp (ms since midnight UTC)
 * @return total length of the ICMPv4 Timestamp Request packet, or 0 on error
 */
uint32_t buildIcmpv4TimestampRequest(
	tIcmp4Timestamp	*req,
	uint32_t		bufferSize,
	uint16_t		id,
	uint16_t		seq,
	uint32_t		originateTs);

/**
 * @brief Parse ICMPv4 Timestamp message from raw data
 * @param data - pointer to raw data
 * @param len - length of the data in bytes
 * @return pointer to ICMPv4 Timestamp structure, or NULL on error
 */
const tIcmp4Timestamp *icmp4ParseTimestamp(const void *data, uint32_t len);

/* ----------------- ICMPv6 Functions ----------------- */

/**
 * @brief Compute ICMPv6 checksum
 * @param src - pointer to source IPv6 address
 * @param dst - pointer to destination IPv6 address
 * @param data - pointer to ICMPv6 message
 * @param len - length in bytes
 * @return checksum
 */
uint16_t icmpv6Checksum(
	const struct in6_addr	*src,
	const struct in6_addr	*dst,
	const void				*data,
	uint32_t				len);

/**
 * @brief Build ICMPv6 Echo Request packet
 * @param req - pointer to ICMPv6 Echo structure to fill
 * @param bufferSize - size of the buffer pointed to by req
 * @param id - Identifier
 * @param seq - Sequence Number
 * @param payload - pointer to payload data
 * @param payloadLen - length of payload data in bytes
 * @param src - pointer to source IPv6 address
 * @param dst - pointer to destination IPv6 address
 * @param doChecksum - whether to compute and set the checksum
 * @return total length of the ICMPv6 Echo Request packet, or 0 on error
 */
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
	int						doChecksum);

/**
 * @brief Parse ICMPv6 header from raw data
 * @param data - pointer to raw data
 * @param len - length of the data in bytes
 * @return pointer to ICMPv6 header structure, or NULL on error
 */
const tIcmp6Hdr *icmp6ParseHeader(const void *data, uint32_t len);

/* ----------------- ICMP Print Functions ----------------- */

/**
 * @brief Print ICMPv4 header details in a human-readable format
 * @param hdr - pointer to ICMPv4 header structure
 */
void printIcmp4Header(const tIcmp4Hdr *hdr);

/**
 * @brief Print ICMPv4 packet details in a human-readable format
 * @param pkt - pointer to the raw ICMPv4 packet data
 * @param len - length of the packet data in bytes
 */
void printIcmp4Packet(const void *pkt, uint32_t len);

/**
 * @brief Print ICMPv6 header details in a human-readable format
 * @param hdr - pointer to ICMPv6 header structure
 */
void printIcmp6Header(const tIcmp6Hdr *hdr);

/**
 * @brief Print ICMPv6 packet
 * @param type - ICMPv4 type
 * @return string representation of the type, or "Unknown" if not recognized
 */
const char *icmp4TypeName(uint8_t type);

/**
 * @brief Get string representation of ICMPv4 code for a given type
 * @param type - ICMPv4 type
 * @param code - ICMPv4 code
 * @return string representation of the code, or "Unknown" if not recognized
 */
const char *icmp4CodeName(uint8_t type, uint8_t code);

/**
 * @brief Get string representation of ICMPv6 type
 * @param type - ICMPv6 type
 * @return string representation of the type, or "Unknown" if not recognized
 */
const char *icmp6TypeName(uint8_t type);

/**
 * @brief Get string representation of ICMPv6 code for a given type
 * @param type - ICMPv6 type
 * @param code - ICMPv6 code
 * @return string representation of the code, or "Unknown" if not recognized
 */
const char *icmp6CodeName(uint8_t type, uint8_t code);

#endif /* HAJ_ICMP_H */
