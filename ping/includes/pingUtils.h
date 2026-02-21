#ifndef HAJ_PING_UTILS_H
# define HAJ_PING_UTILS_H

#include <stdint.h>
#include <sys/time.h>

#include "../../common/includes/ip.h"
#include "../../common/includes/icmp.h"
#include "../includes/parser.h"
#include "ping.h"

/**
 * @brief Convert double seconds to timeval
 * @param tv - timeval to fill
 * @param seconds - seconds as double
 */
void timevalFromDouble(struct timeval *tv, double seconds);

/**
 * @brief Normalize timeval structure (adjusts tv_usec to be within valid range)
 * @param tv - timeval to normalize
 */
void normalizeTimeval(struct timeval *tv);

/**
 * @brief Compute user payload size based on options
 * @param opts - ping options
 * @return user payload size in bytes
 */
uint32_t computeUserPayloadSize(const tPingOptions *opts);

/**
 * @brief Get milliseconds since midnight UTC
 * @return milliseconds since midnight
 */
uint32_t msSinceMidnight(void);

/**
 * @brief Print ICMPv4 Timestamp Reply packet details
 * @param ts - pointer to ICMPv4 Echo structure
 */
void printIcmpv4TimestampReply(const tIcmp4Echo *ts);

/**
 * @brief Print IPv4 timestamp options from the header
 * @param hdr - pointer to IPv4 header structure containing options
 * @param numeric - whether to print in numeric format (no DNS resolution)
 */
void printIp4Timestamps(tIpHdr *hdr, tBool numeric);

/**
 * @brief Print IPv4 Record Route option from the header
 * @param hdr - pointer to IPv4 header structure containing options
 * @param buf - buffer to write the formatted route string
 * @param bufSize - size of the buffer
 * @param numeric - whether to print in numeric format (no DNS resolution)
 * @return length of the formatted route string
 */
size_t formatIp4Route(tIpHdr *hdr, char *buf, size_t bufSize, tBool numeric);

/**
 * @brief Print details of an invalid ICMP error message (e.g., unexpected type/code)
 * @param from - source address of the ICMP error
 * @param icmp - pointer to the ICMP packet that caused the error
 * @param icmpLen - length of the ICMP packet
 * @param numeric - whether to print in numeric format (no DNS resolution)
 */
void printInvalidIcmpError(
	const struct sockaddr_storage *from,
	const unsigned char *icmp,
	size_t icmpLen,
	tBool numeric);

/**
 * @brief Check for ICMP errors in the socket's error queue and print details
 * @param sock - socket file descriptor to check for errors
 * @param numeric - whether to print in numeric format (no DNS resolution)
 * @return 1 if an error was found and printed, 0 if no errors were pending
 */
int checkIcmpErrorQueue(int sock, tBool numeric);

/**
 * @brief Drain the ICMP error queue to remove any pending errors
 * @param sock - socket file descriptor to drain
 */
void drainIcmpErrorQueue(tPingContext *ctx);

#endif /* HAJ_PING_UTILS_H */
