#ifndef HAJ_PING_UTILS_H
# define HAJ_PING_UTILS_H

#include <stdint.h>
#include <sys/time.h>

#include "../../common/includes/icmp.h"
#include "../includes/parser.h"

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

#endif /* HAJ_PING_UTILS_H */