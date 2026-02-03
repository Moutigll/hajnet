#include "../includes/pingUtils.h"

/**
 * @brief Convert double seconds to timeval
 * @param tv - timeval to fill
 * @param seconds - seconds as double
 */
void
timevalFromDouble(struct timeval *tv, double seconds)
{
	tv->tv_sec = (time_t)seconds;
	tv->tv_usec = (suseconds_t)((seconds - (double)tv->tv_sec) * 1e6);
}

/**
 * @brief Normalize timeval structure (adjusts tv_usec to be within valid range)
 * @param tv - timeval to normalize
 */
void
normalizeTimeval(struct timeval *tv)
{
	while (tv->tv_usec >= 1000000)
	{
		tv->tv_usec -= 1000000;
		tv->tv_sec++;
	}
	while (tv->tv_usec < 0)
	{
		tv->tv_usec += 1000000;
		tv->tv_sec--;
	}
	if (tv->tv_sec < 0)
	{
		tv->tv_sec = 0;
		tv->tv_usec = 0;
	}
}

/**
 * @brief Compute user payload size based on options
 * @param opts - ping options
 * @return user payload size in bytes
 */
uint32_t
computeUserPayloadSize(const tPingOptions *opts)
{
	uint32_t userPayload = 56; /* default payload = 56 bytes (typical ping) */

	if (opts && opts->packetSize >= 0)
	{
		/* if user asked for size, use it (can be 0) */
		userPayload = (uint32_t)opts->packetSize;
	}
	return (userPayload);
}
