#include <stdio.h>
#include <time.h>

#include "../includes/pingUtils.h"

void
timevalFromDouble(struct timeval *tv, double seconds)
{
	tv->tv_sec = (time_t)seconds;
	tv->tv_usec = (suseconds_t)((seconds - (double)tv->tv_sec) * 1e6);
}

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

uint32_t
msSinceMidnight(void)
{
	struct timeval	tv;
	struct tm		tmUtc;

	gettimeofday(&tv, NULL);
	gmtime_r(&tv.tv_sec, &tmUtc);
	uint32_t ms = tmUtc.tm_hour * 3600000
				+ tmUtc.tm_min * 60000
				+ tmUtc.tm_sec * 1000
				+ tv.tv_usec / 1000;
	return (ms);
}

void
printIcmpv4TimestampReply(const tIcmp4Echo *ts)
{
	uint32_t otime, rtime, ttime;
	if (!ts)
		return;
	otime = ntohl(((uint32_t *)ts->data)[0]);
	rtime = ntohl(((uint32_t *)ts->data)[1]);
	ttime = ntohl(((uint32_t *)ts->data)[2]);
	printf("icmp_otime = %u\n", otime);
	printf("icmp_rtime = %u\n", rtime);
	printf("icmp_ttime = %u\n", ttime);
}
