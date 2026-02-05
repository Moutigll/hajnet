#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "../../common/includes/ip.h"
#include "../includes/parser.h"
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

void
printIp4Timestamps(tIpHdr *hdr)
{
	if (!hdr)
		return;

	for (int i = 0; i < 10; ++i)
	{
		if (hdr->options[i].type != IP_OPT_TS)
			continue;
		unsigned char *data = hdr->options[i].data;
		size_t len = hdr->options[i].length;

		if (len < 4)
			continue;

		unsigned char flags = data[1];
		size_t payloadLen = (len >= 2) ? (len - 2) : 0;
		const unsigned char *payload = data + 2;

		int printedAny = 0;

		if ((flags & 0xF) == IP_OPT_TS_TSONLY)
		{
			for (size_t off = 0; off + 4 <= payloadLen; off += 4)
			{
				uint32_t raw;
				memcpy(&raw, payload + off, 4);
				raw = ntohl(raw);
				if (raw == 0)
					continue;

				if (!printedAny)
				{
					printf("TS:\t%u", raw);
					printedAny = 1;
				}
				else
					printf("\n\t%u", raw);
			}
		}
		else if ((flags & 0xF) == IP_OPT_TS_TSANDADDR || (flags & 0xF) == IP_OPT_TS_PRESPEC)
		{
			for (size_t off = 8; off + 8 <= payloadLen; off += 8)
			{
				struct in_addr a;
				uint32_t raw;
				memcpy(&a.s_addr, payload + off, 4);
				memcpy(&raw, payload + off + 4, 4);
				raw = ntohl(raw);
				if (a.s_addr == 0 && raw == 0)
					continue;

				char ipbuf[INET_ADDRSTRLEN];
				if (!inet_ntop(AF_INET, &a, ipbuf, sizeof(ipbuf)))
					snprintf(ipbuf, sizeof(ipbuf), "??");

				if (!printedAny)
				{
					printf("TS:\t%s (%s)\t%u", ipbuf, ipbuf, raw);
					printedAny = 1;
				}
				else
					printf("\n\t%s (%s)\t%u", ipbuf, ipbuf, raw);
			}
		}

		if (printedAny)
			printf("\n\n");
		break;
	}
}
