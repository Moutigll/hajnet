#include <arpa/inet.h>
#include <errno.h>
#include <linux/errqueue.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "../../common/includes/ip.h"
#include "../../common/includes/icmp.h"
#include "../includes/parser.h"
#include "../includes/pingUtils.h"
#include "../includes/resolve.h"

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

				struct sockaddr_in sa = {0};
				sa.sin_family = AF_INET;
				sa.sin_addr = a;

				char revDns[NI_MAXHOST];
				if (resolvePeerName((struct sockaddr_storage *)&sa, sizeof(sa),
				                    NULL, revDns, sizeof(revDns)) != 0)
					snprintf(revDns, sizeof(revDns), "%s", ipbuf);

				if (!printedAny)
				{
					printf("TS:\t%s (%s)\t%u", revDns, ipbuf, raw);
					printedAny = 1;
				}
				else
					printf("\n\t%s (%s)\t%u", revDns, ipbuf, raw);
			}
		}

		if (printedAny)
			printf("\n\n");

		break;
	}
}

size_t
formatIp4Route(tIpHdr *hdr, char *buf, size_t bufSize)
{
	if (!hdr || !buf || bufSize == 0)
		return 0;

	buf[0] = '\0';
	size_t totalLen = 0;

	for (int i = 0; i < 10; ++i)
	{
		if (hdr->options[i].type != IPOPT_RR)
			continue;

		unsigned char *data = hdr->options[i].data;
		size_t len = hdr->options[i].length;
		if (len < 3)
			continue;

		size_t payloadLen = len - 3;
		const unsigned char *payload = data + 3;

		int first = 1;
		char prevHost[INET_ADDRSTRLEN] = "";

		for (size_t off = 0; off + 4 <= payloadLen; off += 4)
		{
			uint32_t raw;
			memcpy(&raw, payload + off, 4);
			if (raw == 0)
				continue;

			struct in_addr a;
			a.s_addr = raw;

			char ipbuf[INET_ADDRSTRLEN];
			if (!inet_ntop(AF_INET, &a, ipbuf, sizeof(ipbuf)))
				snprintf(ipbuf, sizeof(ipbuf), "??");

			struct sockaddr_in sa = {0};
			sa.sin_family = AF_INET;
			sa.sin_addr = a;

			char revDns[NI_MAXHOST];
			if (resolvePeerName((struct sockaddr_storage *)&sa, sizeof(sa),
			                    NULL, revDns, sizeof(revDns)) != 0)
				snprintf(revDns, sizeof(revDns), "%s", ipbuf);

			char line[128];
			if (first)
			{
				snprintf(line, sizeof(line), "RR:\t%.31s (%.15s)", revDns, ipbuf);
				first = 0;
			}
			else
			{
#if defined(HAJ)
				if (strcmp(prevHost, revDns) == 0)
					snprintf(line, sizeof(line), "\n\t (same route)");
				else
#endif
					snprintf(line, sizeof(line), "\n\t%.31s (%.15s)", revDns, ipbuf);
			}

			strncpy(prevHost, revDns, sizeof(prevHost));
			size_t lineLen = strlen(line);
			if (totalLen + lineLen + 1 >= bufSize)
				break;

			strcat(buf, line);
			totalLen += lineLen;
		}

		break; // only first RR option
	}

	return totalLen;
}

void
printInvalidIcmpError(
	const struct sockaddr_storage *from,
	const unsigned char *icmp,
	size_t icmpLen,
	tBool numeric)
{
	char ipStr[INET6_ADDRSTRLEN] = {0};

	if (!from || !icmp || icmpLen == 0)
		return;

	/* format IP address */
	if (from->ss_family == AF_INET)
	{
		const struct sockaddr_in *s4 = (const struct sockaddr_in *)from;
		inet_ntop(AF_INET, &s4->sin_addr, ipStr, sizeof(ipStr));
	}
#if defined(AF_INET6)
	else if (from->ss_family == AF_INET6)
	{
		const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)from;
		inet_ntop(AF_INET6, &s6->sin6_addr, ipStr, sizeof(ipStr));
	}
#endif
	else
		snprintf(ipStr, sizeof(ipStr), "Unknown AF %d", from->ss_family);

	/* ICMP type/code */
	uint8_t type = icmp[0];
	uint8_t code = icmpLen > 1 ? icmp[1] : 0;

	const char *typeName = "Unknown";
	const char *codeName = "No code";

	if (from->ss_family == AF_INET)
	{
		typeName = icmp4TypeName(type);
		codeName = icmp4CodeName(type, code);
	}
#if defined(AF_INET6)
	else if (from->ss_family == AF_INET6)
	{
		typeName = icmp6TypeName(type);
		codeName = icmp6CodeName(type, code);
	}
#endif

	if (!numeric)
	{
		char revDns[NI_MAXHOST];
		int resolved = resolvePeerName(from, sizeof(*from), NULL, revDns, sizeof(revDns));
		if (resolved == 0) {
			fprintf(stderr, "%zu bytes from %s (%s): %s(%u), %s(%u)\n",
				icmpLen, revDns, ipStr, typeName, type, codeName, code);
			return;
			}
	}

	fprintf(stderr, "%zu bytes from %s: %s(%u), %s(%u)\n",
		icmpLen, ipStr, typeName, type, codeName, code);
			
}

static void handleCmsg(int level, struct cmsghdr *cmsg, tBool numeric)
{
	struct sock_extended_err *err;
	unsigned char icmp[8] = {0};
	err = (struct sock_extended_err *)CMSG_DATA(cmsg);
	if (err->ee_origin != SO_EE_ORIGIN_ICMP &&
		err->ee_origin != SO_EE_ORIGIN_ICMP6)
		return;

	if (level == SOL_IP)
	{
		struct sockaddr_in *offender = (struct sockaddr_in *)SO_EE_OFFENDER(err);
		if (!offender)
			return;

		struct sockaddr_in from = {0};
		from.sin_family = AF_INET;
		from.sin_addr = offender->sin_addr;

		icmp[0] = err->ee_type;
		icmp[1] = err->ee_code;

		printInvalidIcmpError((struct sockaddr_storage *)&from, icmp, sizeof(icmp), numeric);
	}
	else if (level == SOL_IPV6)
	{
		struct sockaddr_in6 *offender = (struct sockaddr_in6 *)SO_EE_OFFENDER(err);
		if (!offender)
			return;

		struct sockaddr_in6 from6 = *offender;
		icmp[0] = err->ee_type;
		icmp[1] = err->ee_code;

		printInvalidIcmpError((struct sockaddr_storage *)&from6, icmp, sizeof(icmp), numeric);
	}
}

void checkIcmpErrorQueue(int sock, tBool numeric)
{
	struct msghdr msg = {0};
	struct iovec iov;
	unsigned char buf[1];
	unsigned char cmsgbuf[1024] = {0};

	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);

	ssize_t n = recvmsg(sock, &msg, MSG_ERRQUEUE | MSG_DONTWAIT);
	if (n < 0)
	{
		if (errno != EAGAIN && errno != EWOULDBLOCK)
			perror("recvmsg(MSG_ERRQUEUE)");
		return;
	}

	for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg))
	{
		if (cmsg->cmsg_level == SOL_IP || cmsg->cmsg_level == SOL_IPV6)
			handleCmsg(cmsg->cmsg_level, cmsg, numeric);
		else
			printf("Unknown cmsg_level=%d ignored\n", cmsg->cmsg_level);
	}
}

void
drainIcmpErrorQueue(tPingContext *ctx)
{
	while (1)
	{
		if (!ctx)
			return;
		
		struct msghdr msg = {0};
		struct iovec iov;
		unsigned char buf[1];
		unsigned char cmsgbuf[1024];

		iov.iov_base = buf;
		iov.iov_len = sizeof(buf);

		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = cmsgbuf;
		msg.msg_controllen = sizeof(cmsgbuf);

		ssize_t n = recvmsg(ctx->sock.fd, &msg, MSG_ERRQUEUE | MSG_DONTWAIT);
		if (n < 0)
		{
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				return;
			perror("recvmsg(MSG_ERRQUEUE)");
			return;
		}
		for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
			 cmsg;
			 cmsg = CMSG_NXTHDR(&msg, cmsg))
		{
			struct sock_extended_err *err;
			err = (struct sock_extended_err *)CMSG_DATA(cmsg);
			if (err->ee_origin == SO_EE_ORIGIN_ICMP ||
				err->ee_origin == SO_EE_ORIGIN_ICMP6)
				ctx->stats.errors++;
			if (cmsg->cmsg_level == SOL_IP
					|| cmsg->cmsg_level == SOL_IPV6)
				handleCmsg(cmsg->cmsg_level, cmsg, ctx->opts.numeric);
			else
				printf("Unknown cmsg_level=%d ignored\n", cmsg->cmsg_level);
		}
	}
}
