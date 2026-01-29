#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/ip_icmp.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "../includes/ft_ping.h"
#include "../includes/usage.h"

/* Global flag to indicate user interrupted (Ctrl+C) */
volatile sig_atomic_t g_pingInterrupted = 0;

/* Signal handler for SIGINT (Ctrl+C) */
static void handleSigInt(int sig)
{
	(void)sig;
	g_pingInterrupted = 1;
}

/* Compute ICMP checksum */
static unsigned short icmpChecksum(const void *buf, int len)
{
	unsigned int sum = 0;
	const unsigned short *data = buf;

	while (len > 1)
	{
		sum += *data++;
		len -= 2;
	}
	if (len == 1)
		sum += *(unsigned char *)data;

	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);

	return (unsigned short)(~sum);
}

/* Build an ICMP Echo Request packet with embedded timestamp */
static int buildIcmpPacket(tPingContext *ctx, unsigned char *buf, int *len)
{
	if (!ctx || !buf || !len)
		return -1;

	memset(buf, 0, PING_MAX_PACKET_SIZE);

	struct icmphdr *hdr = (struct icmphdr *)buf;
	hdr->type = ICMP_ECHO;
	hdr->code = 0;
	hdr->un.echo.id = htons(getpid() & 0xFFFF);
	hdr->un.echo.sequence = htons(ctx->seq);

	/* Store current time in packet data to compute RTT later */
	struct timeval *tv = (struct timeval *)(buf + ICMP_DATA_OFFSET);
	gettimeofday(tv, NULL);

	*len = ICMP_DATA_OFFSET + sizeof(struct timeval);

	hdr->checksum = 0;
	hdr->checksum = icmpChecksum(buf, *len);

	return 0;
}

/* Send one ICMP packet and optionally print header if verbose */
static int sendIcmpPacket(tPingContext *ctx)
{
	if (!ctx)
		return -1;

	unsigned char buf[PING_MAX_PACKET_SIZE];
	int len;

	if (buildIcmpPacket(ctx, buf, &len) < 0)
		return -1;

	ssize_t sent = sendto(ctx->sock.fd, buf, len, 0,
						  (struct sockaddr *)&ctx->targetAddr, ctx->addrLen);
	if (sent != len)
		return -1;

	ctx->stats.sent++;

	/* Verbose logging */
	if (ctx->opts.options.verbose > 2)
		printf("Sent %zd bytes\n", sent);
	if (ctx->opts.options.verbose > 3)
	{
		printf("================================================================\n");
		printf("SENDING REQ [%d]\n", ctx->seq);
		printIcmpHeader(buf, len, ctx->targetAddr.ss_family == AF_INET);
	}

	return 0;
}

/* Receive one ICMP reply and compute RTT using timestamp */
static int receiveIcmpReply(tPingContext *ctx, unsigned char *buf, int bufLen, double *rtt)
{
	if (!ctx || !buf || bufLen <= 0)
		return -1;

	socklen_t addrLen = ctx->addrLen;
	ssize_t n = recvfrom(ctx->sock.fd, buf, bufLen, 0,
						 (struct sockaddr *)&ctx->targetAddr, &addrLen);
	if (n < 0)
	{
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return -1;
		return -1;
	}

	ctx->stats.received++;
	ctx->stats.lost = ctx->stats.sent - ctx->stats.received;

	/* Compute RTT using timestamp in packet */
	if ((unsigned long)n >= ICMP_DATA_OFFSET + sizeof(struct timeval))
	{
		struct timeval *tvSent = (struct timeval *)(buf + ICMP_DATA_OFFSET);
		struct timeval tvNow;
		gettimeofday(&tvNow, NULL);

		double ms = (tvNow.tv_sec - tvSent->tv_sec) * 1000.0 +
					(tvNow.tv_usec - tvSent->tv_usec) / 1000.0;
		if (rtt)
			*rtt = ms;

		if (ctx->stats.rttMin == 0 || ms < ctx->stats.rttMin)
			ctx->stats.rttMin = ms;
		if (ms > ctx->stats.rttMax)
			ctx->stats.rttMax = ms;
		ctx->stats.rttSum += ms;
		ctx->stats.rttSumSq += ms * ms;
	}
	else if (rtt)
		*rtt = 0.0;

	return 0;
}

/* Print one ICMP reply to stdout */
static void printIcmpReply(tPingContext *ctx, double rtt)
{
	char *ipStr;

	if (ctx->targetAddr.ss_family == AF_INET)
	{
		ipStr = inet_ntoa(((struct sockaddr_in *)&ctx->targetAddr)->sin_addr);
		printf("64 bytes from %s: icmp_seq=%u ttl=64 time=%.3f ms\n",
			   ipStr, ctx->seq, rtt);
	}
	else
	{
		printf("64 bytes from (ipv6): icmp_seq=%u time=%.3f ms\n",
			   ctx->seq, rtt);
	}
}

/* Convert double seconds to timeval */
static void timevalFromDouble(struct timeval *tv, double seconds)
{
	tv->tv_sec = (time_t)seconds;
	tv->tv_usec = (suseconds_t)((seconds - (double)tv->tv_sec) * 1e6);
}

/* Normalize timeval structure to valid range */
static void normalizeTimeval(struct timeval *tv)
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

/* Main ping loop */
void runPingLoop(tPingContext *ctx)
{
	fd_set fdset;
	struct timeval respTime;
	struct timeval lastSend, interval, now;
	unsigned char buf[PING_MAX_PACKET_SIZE];
	double rtt;

	if (!ctx)
		return;

	/* Set socket to non-blocking mode */
	fcntl(ctx->sock.fd, F_SETFL, O_NONBLOCK);

	/* Install SIGINT handler */
	signal(SIGINT, handleSigInt);

	/* Ensure interval is valid */
	if (ctx->opts.options.interval <= 0)
		ctx->opts.options.interval = 1.0;

	timevalFromDouble(&interval, ctx->opts.options.interval);
	normalizeTimeval(&interval);

	gettimeofday(&lastSend, NULL);
	ctx->seq = 0;

	while (!g_pingInterrupted &&
		   (ctx->opts.options.count == 0 || ctx->seq < ctx->opts.options.count))
	{
		/* Send ICMP Echo Request */
		if (sendIcmpPacket(ctx) < 0)
			fprintf(stderr, "Failed to send ICMP packet\n");

		/* Wait for reply with select() respecting interval */
		while (!g_pingInterrupted)
		{
			FD_ZERO(&fdset);
			FD_SET(ctx->sock.fd, &fdset);

			gettimeofday(&now, NULL);
			respTime.tv_sec = lastSend.tv_sec + interval.tv_sec - now.tv_sec;
			respTime.tv_usec = lastSend.tv_usec + interval.tv_usec - now.tv_usec;
			normalizeTimeval(&respTime);
			if (respTime.tv_sec < 0)
				respTime.tv_sec = respTime.tv_usec = 0;

			int sel = select(ctx->sock.fd + 1, &fdset, NULL, NULL, &respTime);
			if (sel > 0)
			{
				if (receiveIcmpReply(ctx, buf, sizeof(buf), &rtt) == 0)
					printIcmpReply(ctx, rtt);
			}
			else
				break;
		}

		/* Update last send timestamp and sequence */
		gettimeofday(&lastSend, NULL);
		ctx->seq++;
	}

	/* Print final statistics */
	printf("\n--- ping statistics ---\n");
	printf("%u packets transmitted, %u received, %.1f%% packet loss\n",
		   ctx->seq, ctx->stats.received,
		   ((ctx->seq - ctx->stats.received) * 100.0) / ctx->seq);

	if (ctx->stats.received > 0)
	{
		double avg = ctx->stats.rttSum / ctx->stats.received;
		printf("rtt min/avg/max = %.3f/%.3f/%.3f ms\n",
			   ctx->stats.rttMin, avg, ctx->stats.rttMax);
	}
}
