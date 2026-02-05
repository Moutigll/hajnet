
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>


#include "../includes/ping.h"
#include "../includes/pingUtils.h"
#include "../includes/usage.h"


/* global flag set on SIGINT */
volatile sig_atomic_t g_pingInterrupted = 0;

/* SIGINT handler */
static void
handleSigInt(int sig)
{
	(void)sig;
	g_pingInterrupted = 1;
}

/**
 * @brief Send one ICMP Echo Request packet
 * @param ctx - ping context
 * @return 0 on success, -1 on failure
 */
static int
sendIcmpPacket(tPingContext *ctx)
{
	unsigned char	packet[PING_MAX_PACKET_SIZE];
	unsigned char	payload[PING_MAX_PACKET_SIZE];
	struct timeval	tv;
	uint32_t		userPayload;
	uint32_t		payloadLen;
	uint32_t		packetLen;
	ssize_t			sent;

	if (!ctx)
		return (-1);

	/* compute user payload and bound it */
	userPayload = computeUserPayloadSize(&ctx->opts);
	if (userPayload > (PING_MAX_PACKET_SIZE - sizeof(tIcmp4Hdr) - 4))
		userPayload = PING_MAX_PACKET_SIZE - sizeof(tIcmp4Hdr) - 4;

	payloadLen = userPayload;

	if (payloadLen > 0)
	{
		unsigned int	i;
		unsigned int	tvSize;
		unsigned int	patternLen;
		unsigned char	pattern[256];

		tvSize = sizeof(tv);
		patternLen = ctx->opts.patternLen;

		if (payloadLen >= tvSize)
		{
			gettimeofday(&tv, NULL);
			memcpy(payload, &tv, tvSize);
		}
		else
			tvSize = 0;

		if (patternLen > 0)
		{
			memcpy(pattern, ctx->opts.pattBytes, patternLen);
			for (i = tvSize; i < payloadLen; i++)
				payload[i] = pattern[(i - tvSize) % patternLen];
		}
		else
		{
			for (i = tvSize; i < payloadLen; i++)
				payload[i] = 0;
		}
	}

	if (ctx->targetAddr.ss_family == AF_INET)
	{
		if (ctx->opts.timestamp && ctx->sock.privilege == SOCKET_PRIV_RAW)
		{
			/* build ICMP Timestamp request if raw socket and timestamp option */
			packetLen = buildIcmpv4TimestampRequest(
				(tIcmp4Timestamp *)packet,
				sizeof(tIcmp4Timestamp),
				(uint16_t)ctx->pid,
				(uint16_t)ctx->seq,
				msSinceMidnight()
			);

		}
		else
		{
			/* default Echo request */
			packetLen = buildIcmpv4EchoRequest(
				(tIcmp4Echo *)packet,
				sizeof(packet),
				(uint16_t)ctx->pid,
				(uint16_t)ctx->seq,
				(payloadLen ? payload : NULL),
				payloadLen
			);
		}
	}
#if defined(AF_INET6)
	else if (ctx->targetAddr.ss_family == AF_INET6)
	{
		const struct sockaddr_in6 *dst6 = (const struct sockaddr_in6 *)&ctx->targetAddr;
		struct in6_addr src6;
		int doChecksum = (ctx->sock.privilege == SOCKET_PRIV_RAW);
		/* try to get local src addr for checksum when RAW */
		if (doChecksum)
		{
			struct sockaddr_storage local;
			socklen_t l = sizeof(local);
			if (getsockname(ctx->sock.fd, (struct sockaddr *)&local, &l) == 0
				&& local.ss_family == AF_INET6)
				src6 = ((struct sockaddr_in6 *)&local)->sin6_addr;
			else
				src6 = in6addr_any;
		}
		packetLen = buildIcmpv6EchoRequest(
			(tIcmp6Echo *)packet,
			sizeof(packet),
			(uint16_t)ctx->pid,
			(uint16_t)ctx->seq,
			(payloadLen ? payload : NULL),
			payloadLen,
			(doChecksum ? &src6 : NULL),
			&dst6->sin6_addr,
			doChecksum
		);
	}
#endif
	else
	{
		fprintf(stderr, "Unsupported address family %d\n", ctx->targetAddr.ss_family);
		return (-1);
	}

	if (packetLen == 0)
		return (-1);

	/* send (works for RAW and DGRAM when target provided) */
	if (ctx->sock.privilege == SOCKET_PRIV_USER)
	{
		/* socket DGRAM connecté → utiliser send() pour que le kernel
		 * associe correctement les erreurs ICMP à ce socket */
		sent = send(ctx->sock.fd, packet, packetLen, 0);
	}
	else
	{
		sent = sendto(ctx->sock.fd,
						packet,
						packetLen,
						0,
						(struct sockaddr *)&ctx->targetAddr,
						ctx->addrLen);
	}
	if (sent < 0)
	{
		if (ctx->opts.verbose > 1)
			fprintf(stderr, "sendto failed: %s (%d)\n", strerror(errno), errno);
		return (-1);
	}

	if (ctx->opts.verbose > 2)
		printf("Sent ICMP Echo Request: seq=%u bytes=%zd\n", ctx->seq, sent);

	ctx->stats.sent++;
	return (0);
}

/**
 * @brief Receive ICMP packet on a DGRAM socket.
 * @param ctx - ping context
 * @param buf - buffer to receive packet
 * @param bufLen - length of buffer
 * @param from - source address output
 * @param icmp - ICMP packet output
 * @param icmpLen - ICMP packet length output
 * @param ttl - TTL output
 * @return 0 on success, -1 on failure
 */
static int
recvIcmpDgram(
	tPingContext			*ctx,
	void					*buf,
	size_t					bufLen,
	struct sockaddr_storage	*from,
	const unsigned char		**icmp,
	size_t					*icmpLen,
	uint8_t					*ttl)
{
	ssize_t				n;
	socklen_t			fromLen = sizeof(*from);
	struct iovec		iov;
	struct msghdr		msg;
	char				cmsgbuf[CMSG_SPACE(sizeof(int))];
	int					recvTtl = 0;

	if (!ctx || !buf || !from || !icmp || !icmpLen || !ttl)
		return (-1);

	iov.iov_base = buf;
	iov.iov_len = bufLen;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name		= from;		/* source address */
	msg.msg_namelen		= fromLen;	/* length of source address */
	msg.msg_iov			= &iov;		/* scatter/gather array */
	msg.msg_iovlen		= 1;		/* number of elements in iov */
	msg.msg_control		= cmsgbuf;	/* ancillary data buffer */
	msg.msg_controllen	= sizeof(cmsgbuf);

	n = recvmsg(ctx->sock.fd, &msg, 0);
#if defined (HAJ)
	if (ctx->opts.verbose > 0)
		checkIcmpErrorQueue(ctx->sock.fd, ctx->opts.numeric);
#endif
	if (n <= 0)
		return (-1);

	/* parse ancillary: IPv4 TTL or IPv6 HOPLIMIT if present */
	for (struct cmsghdr *c = CMSG_FIRSTHDR(&msg); c; c = CMSG_NXTHDR(&msg, c))
	{
		if (c->cmsg_level == IPPROTO_IP && c->cmsg_type == IP_TTL)
		{
			if (c->cmsg_len >= CMSG_LEN(sizeof(int)))
				memcpy(&recvTtl, CMSG_DATA(c), sizeof(int));
			break;
		}
#if defined(IPPROTO_IPV6) && defined(IPV6_HOPLIMIT)
		if (c->cmsg_level == IPPROTO_IPV6 && c->cmsg_type == IPV6_HOPLIMIT)
		{
			if (c->cmsg_len >= CMSG_LEN(sizeof(int)))
				memcpy(&recvTtl, CMSG_DATA(c), sizeof(int));
			break;
		}
#endif
	}

	*icmp		= (const unsigned char *)buf;
	*icmpLen	= (size_t)n;
	*ttl		= (uint8_t)recvTtl;
	return (0);
}

/**
 * @brief Receive ICMP packet on a RAW socket.
 * Parse IP header to locate ICMP payload.
 * @param ctx - ping context
 * @param buf - buffer to receive packet
 * @param bufLen - length of buffer
 * @param from - source address output
 * @param icmp - ICMP packet output
 * @param icmpLen - ICMP packet length output
 * @param ttl - TTL output
 * @param ipHdrOut - parsed IP header output
 * @return 0 on success, -1 on failure
 */
static int
recvIcmpRaw(tPingContext *ctx,
			void					*buf,
			size_t					bufLen,
			struct sockaddr_storage	*from,
			const unsigned char		**icmp,
			size_t					*icmpLen,
			uint8_t					*ttl,
			const tIpHdr			**ipHdrOut)
{
	ssize_t			n;
	socklen_t		fromLen = sizeof(*from);
	int				recvTtl = 0;
	struct iovec	iov;
	struct msghdr	msg;
	char			cmsgbuf[CMSG_SPACE(sizeof(int))];

	if (!ctx || !buf || !from || !icmp || !icmpLen || !ttl || !ipHdrOut)
		return (-1);

	iov.iov_base = buf;
	iov.iov_len = bufLen;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = from;
	msg.msg_namelen = fromLen;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);

	n = recvmsg(ctx->sock.fd, &msg, 0);
	if (n <= 0)
		return (-1);

	/* Retrieve TTL from ancillary control data */
	for (struct cmsghdr *c = CMSG_FIRSTHDR(&msg); c; c = CMSG_NXTHDR(&msg, c))
	{
		if (c->cmsg_level == IPPROTO_IP && c->cmsg_type == IP_TTL)
		{
			if (c->cmsg_len >= CMSG_LEN(sizeof(int)))
				memcpy(&recvTtl, CMSG_DATA(c), sizeof(int));
			break;
		}
	}

	size_t ipHeaderLen = 0;

	if (ctx->sock.family == AF_INET)
	{
		static tIpHdr ipHdr;

		ipHeaderLen = parseIpHeaderFromBuffer(buf, (size_t)n, &ipHdr);
		if (ipHeaderLen == 0)
			return (-1);

		parseIp4Opts((const unsigned char *)buf, ipHeaderLen, &ipHdr);
		*ipHdrOut = &ipHdr;
	}
	else if (ctx->sock.family == AF_INET6)
	{
		/* RAW ICMPv6 socket: buffer starts with ICMPv6 header */
		ipHeaderLen = 0;
		*ipHdrOut = NULL;
	}

	*icmp = (const unsigned char *)buf + ipHeaderLen;
	*icmpLen = n - ipHeaderLen;
	*ttl = (uint8_t)recvTtl;

	return (0);
}

/**
 * @brief Validate received ICMP reply
 * @param ctx - ping context
 * @param icmp - ICMP packet
 * @param icmpLen - length of ICMP packet
 * @param from - source address
 * @param seqOut - output sequence number
 * @return 0 on success, -1 on failure
 */
static int
validateIcmpReply(
	tPingContext					*ctx,
	const unsigned char				*icmp,
	size_t							icmpLen,
	const struct sockaddr_storage	*from,
	uint16_t						*seqOut)
{
	uint16_t idNet, seqNet;

	if (!ctx || !icmp || !from || !seqOut)
		return (-1);

	/* require at least ICMP header size */
	if (ctx->targetAddr.ss_family == AF_INET)
	{
		if (icmpLen < ICMP4_HDR_LEN)
			return (-1);
		/* only consider IPv4 Echo Reply */
		if (icmp[0] != ICMP4_ECHO_REPLY &&
			!(ctx->opts.timestamp && icmp[0] == ICMP4_TIMESTAMP_REPLY))
		{
			if (ctx->opts.verbose > 0)
			{
				printInvalidIcmpError(from, icmp, icmpLen, ctx->opts.numeric);
#ifndef HAJ
				const unsigned char *ip = icmp - 20; /* ICMP starts after IP header */
				if (icmpLen >= 28) /* minimal IPv4 header + ICMP header */
				{
					printf("IP Hdr Dump:\n");
					for (size_t i = 0; i < 20; i += 2)
						printf("%02x%02x ", ip[i], ip[i+1]);
					printf("\n");

					printf("Vr HL TOS  Len   ID Flg  off TTL Pro  cks      Src\tDst\tData\n");
					printf("%u  %u  %02x %04x %04x   %u %04x  %02x  %02x %04x ",
						(ip[0] >> 4), (ip[0] & 0x0F), ip[1],
						(ip[2] << 8) | ip[3], (ip[4] << 8) | ip[5],
						(ip[6] >> 5), ((ip[6] & 0x1F) << 8) | ip[7],
						ip[8], ip[9], (ip[10] << 8) | ip[11]);
					printf("%u.%u.%u.%u\t%u.%u.%u.%u\n",
						ip[12], ip[13], ip[14], ip[15],
						ip[16], ip[17], ip[18], ip[19]);
				}

				/* print ICMP info */
				printf("ICMP: type %u, code %u, size %zu, id 0x%04x, seq 0x%04x\n",
					icmp[0], icmp[1], icmpLen,
					(uint16_t)((icmp[4] << 8) | icmp[5]),
					(uint16_t)((icmp[6] << 8) | icmp[7])
				);
#endif
			}
			return (-1);
		}

	}
#if defined(AF_INET6)
	else if (ctx->targetAddr.ss_family == AF_INET6)
	{
		if (icmpLen < ICMP6_HDR_LEN)
			return (-1);
		/* only consider IPv6 Echo Reply */
		if (icmp[0] != ICMP6_ECHO_REPLY)
		{
			if (ctx->opts.verbose > 0)
				printInvalidIcmpError(from, icmp, icmpLen, ctx->opts.numeric);
			return (-1);
		}
	}
#endif

	/* id/seq are at offsets 4 and 6 (network order) */
	memcpy(&idNet, icmp + 4, sizeof(idNet));
	memcpy(&seqNet, icmp + 6, sizeof(seqNet));

	*seqOut = ntohs(seqNet);

	/* DGRAM: kernel may rewrite id; ensure reply comes from the target address */
	if (ctx->targetAddr.ss_family == AF_INET && from->ss_family == AF_INET)
	{
		const struct sockaddr_in *sfrom = (const struct sockaddr_in *)from;
		const struct sockaddr_in *starget = (const struct sockaddr_in *)&ctx->targetAddr;
		if (sfrom->sin_addr.s_addr != starget->sin_addr.s_addr)
			return (-1);
	}
#if defined(AF_INET6)
	else if (ctx->targetAddr.ss_family == AF_INET6 && from->ss_family == AF_INET6)
	{
		const struct sockaddr_in6 *sfrom6 = (const struct sockaddr_in6 *)from;
		const struct sockaddr_in6 *starget6 = (const struct sockaddr_in6 *)&ctx->targetAddr;
		if (memcmp(&sfrom6->sin6_addr, &starget6->sin6_addr, sizeof(sfrom6->sin6_addr)) != 0)
			return (-1);
	}
#endif

	return (0);
}

/**
 * @brief Compute ICMP RTT from received packet
 * @param ctx - ping context
 * @param icmp - ICMP packet
 * @param icmpLen - length of ICMP packet
 * @param rtt - output RTT
 */
static void
computeIcmpRtt(
	tPingContext		*ctx,
	const unsigned char	*icmp,
	size_t				icmpLen,
	struct timeval		*rtt)
{
	struct timeval sentTv;
	struct timeval now;
	size_t offset;
	uint32_t userPayload;

	if (!ctx || !icmp || !rtt)
		return;

	userPayload = computeUserPayloadSize(&ctx->opts);

	/* ICMP header length is 8 for both v4 and v6, but keep family check for clarity */
	if (ctx->targetAddr.ss_family == AF_INET6)
		offset = ICMP6_HDR_LEN;
	else
		offset = ICMP4_HDR_LEN;

	memset(rtt, 0, sizeof(*rtt));
	if (userPayload < sizeof(sentTv))
		return;
	if (icmpLen < offset + sizeof(sentTv))
		return;

	memcpy(&sentTv, icmp + offset, sizeof(sentTv));
	gettimeofday(&now, NULL);
	timersub(&now, &sentTv, rtt);
}


/*
 * Top-level receive: choose RAW vs DGRAM helpers, validate, compute rtt.
 * - fills info->type, info->code, info->seq, info->ttl, info->rtt
 */
static int
receiveIcmpReply(
	tPingContext	*ctx,
	void			*buf,
	size_t			bufLen,
	tIcmpReplyInfo	*info,
	const tIpHdr	**ipHdrOut)
{
	struct sockaddr_storage	from;
	const unsigned char		*icmp;
	size_t					icmpLen;
	const tIpHdr			*ipHdr = NULL;

	if (!ctx || !buf || !info)
		return (-1);

	if (ctx->sock.privilege == SOCKET_PRIV_RAW)
	{
		if (recvIcmpRaw(ctx, buf, bufLen, &from, &icmp, &icmpLen, &info->ttl, &ipHdr) != 0)
			return (-1);
	}
	else
	{
		if (recvIcmpDgram(ctx, buf, bufLen, &from, &icmp, &icmpLen, &info->ttl) != 0)
			return (-1);
	}

	/* validate and extract seq (also filters unrelated replies) */
	if (validateIcmpReply(ctx, icmp, icmpLen, &from, &info->seq) != 0)
		return (-1);

	info->type = icmp[0];
	info->code = icmp[1];

	/* compute RTT if available */
	computeIcmpRtt(ctx, icmp, icmpLen, &info->rtt);

	*ipHdrOut = ipHdr;

	/* verbose: if RAW, also print parsed IP header */
	if (ctx->opts.verbose > 4 && ipHdr)
	{
		printf("Received IPv4 Header:\n");
		printIpv4Header(ipHdr);
	}

	if (ctx->opts.verbose > 3)
	{
		printf("ICMP reply: seq=%u ttl=%u\n", info->seq, info->ttl);
		printIcmp4Packet(icmp, (uint32_t)icmpLen);
	}

	ctx->stats.received++;
	return (0);
}

static void
pingLoopInit(
	tPingContext	*ctx,
	struct timeval	*lastSend,
	struct timeval	*interval,
	uint32_t		*userPayload,
	uint32_t		*onWireHeader)
{
	if (!ctx || !lastSend || !interval || !userPayload || !onWireHeader)
		return;

	*userPayload = computeUserPayloadSize(&ctx->opts);
	*onWireHeader = ICMP4_HDR_LEN; /* ICMP header on-wire (8) - printing will add user payload */

	printf(PROG_NAME " %s (%s): %u data bytes",
		ctx->targetHost,
		ctx->resolvedIp,
		*userPayload);
	
	if (ctx->opts.verbose > 0)
		printf(", id 0x%04x = %u", ctx->pid, ctx->pid);

	putchar('\n');

	fcntl(ctx->sock.fd, F_SETFL, O_NONBLOCK);
	signal(SIGINT, handleSigInt);

	double iv = ctx->opts.interval;
	if (iv <= 0.0)
		iv = PING_DEFAULT_INTERVAL;
	timevalFromDouble(interval, iv);
	normalizeTimeval(interval);

	gettimeofday(lastSend, NULL);

	ctx->seq = 0;
	ctx->stats.sent = 0;
	ctx->stats.received = 0;
	ctx->stats.lost = 0;
	ctx->stats.rttMin = 0.0;
	ctx->stats.rttMax = 0.0;
	ctx->stats.rttSum = 0.0;
}

/**
 * @brief Handle linger after sending all packets: wait for remaining replies until linger timeout expires
 * @param ctx - ping context
 * @param sentCount - number of packets sent
 * @param onWireHeader - size of ICMP header on the wire (without user payload)
 * @param userPayload - size of user payload in bytes
 */
static void
handleLinger(tPingContext *ctx,
			 unsigned int sentCount,
			 unsigned int onWireHeader,
			 uint32_t userPayload)
{
	if (!ctx || ctx->opts.linger <= 0 || sentCount == 0)
		return;

	fd_set fdset;
	struct timeval lingerTv, startTv, nowTv;
	unsigned char buf[PING_MAX_PACKET_SIZE];

	gettimeofday(&startTv, NULL);

	while (!g_pingInterrupted)
	{
		/* Check if all sent packets are already received */
		if (ctx->stats.received >= sentCount)
			break;

		/* Compute remaining linger time */
		gettimeofday(&nowTv, NULL);
		long elapsedUs = (nowTv.tv_sec - startTv.tv_sec) * 1000000L
					   + (nowTv.tv_usec - startTv.tv_usec);
		long remainingUs = ctx->opts.linger * 1000000L - elapsedUs;
		if (remainingUs <= 0)
			break;

		lingerTv.tv_sec  = remainingUs / 1000000L;
		lingerTv.tv_usec = remainingUs % 1000000L;

		FD_ZERO(&fdset);
		FD_SET(ctx->sock.fd, &fdset);

		int sel = select(ctx->sock.fd + 1, &fdset, NULL, NULL, &lingerTv);
		if (sel < 0)
		{
			if (errno != EINTR)
				fprintf(stderr, "select failed during linger: %s\n", strerror(errno));
			break;
		}
		else if (sel == 0)
			break;	/* timeout expired, stop linger */

		if (FD_ISSET(ctx->sock.fd, &fdset))
		{
			tIcmpReplyInfo replyInfo;
			if (receiveIcmpReply(ctx, buf, sizeof(buf), &replyInfo, NULL) != 0)
				continue;

			double ms = 0.0;
			if (userPayload >= sizeof(struct timeval) &&
					(replyInfo.rtt.tv_sec != 0 || replyInfo.rtt.tv_usec != 0))
				ms = replyInfo.rtt.tv_sec * 1000.0
				   + replyInfo.rtt.tv_usec / 1000.0;

			unsigned int replyBytes = onWireHeader + userPayload;
			if (!ctx->opts.flood)
				printf("%u bytes from %s: icmp_seq=%u ttl=%u time=%.3f ms\n",
					   replyBytes, ctx->resolvedIp, replyInfo.seq, replyInfo.ttl, ms);
		}
	}
}

void
runPingLoop(tPingContext *ctx)
{
	fd_set			fdset;
	struct timeval	lastSend, interval, now, respTime, startTime;
	unsigned char	buf[PING_MAX_PACKET_SIZE];
	unsigned int	sentCount = 0;
	uint32_t		userPayload;
	uint32_t		onWireHeader;
	char			oldRoute[512];

	if (!ctx)
		return;

	/* call initialization */
	pingLoopInit(ctx, &lastSend, &interval, &userPayload, &onWireHeader);

	/* save start time for -w / --timeout */
	gettimeofday(&startTime, NULL);

	/* handle -l / --preload */
	if (ctx->opts.preload > 0)
	{
		unsigned int i = 0;
		unsigned int max;

		if (ctx->opts.count > 0 && ctx->opts.preload > ctx->opts.count)
			max = ctx->opts.count;
		else
			max = ctx->opts.preload;

		while (i < max && !g_pingInterrupted)
		{
			if (sendIcmpPacket(ctx) == 0)
			{
				sentCount++;
				ctx->seq++;
			}
			i++;
		}

		gettimeofday(&lastSend, NULL);
	}

	while (!g_pingInterrupted &&
		   (ctx->opts.count == 0 || sentCount < ctx->opts.count))
	{
		/* check -w / --timeout */
		gettimeofday(&now, NULL);
		if (ctx->opts.timeout > 0 &&
			(now.tv_sec - startTime.tv_sec) >= ctx->opts.timeout)
			break;

		/* send one packet */
		if (sendIcmpPacket(ctx) == 0)
		{
			sentCount++;
			gettimeofday(&lastSend, NULL); // mise à jour timing précis
		}

		/* wait for replies until next interval */
		while (!g_pingInterrupted)
		{
			FD_ZERO(&fdset);
			FD_SET(ctx->sock.fd, &fdset);

			gettimeofday(&now, NULL);
			/* compute remaining time until next send */
			respTime.tv_sec  = lastSend.tv_sec  + interval.tv_sec  - now.tv_sec;
			respTime.tv_usec = lastSend.tv_usec + interval.tv_usec - now.tv_usec;
			normalizeTimeval(&respTime);
			if (respTime.tv_sec < 0) { respTime.tv_sec = 0; respTime.tv_usec = 0; }

			int sel = select(ctx->sock.fd + 1, &fdset, NULL, NULL, &respTime);
			if (sel < 0)
			{
				if (errno != EINTR)
				{
					fprintf(stderr, "select failed: %s\n", strerror(errno));
					exit(EXIT_FAILURE);
				}
			}

			if (ctx->targetAddr.ss_family == AF_INET6 &&
				ctx->sock.privilege == SOCKET_PRIV_USER)
				drainIcmpErrorQueue(ctx->sock.fd, ctx->opts.numeric);

			if (sel == 0)
				break; /* timeout, send next packet */
			if (FD_ISSET(ctx->sock.fd, &fdset))
			{
				tIcmpReplyInfo	replyInfo;
				double			ms;
				int				haveRtt;
				unsigned int	replyBytes;
				const tIpHdr	*ipHdr = NULL;

				if (receiveIcmpReply(ctx, buf, sizeof(buf), &replyInfo, &ipHdr) != 0)
					continue;

				haveRtt = (userPayload >= sizeof(struct timeval) &&
						   (replyInfo.rtt.tv_sec != 0 || replyInfo.rtt.tv_usec != 0));

				ms = 0.0;
				if (haveRtt)
				{
					ms = replyInfo.rtt.tv_sec * 1000.0
					   + replyInfo.rtt.tv_usec / 1000.0;

					if (ctx->stats.received == 1 || ms < ctx->stats.rttMin)
						ctx->stats.rttMin = ms;
					if (ms > ctx->stats.rttMax)
						ctx->stats.rttMax = ms;

					ctx->stats.rttSum += ms;
					ctx->stats.rttSumSq += ms * ms;
				}

				replyBytes = onWireHeader + userPayload;

				if (!ctx->opts.flood && !ctx->opts.quiet)
				{
#if defined(HAJ)
					if (!ctx->opts.numeric)
						printf("%u bytes from %s (%s): icmp_seq=%u ttl=%u",
							   replyBytes,
							   ctx->resolvedIp,
							   ctx->canonicalName,
							   replyInfo.seq,
							   replyInfo.ttl);
					else
#endif
						printf("%u bytes from %s: icmp_seq=%u ttl=%u",
							   replyBytes,
							   ctx->resolvedIp,
							   replyInfo.seq,
							   replyInfo.ttl);
					if (haveRtt)
						printf(" time=%.3f ms", ms);

				}
				if (ipHdr)
				{
					char	currRoute[512];
					size_t routeLen = formatIp4Route((tIpHdr *)ipHdr, currRoute, sizeof(currRoute));
					if (routeLen > 0)
					{
						if (strcmp(currRoute, oldRoute) != 0)
						{
							printf("\n%s\n", currRoute);
							strncpy(oldRoute, currRoute, sizeof(oldRoute));
						}
						else
							printf("\t (same route)\n");
					} else
						putchar('\n');
					printIp4Timestamps((tIpHdr *)ipHdr);
				} else
					putchar('\n');

				if (ctx->opts.timestamp && replyInfo.type == ICMP4_TIMESTAMP_REPLY)
					printIcmpv4TimestampReply((const tIcmp4Echo *)buf);
				fflush(stdout);
			}
		}

		ctx->seq++;

		/* recalc interval for next send */
		double iv = ctx->opts.interval;
		if (ctx->opts.flood && iv <= 0.0)
			iv = 0.01;
		else if (iv <= 0.0)
			iv = PING_DEFAULT_INTERVAL;
		timevalFromDouble(&interval, iv);
		normalizeTimeval(&interval);
	}

	/* handle -W / --linger */
	if (ctx->opts.linger > 0)
		handleLinger(ctx, sentCount, onWireHeader, userPayload);

	printPingSummary(ctx);
}
