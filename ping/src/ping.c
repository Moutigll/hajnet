
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


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

	/* prepare payload: zero and, if possible, copy timeval at start */
	if (payloadLen > 0)
		memset(payload, 0, payloadLen);
	if (payloadLen >= (uint32_t)sizeof(tv))
	{
		gettimeofday(&tv, NULL);
		memcpy(payload, &tv, sizeof(tv));
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
				sizeof(tIcmp4Echo),
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
	sent = sendto(ctx->sock.fd,
					packet,
					packetLen,
					0,
					(struct sockaddr *)&ctx->targetAddr,
					ctx->addrLen);
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

	/* Parse IP header from received buffer */
	static tIpHdr ipHdr;
	size_t ipHeaderLen = parseIpHeaderFromBuffer(buf, (size_t)n, &ipHdr);
	if (ipHeaderLen == 0)
		return (-1);

	*ipHdrOut = &ipHdr;
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
			return (-1);

	}
#if defined(AF_INET6)
	else if (ctx->targetAddr.ss_family == AF_INET6)
	{
		if (icmpLen < ICMP6_HDR_LEN)
			return (-1);
		/* only consider IPv6 Echo Reply */
		if (icmp[0] != ICMP6_ECHO_REPLY)
			return (-1);
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
	tIcmpReplyInfo	*info)
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

/* keep your pingLoopInit - it's already fine; ensure it calls timevalFromDouble etc. */
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

	printf("PING %s (%s): %u data bytes\n",
		ctx->targetHost,
		ctx->resolvedIp,
		*userPayload);

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

/* run the ping loop */
void
runPingLoop(tPingContext *ctx)
{
	fd_set			fdset;
	struct timeval	lastSend, interval, now, respTime;
	unsigned char	buf[PING_MAX_PACKET_SIZE];
	unsigned int	sentCount = 0;
	uint32_t		userPayload;
	uint32_t		onWireHeader;

	if (!ctx)
		return;

	/* call initialization */
	pingLoopInit(ctx, &lastSend, &interval, &userPayload, &onWireHeader);

	while (!g_pingInterrupted &&
		   (ctx->opts.count == 0 || sentCount < ctx->opts.count))
	{
		/* send one packet */
		if (sendIcmpPacket(ctx) == 0)
			sentCount++;

		/* wait for replies until next interval */
		while (!g_pingInterrupted)
		{
			FD_ZERO(&fdset);
			FD_SET(ctx->sock.fd, &fdset);

			gettimeofday(&now, NULL);
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
			else if (sel == 0)
				break; /* timeout, send next packet */
			else if (FD_ISSET(ctx->sock.fd, &fdset))
			{
				tIcmpReplyInfo	replyInfo;
				double			ms;
				int				haveRtt;
				unsigned int	replyBytes;

				if (receiveIcmpReply(ctx, buf, sizeof(buf), &replyInfo) != 0)
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

#if defined(HAJ)
				printf("%u bytes from %s (%s): icmp_seq=%u ttl=%u",
					   replyBytes,
					   ctx->resolvedIp,
					   ctx->canonicalName,
					   replyInfo.seq,
					   replyInfo.ttl);
#else
				printf("%u bytes from %s: icmp_seq=%u ttl=%u",
						   replyBytes,
						   ctx->resolvedIp,
						   replyInfo.seq,
						   replyInfo.ttl);
#endif

				if (haveRtt)
					printf(" time=%.3f ms", ms);

				printf("\n");
				if (ctx->opts.timestamp && replyInfo.type == ICMP4_TIMESTAMP_REPLY)
					printIcmpv4TimestampReply((const tIcmp4Echo *)buf);

			}
		}

		gettimeofday(&lastSend, NULL);
		ctx->seq++;
	}

	printPingSummary(ctx);
}
