#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "../includes/socket.h"
#include "../includes/ping.h"
#include "../includes/utils.h"

tSocketPrivilege
sockDetectPrivilege(void)
{
	if (isRoot())
		return (SOCKET_PRIV_RAW);
	return (SOCKET_PRIV_USER);
}

void
socketInit(
	tPingSocket			*ctx,
	int					family,
	tPingSocketType		type,
	tSocketPrivilege	privilege)
{
	if (!ctx)
		return;
	memset(ctx, 0, sizeof(*ctx));
	ctx->fd = -1;
	ctx->family = family;
	ctx->type = type;
	ctx->privilege = privilege;
	if (family == AF_INET)
		ctx->protocol = IPPROTO_ICMP;
	else
		ctx->protocol = IPPROTO_ICMPV6;
}

int
icmpRequiresPrivilege(tPingSocketType type)
{
	if (type == PING_SOCKET_ADDRESS)
		return (1);
	return (0);
}

int
sockValidatePrivileges(
	const tPingOptions	*opts,
	tSocketPrivilege	privilege)
{
	if (!opts)
		return (-1);
	if (privilege == SOCKET_PRIV_RAW)
		return (0);
	if (opts->flood || opts->preload > 0)
		return (-1);
	if (opts->recordRoute || opts->ipTsType != IP_TS_NONE)
		return (-1);
	return (0);
}

int
pingSocketCreate(tPingSocket *ctx)
{
	if (!ctx)
		return (-1);

	ctx->fd = socket(ctx->family, SOCK_RAW, ctx->protocol);
	if (ctx->fd < 0)
	{
		if (errno == EPERM || errno == EACCES)
		{
			ctx->fd = socket(ctx->family, SOCK_DGRAM, ctx->protocol);
			if (ctx->fd < 0)
			{
				if (errno == EPERM || errno == EACCES || errno == EPROTONOSUPPORT)
					fprintf (stderr, PROG_NAME ": Lacking privilege for icmp socket.\n");
				else
					fprintf (stderr, PROG_NAME ": %s\n", strerror (errno));
				return (-1);
			}
			ctx->privilege = SOCKET_PRIV_USER;
		}
	} else
		ctx->privilege = SOCKET_PRIV_RAW;

	return (0);
}


void
pingSocketClose(tPingSocket *ctx)
{
	if (!ctx)
		return;
	if (ctx->fd >= 0)
		close(ctx->fd);
	ctx->fd = -1;
}


int
socketApplyCommonOptions(
	tPingSocket			*ctx,
	const tPingOptions	*opts)
{
	if (!ctx || !opts)
		return (-1);
	if (opts->debug)
		setsockopt(ctx->fd, SOL_SOCKET, SO_DEBUG, &(int){1}, sizeof(int));
	if (opts->ignRouting)
		setsockopt(ctx->fd, SOL_SOCKET, SO_DONTROUTE, &(int){1}, sizeof(int));
	return (0);
}

static void fatalError(const char *msg)
{
	fprintf(stderr, "Fatal error: %s\n", msg);
	exit(EXIT_FAILURE);
}

/**
 * @briefBuild set of IP options based on ping options and privilege level
 * - fills buf with options data and returns total length of options in bytes
 * - handles Timestamp and Record Route options based on user request and privileges
 * @param opts - ping options
 * @param privilege - socket privilege level
 * @param buf - buffer to fill with IP options
 * @param bufSize - size of the buffer in bytes
 * @return socklen_t 
 */
static socklen_t
buildIpOptions(const tPingOptions *opts, int privilege, unsigned char *buf, socklen_t bufSize)
{
	if (!opts || !buf || bufSize < 4)
		return 0;

	memset(buf, 0, bufSize);

	socklen_t used = 0;

	/* --- Timestamp --- */
	if (opts->ipTsType != IP_TS_NONE)
	{
		const unsigned int hdrLen = 4; /* type(1) + len(1) + ptr(1) + flags(1) */
		unsigned int entrySize;

		/* size of each timestamp entry depends on type (tsonly vs ts+addr) */
#if defined(HAJ)
		if (opts->ipTsType == IP_TS_PRESPEC)
			entrySize = 8; /* addr(4) + ts(4) */
		else
#endif
		if (opts->ipTsType == IP_TS_ADDR)
			entrySize = 8; /* addr + ts */
		else
			entrySize = 4; /* tsonly: ts only */

		/* how many entries can we fit at max in the remaining buffer? */
		if (bufSize <= hdrLen)
			return 0; /* impossible */

		unsigned int remaining = (unsigned int)bufSize - hdrLen;
		unsigned int maxEntries = remaining / entrySize;
		if (maxEntries == 0)
			return 0; /* not enough space for an entry */

		/* total length of the TS option to write */
		unsigned int optLen = hdrLen + maxEntries * entrySize;
		if (optLen < hdrLen)
			optLen = hdrLen;

		/* writing TS header */
		buf[used + 0] = IPOPT_TIMESTAMP;		/* type */
		buf[used + 1] = (unsigned char)optLen;	/* length: exact value */
		buf[used + 2] = 5;						/* pointer to next free (1-based) */
#if defined(HAJ)
		if (opts->ipTsType == IP_TS_PRESPEC)
			buf[used + 3] = IPOPT_TS_PRESPEC;
		else
#endif
		if (opts->ipTsType == IP_TS_ADDR)
			buf[used + 3] = IPOPT_TS_TSANDADDR;
		else
			buf[used + 3] = IPOPT_TS_TSONLY;

		/* payload left zero — kernel/routers will fill timestamps (or you can pre-specify addresses if PRESPEC) */
		used += optLen;
	}

	/* --- Record Route (RR) --- */
	if (opts->recordRoute && privilege == SOCKET_PRIV_RAW)
	{
		/* desired length for RR (39 is classic: 3(header) + 9*4 = 39) */
		const unsigned int desired_rr_len = 39;
		/* if HAJ: we can concatenate (if it fits), otherwise we overwrite */
#if defined(HAJ)
		/* if concatenation */
		if ((unsigned int)used + 3 <= (unsigned int)bufSize)
		{
			/* calculate achievable RR length in the remaining buffer */
			unsigned int avail = (unsigned int)bufSize - (unsigned int)used;
			unsigned int rrLen = (avail >= desired_rr_len) ? desired_rr_len : avail;
			if (rrLen < 3)
				; /* not enough space -> do not add RR */
			else
			{
				buf[used + 0] = IPOPT_RR;
				buf[used + 1] = (unsigned char) rrLen;
				buf[used + 2] = 4; /* initial pointer */
				/* the rest is zero (address slots) */
				used += rrLen;
			}
		}
#else
		/* without HAJ: RR overwrites everything (requested behavior). we overwrite buf from the beginning */
		if ((unsigned int)bufSize >= 3)
		{
			unsigned int rrLen = (bufSize >= desired_rr_len) ? desired_rr_len : (unsigned int)bufSize;
			memset(buf, 0, bufSize);
			buf[0] = IPOPT_RR;
			buf[1] = (unsigned char) rrLen;
			buf[2] = 4;
			used = rrLen;
		}
#endif
	}

	/* --- padding: align on 4 bytes by adding NOP (1) if needed --- */
	while ((used % 4) != 0 && used < bufSize)
	{
		buf[used++] = IPOPT_NOP;
	}

	if (used > bufSize)
		used = bufSize;

	return used;
}


int socketApplyOptions(tPingSocket *ctx, const tPingOptions *opts)
{
	int one = 1;
	int ret;

	if (!ctx || !opts)
		return (-1);

	if (ctx->family == AF_INET)
	{
		/* Activate the reception of TTL in received packets */
		ret = setsockopt(ctx->fd, IPPROTO_IP, IP_RECVTTL, &one, sizeof(one));
		if (ret < 0)
			fatalError("setsockopt IP_RECVTTL");

		/* Set a custom TTL if specified */
		if (opts->ttl)
		{
			ret = setsockopt(ctx->fd, IPPROTO_IP, IP_TTL, &opts->ttl, sizeof(opts->ttl));
			if (ret < 0)
				fatalError("setsockopt IP_TTL");
		}

		/* Set a custom TOS if specified in ipv4 header */
		if (opts->tos)
		{
			ret = setsockopt(ctx->fd, IPPROTO_IP, IP_TOS, &opts->tos, sizeof(opts->tos));
			if (ret < 0)
				fatalError("setsockopt IP_TOS");
		}

		if (ctx->privilege == SOCKET_PRIV_USER)
		{
			/* For DGRAM sockets, we need to connect to the target to receive ICMP errors related to that target */
			struct sockaddr_in dst4;
			memset(&dst4, 0, sizeof(dst4));
			dst4.sin_family = AF_INET;
			dst4.sin_addr = ((struct sockaddr_in *)&ctx->targetAddr)->sin_addr;
			dst4.sin_port = 0;

			if (connect(ctx->fd, (struct sockaddr *)&dst4, sizeof(dst4)) < 0)
			{
				perror("connect ICMP DGRAM");
				close(ctx->fd);
				ctx->fd = -1;
				return (-1);
			}
			/* Activate the reception of ICMP errors (for unreachable, time exceeded, etc.) */
			ret = setsockopt(ctx->fd, SOL_IP, IP_RECVERR, &one, sizeof(one));
			if (ret < 0)
				fatalError("setsockopt IP_RECVERR");
		}
		/* Build and set IP options if needed */
		{
			unsigned char ipOpts[40];
			socklen_t len = buildIpOptions(opts, ctx->privilege, ipOpts, sizeof(ipOpts));
			if (len > 0)
			{
				ret = setsockopt(ctx->fd, IPPROTO_IP, IP_OPTIONS, ipOpts, len);
				if (ret < 0)
					fatalError("setsockopt IP_OPTIONS");
			}
		}
	}
	else if (ctx->family == AF_INET6)
	{
		/* Activate the reception of Hop Limit in received packets */
		ret = setsockopt(ctx->fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &one, sizeof(one));
		if (ret < 0)
			fatalError("setsockopt IPV6_RECVHOPLIMIT");

		if (opts->ttl)
		{
			ret = setsockopt(ctx->fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &opts->ttl, sizeof(opts->ttl));
			if (ret < 0)
				fatalError("setsockopt IPV6_UNICAST_HOPS");
		}
		if (opts->tos)
		{
			ret = setsockopt(ctx->fd, IPPROTO_IPV6, IPV6_TCLASS, &opts->tos, sizeof(opts->tos));
			if (ret < 0)
				fatalError("setsockopt IPV6_TCLASS");
		}

		if (ctx->privilege == SOCKET_PRIV_USER)
		{
			/* For DGRAM sockets, we need to connect to the target to receive ICMP errors related to that target */
			struct sockaddr_in6 dst6;
			memset(&dst6, 0, sizeof(dst6));
			dst6.sin6_family = AF_INET6;
			dst6.sin6_addr = ((struct sockaddr_in6 *)&ctx->targetAddr)->sin6_addr;

			if (connect(ctx->fd, (struct sockaddr *)&dst6, sizeof(dst6)) < 0)
			{
				perror("connect ICMPv6 DGRAM");
				close(ctx->fd);
				ctx->fd = -1;
				return (-1);
			}
			/* Activate the reception of ICMP errors (for unreachable, time exceeded, etc.) */
			ret = setsockopt(ctx->fd, IPPROTO_IPV6, IPV6_RECVERR, &one, sizeof(one));
			if (ret < 0)
				fatalError("setsockopt IPV6_RECVERR");
		}
	}

	return (0);
}