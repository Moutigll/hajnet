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
	int	value;

	if (!ctx || !opts)
		return (-1);
	if (opts->debug)
		setsockopt(ctx->fd, SOL_SOCKET, SO_DEBUG, &(int){1}, sizeof(int));
	if (opts->ignRouting)
		setsockopt(ctx->fd, SOL_SOCKET, SO_DONTROUTE, &(int){1}, sizeof(int));
	if (opts->linger >= 0)
	{
		value = opts->linger;
		setsockopt(ctx->fd, SOL_SOCKET, SO_LINGER,
			&(struct linger){1, value}, sizeof(struct linger));
	}
	return (0);
}

static void fatalError(const char *msg)
{
	fprintf(stderr, "Fatal error: %s\n", msg);
	exit(EXIT_FAILURE);
}
	
int
socketApplyOptions(tPingSocket *ctx, const tPingOptions *opts)
{
	int	one;
	int	ret;

	if (!ctx || !opts)
		return (-1);

	one = 1;
	if (ctx->family == AF_INET)
	{
		/* activer réception du TTL (flag = 1) */
		ret = setsockopt(ctx->fd, IPPROTO_IP, IP_RECVTTL, &one, sizeof(one));
		if (ret < 0)
			fatalError("setsockopt IP_RECVTTL");

		/* si user a demandé TTL d'envoi */
		if (opts->ttl)
		{
			ret = setsockopt(ctx->fd, IPPROTO_IP, IP_TTL,
				&opts->ttl, sizeof(opts->ttl));
			if (ret < 0)
				fatalError("setsockopt IP_TTL");
		}
		if (opts->tos)
		{
			ret = setsockopt(ctx->fd, IPPROTO_IP, IP_TOS,
				&opts->tos, sizeof(opts->tos));
			if (ret < 0)
				fatalError("setsockopt IP_TOS");
		}
		if (opts->recordRoute)
		{
			unsigned char	rr[40];
			socklen_t		len;

			memset(rr, 0, sizeof(rr));

			rr[0] = IPOPT_RR;
			rr[1] = sizeof(rr);
			rr[2] = 4;

			len = 3;
			ret = setsockopt(ctx->fd, IPPROTO_IP, IP_OPTIONS, rr, len);
			if (ret < 0)
				fatalError("setsockopt IP_OPTIONS (record route)");
		}
		if (opts->ipTsType != IP_TS_NONE)
		{
			unsigned char	ts[40];
			socklen_t		len;
			int				ret;

			/* Clear buffer */
			memset(ts, 0, sizeof(ts));

			/* IP Timestamp option header */
			ts[0] = IPOPT_TIMESTAMP;	/* Option type */
			ts[1] = sizeof(ts);			/* Total length of the option */
			ts[2] = 5;					/* Pointer to next empty slot (first timestamp) */

			/* Set flags based on requested type */
			if (opts->ipTsType == IP_TS_ONLY)
				ts[3] = IPOPT_TS_TSONLY;
			else if (opts->ipTsType == IP_TS_ADDR)
				ts[3] = IPOPT_TS_TSANDADDR;
		#if defined(HAJ)
			else if (opts->ipTsType == IP_TS_PRESPEC)
				ts[3] = IPOPT_TS_PRESPEC;
		#endif

			/* Total length of option to pass to setsockopt */
			len = ts[1];

			ret = setsockopt(ctx->fd, IPPROTO_IP, IP_OPTIONS, ts, len);
			if (ret < 0)
				fatalError("setsockopt IP_OPTIONS (timestamp)");
		}
	}
	else if (ctx->family == AF_INET6)
	{
		/* activer réception du hoplimit */
		ret = setsockopt(ctx->fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT,
			&one, sizeof(one));
		if (ret < 0)
			fatalError("setsockopt IPV6_RECVHOPLIMIT");

		if (opts->ttl)
		{
			ret = setsockopt(ctx->fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS,
				&opts->ttl, sizeof(opts->ttl));
			if (ret < 0)
				fatalError("setsockopt IPV6_UNICAST_HOPS");
		}
		if (opts->tos)
		{
			ret = setsockopt(ctx->fd, IPPROTO_IPV6, IPV6_TCLASS,
				&opts->tos, sizeof(opts->tos));
			if (ret < 0)
				fatalError("setsockopt IPV6_TCLASS");
		}
	}
	return (0);
}