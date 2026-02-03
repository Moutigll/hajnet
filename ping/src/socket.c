#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "../includes/socket.h"
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
	int	type;

	if (!ctx)
		return (-1);

	type = SOCK_DGRAM;
	if (ctx->privilege == SOCKET_PRIV_RAW)
		type = SOCK_RAW;
	ctx->fd = socket(ctx->family, type, ctx->protocol);
	if (ctx->fd < 0)
		return (-1);
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