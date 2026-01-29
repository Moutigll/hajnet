#include <netinet/in.h>
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
	type = SOCK_RAW;
	if (ctx->privilege == SOCKET_PRIV_USER)
		type = SOCK_DGRAM;
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

int
socketApplyIpv4Options(
	tPingSocket			*ctx,
	const tPingOptions	*opts)
{
	if (!ctx || !opts)
		return (-1);
	if (opts->ttl > 0)
		setsockopt(ctx->fd, IPPROTO_IP, IP_TTL,
			&opts->ttl, sizeof(opts->ttl));
	if (opts->tos >= 0)
		setsockopt(ctx->fd, IPPROTO_IP, IP_TOS,
			&opts->tos, sizeof(opts->tos));
	return (0);
}
