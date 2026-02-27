#include <string.h>
#include <errno.h>

#include "../../hajlib/include/hmemory.h"
#include "../../hajlib/include/hprintf.h"
#include "../../hajlib/include/hstring.h"

#include "../includes/network.h"

void tracerouteSocketInit(tTracerouteSocket *ctx, int family, tProbeMethod method)
{
	if (!ctx)
		return;
	ft_bzero(ctx, sizeof(*ctx));
	ctx->fd = -1;
	ctx->family = family;
	ctx->method = method;
	if (geteuid() == 0)
		ctx->privilege = SOCKET_PRIV_RAW;
	else
		ctx->privilege = SOCKET_PRIV_USER;
}

int tracerouteSocketCreate(tTracerouteSocket *ctx, const tTracerouteOptions *opts)
{
	int	sockType;
	int	protocol;

	if (!ctx || !opts)
		return (-1);

	/* Determine socket type and protocol */
	switch (opts->method)
	{
		case PROBE_ICMP:
			sockType = SOCK_RAW;
			protocol = (opts->v4 || ctx->family == AF_INET) ? IPPROTO_ICMP : IPPROTO_ICMPV6;
			break ;
		case PROBE_UDP:
		case PROBE_UDPLITE:
			sockType = SOCK_DGRAM;
			protocol = IPPROTO_UDP;
			break ;
		case PROBE_TCP:
			sockType = SOCK_STREAM;
			protocol = IPPROTO_TCP;
			break ;
		case PROBE_DCCP:
			sockType = SOCK_DCCP;
			protocol = IPPROTO_DCCP;
			break ;
		case PROBE_RAW:
			sockType = SOCK_RAW;
			protocol = opts->protocol;
			break ;
		default:
			ft_dprintf(STDERR_FILENO, "Unknown probe method\n");
			return (-1);
	}

	ctx->fd = socket(ctx->family, sockType, protocol);
	if (ctx->fd < 0)
	{
		ft_dprintf(STDERR_FILENO, "\nsocket: %s\n", strerror(errno));
		return (-1);
	}

	/* Apply common options */
	if (opts->debug)
		setsockopt(ctx->fd, SOL_SOCKET, SO_DEBUG, &(int){1}, sizeof(int));
	if (opts->dontFragment && ctx->family == AF_INET)
		setsockopt(ctx->fd, IPPROTO_IP, IP_MTU_DISCOVER, &(int){IP_PMTUDISC_DO}, sizeof(int));

	if (opts->interface)
	{
		if (setsockopt(ctx->fd, SOL_SOCKET, SO_BINDTODEVICE, opts->interface, ft_strlen(opts->interface)) < 0)
		{
			ft_dprintf(STDERR_FILENO, "Failed to bind socket to interface `%s': %s\n", opts->interface, strerror(errno));
			close(ctx->fd);
			ctx->fd = -1;
			return (-1);
		}
	}

	if (opts->sourceAddr.sa.sa_family)
	{
		socklen_t addrLen = (opts->sourceAddr.sa.sa_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
		if (bind(ctx->fd, (struct sockaddr *)&opts->sourceAddr, addrLen) < 0)
		{
			ft_dprintf(STDERR_FILENO, "Failed to bind socket to source address: %s\n", strerror(errno));
			close(ctx->fd);
			ctx->fd = -1;
			return (-1);
		}
	}

	return (0);
}

void tracerouteSocketClose(tTracerouteSocket *ctx)
{
	if (!ctx)
		return;
	if (ctx->fd >= 0)
		close(ctx->fd);
	ctx->fd = -1;
}
