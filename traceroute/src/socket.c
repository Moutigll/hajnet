#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "../../hajlib/include/hmemory.h"
#include "../../hajlib/include/hprintf.h"

#include "../includes/network.h"


static void	fatalError(const char *msg)
{
	ft_dprintf(STDERR_FILENO, "Fatal error: %s\n", msg);
	exit(EXIT_FAILURE);
}

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
		ft_dprintf(STDERR_FILENO, "socket() failed: %s\n", strerror(errno));
		return (-1);
	}

	/* Apply common options */
	if (opts->debug)
		setsockopt(ctx->fd, SOL_SOCKET, SO_DEBUG, &(int){1}, sizeof(int));
	if (opts->dontFragment && ctx->family == AF_INET)
		setsockopt(ctx->fd, IPPROTO_IP, IP_MTU_DISCOVER, &(int){IP_PMTUDISC_DO}, sizeof(int));

	if (opts->sourceAddr)
	{
		struct sockaddr_in	src4;
		struct sockaddr_in6	src6;
		ft_bzero(&src4, sizeof(src4));
		ft_bzero(&src6, sizeof(src6));

		if (ctx->family == AF_INET)
		{
			src4.sin_family = AF_INET;
			if (!inet_pton(AF_INET, opts->sourceAddr, &src4.sin_addr))
				fatalError("Invalid source IPv4 address");
			if (bind(ctx->fd, (struct sockaddr *)&src4, sizeof(src4)) < 0)
				fatalError("bind() source IPv4 failed");
		}
		else
		{
			src6.sin6_family = AF_INET6;
			if (!inet_pton(AF_INET6, opts->sourceAddr, &src6.sin6_addr))
				fatalError("Invalid source IPv6 address");
			if (bind(ctx->fd, (struct sockaddr *)&src6, sizeof(src6)) < 0)
				fatalError("bind() source IPv6 failed");
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
