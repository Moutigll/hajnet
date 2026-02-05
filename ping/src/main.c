#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../../common/includes/ip.h"
#include "../includes/ping.h"
#include "../includes/resolve.h"
#include "../includes/usage.h"
#include "../includes/utils.h"

/**
 * @brief Print all resolved IP addresses from addrinfo list
 * @param res - addrinfo linked list from getaddrinfo
 * @param host - hostname for logging
 */
static void
printAllResolvedIPs(struct addrinfo *res, const char *host)
{
	struct addrinfo	*cur;
	char			ipStr[INET6_ADDRSTRLEN];

	printf("All resolved IPs for '%s':\n", host);
	for (cur = res; cur; cur = cur->ai_next)
	{
		if (cur->ai_family == AF_INET)
			inet_ntop(AF_INET,
					  &((struct sockaddr_in *)cur->ai_addr)->sin_addr,
					  ipStr, sizeof(ipStr));
		else if (cur->ai_family == AF_INET6)
			inet_ntop(AF_INET6,
					  &((struct sockaddr_in6 *)cur->ai_addr)->sin6_addr,
					  ipStr, sizeof(ipStr));
		else
			continue;
		printf("  %s\n", ipStr);
	}
}

/**
 * @brief Print the primary resolved IP address
 * @param addr - sockaddr_storage of the primary resolved address
 * @param host - hostname for logging
 */
static void
printPrimaryIP(const struct sockaddr_storage *addr, const char *host)
{
	char	ipStr[INET6_ADDRSTRLEN] = {0};

	if (addr->ss_family == AF_INET)
		inet_ntop(AF_INET,
				  &((struct sockaddr_in *)addr)->sin_addr,
				  ipStr, sizeof(ipStr));
	else if (addr->ss_family == AF_INET6)
		inet_ntop(AF_INET6,
				  &((struct sockaddr_in6 *)addr)->sin6_addr,
				  ipStr, sizeof(ipStr));
	if (*ipStr)
		printf("Resolved host '%s' to IP: %s\n", host, ipStr);
}

/**
 * @brief Setup the ping socket with given options and target address
 * @param sockCtx - ping socket context to setup
 * @param opts - ping options to apply
 * @param target - target address to ping
 * @return 0 on success, -1 on failure
 */
static int
setupPingSocket(
	tPingSocket						*sockCtx,
	const tPingOptions				*opts,
	const struct sockaddr_storage	*target)
{
	int	ret;

	sockCtx->privilege = sockDetectPrivilege();

	/* Validate options against privileges */
	if (sockValidatePrivileges(opts, sockCtx->privilege) != 0)
	{
		fprintf(stderr, "Some options require root privileges.\n");
		return (-1);
	}

	/* Initialize socket context */
	socketInit(sockCtx,
			   target->ss_family,
			   opts->echo ? PING_SOCKET_ECHO :
			   opts->timestamp ? PING_SOCKET_TIMESTAMP :
			   opts->address ? PING_SOCKET_ADDRESS : PING_SOCKET_ECHO,
			   sockCtx->privilege);

	sockCtx->targetAddr = *target;

	ret = pingSocketCreate(sockCtx);
	if (ret != 0)
		return (-1);

	if (socketApplyCommonOptions(sockCtx, opts) != 0)
	{
		fprintf(stderr, "Failed to apply socket options.\n");
		pingSocketClose(sockCtx);
		return (-1);
	}

	if (socketApplyOptions(sockCtx, opts) != 0)
	{
		fprintf(stderr, "Failed to apply socket options.\n");
		pingSocketClose(sockCtx);
		return (-1);
	}

	/* Log socket state for verbose level 2 */
	if (opts->verbose > 1)
		printf("Socket fd %d created (family=%s, type=%s, proto=%s(%d), priv=%s)\n",
			   sockCtx->fd,
			   sockCtx->family == AF_INET ? "AF_INET" : "AF_INET6",
			   sockTypeToStr(sockCtx->type),
			   protoToStr(sockCtx->protocol),
			   sockCtx->protocol,
			   sockCtx->privilege == SOCKET_PRIV_RAW ? "RAW" : "USER");
	return (0);
}

int
main(int argc, char **argv)
{
	tParseResult				parseRes;
	int							ret;
	int							i;

	ret = parseArgs(argc, argv, &parseRes);
	if (ret == PARSE_HELP)
		return (printFullHelp(argv[0]), EXIT_SUCCESS);
	if (ret == PARSE_USAGE)
		return (printUsage(argv[0]), EXIT_SUCCESS);

	if (parseRes.posCount == 0)
	{
		printMissingHost(argv[0]);
		return (EXIT_MISSING_HOST);
	}

	if (parseRes.options.flood && parseRes.options.interval != 0.0)
	{
		fprintf(stderr, "%s: -f and -i incompatible options\n", argv[0]);
		return (EXIT_FAILURE);
	}

	for (i = 0; i < parseRes.posCount; i++)
	{
		const char					*host;
		struct sockaddr_storage		targetAddr;
		socklen_t					addrLen;
		struct addrinfo				*addrList;
		tPingSocket					sockCtx;
		tPingContext				ctx;
		tIpType						ipMode;

		host = parseRes.positionals[i];
		addrList = NULL;
		ipMode = IP_TYPE_V4;

#if defined(HAJ)
		ipMode = IP_TYPE_UNSPEC;
		if (parseRes.options.v4)
			ipMode = IP_TYPE_V4;
		else if (parseRes.options.v6)
			ipMode = IP_TYPE_V6;
#endif

		ret = resolveHost(host,
						  &targetAddr,
						  &addrLen,
						  &addrList,
						  ipMode);
		if (ret != 0)
		{
			fprintf(stderr,
					"%s: %s\n",
					argv[0],
					parseRes.options.verbose ?
					gai_strerror(ret) : "unknown host");
			continue;
		}

		if (parseRes.options.verbose > 1)
			printPrimaryIP(&targetAddr, host);
		if (parseRes.options.verbose > 2 && addrList)
			printAllResolvedIPs(addrList, host);

		if (setupPingSocket(&sockCtx,
							&parseRes.options,
							&targetAddr) != 0)
		{
			freeaddrinfo(addrList);
			continue;
		}

		memset(&ctx, 0, sizeof(ctx));
		ctx.opts = parseRes.options;
		ctx.sock = sockCtx;
		ctx.targetAddr = targetAddr;
		ctx.addrLen = addrLen;
		ctx.pid = getpid() & 0xFFFF;
		strncpy(ctx.targetHost, host, sizeof(ctx.targetHost) - 1);

#if defined(HAJ)
		{
			char	tmpCanon[NI_MAXHOST];

			tmpCanon[0] = '\0';
			if (addrList && addrList->ai_canonname)
			{
				strncpy(tmpCanon,
						addrList->ai_canonname,
						sizeof(tmpCanon) - 1);
				tmpCanon[sizeof(tmpCanon) - 1] = '\0';
			}

			resolvePeerName(&targetAddr,
							addrLen,
							tmpCanon,
							ctx.canonicalName,
							sizeof(ctx.canonicalName));
		}
#endif

		if (targetAddr.ss_family == AF_INET)
			inet_ntop(AF_INET,
					  &((struct sockaddr_in *)&targetAddr)->sin_addr,
					  ctx.resolvedIp,
					  sizeof(ctx.resolvedIp));
		else if (targetAddr.ss_family == AF_INET6)
			inet_ntop(AF_INET6,
					  &((struct sockaddr_in6 *)&targetAddr)->sin6_addr,
					  ctx.resolvedIp,
					  sizeof(ctx.resolvedIp));

		runPingLoop(&ctx);

		pingSocketClose(&ctx.sock);
		freeaddrinfo(addrList);
		printf("\n");
	}
	return (EXIT_SUCCESS);
}