#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
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

	ret = pingSocketCreate(sockCtx);
	if (ret != 0)
	{
		perror("pingSocketCreate");
		return (-1);
	}

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

int main(int argc, char **argv)
{
	tParseResult res;
	int ret;

	/* Parse command-line arguments */
	ret = parseArgs(argc, argv, &res);
	switch (ret)
	{
		case PARSE_HELP:
			printFullHelp(argv[0]);
			return EXIT_SUCCESS;
		case PARSE_USAGE:
			printUsage(argv[0]);
			return EXIT_SUCCESS;
		case PARSE_OK:
			break;
	}

	/* Check that at least one host was provided */
	if (res.posCount == 0)
	{
		printMissingHost(argv[0]);
		return EXIT_MISSING_HOST;
	}

	/* Iterate over all provided hosts */
	for (int i = 0; i < res.posCount; i++)
	{
		const char *host = res.positionals[i];
		struct sockaddr_storage targetAddr;
		socklen_t addrLen;
		struct addrinfo *allAddrs = NULL;
		tPingSocket sockCtx;
		tPingContext ctx;
		tIpType ipMode = IP_TYPE_V4;

#if defined(HAJ)
		/* Allow forcing IPv4 / IPv6 */
		ipMode = IP_TYPE_UNSPEC;
		if (res.options.v4)
			ipMode = IP_TYPE_V4;
		else if (res.options.v6)
			ipMode = IP_TYPE_V6;
#endif

		/* Resolve hostname */
		ret = resolveHost(host, &targetAddr, &addrLen, &allAddrs, ipMode);
		if (ret != 0)
		{
			if (res.options.verbose <= 1)
				fprintf(stderr, "%s: unknown host\n", argv[0]);
			else
				fprintf(stderr, "Failed to resolve host '%s': %s\n",
						host, gai_strerror(ret));
			continue;
		}

		/* Verbose output */
		if (res.options.verbose > 1)
			printPrimaryIP(&targetAddr, host);
		if (res.options.verbose > 2 && allAddrs)
			printAllResolvedIPs(allAddrs, host);

		/* Setup raw socket */
		if (setupPingSocket(&sockCtx, &res.options, &targetAddr) != 0)
		{
			if (allAddrs)
				freeaddrinfo(allAddrs);
			continue;
		}

		/* Initialize ping context */
		memset(&ctx, 0, sizeof(ctx));
		ctx.opts = res.options;
		ctx.sock = sockCtx;
		ctx.targetAddr = targetAddr;
		ctx.addrLen = addrLen;
		ctx.seq = 0;
		ctx.pid = getpid() & 0xFFFF; /* ICMP identifier */
		strncpy(ctx.targetHost, host, sizeof(ctx.targetHost) - 1);

		/* Fill resolved IP string safely */
		if (targetAddr.ss_family == AF_INET)
		{
			struct sockaddr_in *addr4 = (struct sockaddr_in *)&targetAddr;
			inet_ntop(AF_INET, &addr4->sin_addr, ctx.resolvedIp, sizeof(ctx.resolvedIp));
		}
		else if (targetAddr.ss_family == AF_INET6)
		{
			struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&targetAddr;
			inet_ntop(AF_INET6, &addr6->sin6_addr, ctx.resolvedIp, sizeof(ctx.resolvedIp));
		}
		else
		{
			snprintf(ctx.resolvedIp, sizeof(ctx.resolvedIp), "unknown");
		}

		/* Run the ping loop */
		runPingLoop(&ctx);

		/* Cleanup */
		pingSocketClose(&ctx.sock);
		if (allAddrs)
			freeaddrinfo(allAddrs);

		printf("\n"); /* separate hosts */
	}

	return EXIT_SUCCESS;
}