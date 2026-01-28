#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "../includes/ft_ping.h"
#include "../includes/parser.h"
#include "../includes/resolve.h"
#include "../includes/usage.h"

/**
 * @brief Print all resolved IP addresses from addrinfo list
 * @param res - addrinfo linked list from getaddrinfo
 * @param host - hostname for logging
 */
static void printAllResolvedIPs(struct addrinfo *res, const char *host)
{
	struct addrinfo *cur;
	char ipStr[INET6_ADDRSTRLEN];

	printf("All resolved IPs for '%s':\n", host);
	for (cur = res; cur; cur = cur->ai_next)
	{
		if (cur->ai_family == AF_INET)
		{
			inet_ntop(AF_INET, &((struct sockaddr_in *)cur->ai_addr)->sin_addr,
					  ipStr, sizeof(ipStr));
			printf("  %s\n", ipStr);
		}
		else if (cur->ai_family == AF_INET6)
		{
			inet_ntop(AF_INET6, &((struct sockaddr_in6 *)cur->ai_addr)->sin6_addr,
					  ipStr, sizeof(ipStr));
			printf("  %s\n", ipStr);
		}
	}
}

int main(int argc, char **argv)
{
	tParseResult		res;
	int					ret;
	struct sockaddr_storage	targetAddr;
	socklen_t			addrLen;
	struct addrinfo		*allAddrs = NULL; // store full list for -vvv

	/* Parse command line arguments */
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

	/* Check if a host was provided */
	if (res.posCount == 0)
	{
		printMissingHost(argv[0]);
		return EXIT_MISSING_HOST;
	}

	/* Determine preferred IP version */
#if defined(HAJ)
	tIpType ipMode = IP_TYPE_UNSPEC;
	if (res.options.v4)
		ipMode = IP_TYPE_V4;
	else if (res.options.v6)
		ipMode = IP_TYPE_V6;
#else
	tIpType ipMode = IP_TYPE_V4;
#endif

	/* Resolve host to first usable IP and optionally get all addresses for verbose */
	ret = resolveHost(res.positionals[res.posCount - 1],
					  &targetAddr,
					  &addrLen,
					  &allAddrs,   // pass pointer to get full list
					  ipMode);
	if (ret != 0)
	{
		if (res.options.verbose <= 1)
		{
#if defined(HAJ)
			fprintf(stderr, "%s: unknown host\n", PROG_NAME);
#else
			fprintf(stderr, "%s: unknown host\n", argv[0]);
#endif
		}
		else
		{
			fprintf(stderr, "Failed to resolve host '%s': %s\n",
					res.positionals[res.posCount - 1],
					gai_strerror(ret));
		}
		return EXIT_FAILURE;
	}

	/* Verbose logging: show primary resolved IP if verbose > 1 */
	if (res.options.verbose > 1)
	{
		char ipStr[INET6_ADDRSTRLEN] = {0};

		if (targetAddr.ss_family == AF_INET)
			inet_ntop(AF_INET,
					  &((struct sockaddr_in *)&targetAddr)->sin_addr,
					  ipStr, sizeof(ipStr));
		else if (targetAddr.ss_family == AF_INET6)
			inet_ntop(AF_INET6,
					  &((struct sockaddr_in6 *)&targetAddr)->sin6_addr,
					  ipStr, sizeof(ipStr));

		printf("Resolved host '%s' to IP: %s\n",
			   res.positionals[res.posCount - 1],
			   ipStr);
	}

	/* If verbose level 3, print all resolved IP addresses */
	if (res.options.verbose > 2 && allAddrs)
		printAllResolvedIPs(allAddrs, res.positionals[res.posCount - 1]);

	/* Start the ping using the first resolved IP */
	// startPing(&targetAddr, addrLen, &res.options);

	/* Free addrinfo list if it was returned */
	if (allAddrs)
		freeaddrinfo(allAddrs);

	return EXIT_SUCCESS;
}
