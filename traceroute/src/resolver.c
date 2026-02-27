#include "../../hajlib/include/hprintf.h"
#include "../../hajlib/include/hstring.h"
#include "../../hajlib/include/hutils.h"

#include "../includes/parser.h"
#include "../../common/includes/resolve.h"

#include "../includes/traceroute.h"

/**
 * @file resolver.c
 * @brief Hostname and gateway resolution functions
 */

/**
 * Find position of an argument in argv
 * @param argc Argument count
 * @param argv Argument vector
 * @param arg Argument to find
 * @return Index of argument or -1 if not found
 */
int findArgpos(int argc, char **argv, const char *arg)
{
	int i;

	i = 1;
	while (i < argc)
	{
		if (ft_strcmp(argv[i], arg) == 0)
			return (i);
		i++;
	}
	return (-1);
}

/**
 * Resolve a single gateway address
 * @param gateway Gateway string to resolve
 * @param required_family Required address family (AF_INET/AF_INET6)
 * @return EXIT_SUCCESS on success, EXIT_BAD_ARGS on failure
 */
static int resolveGateway(const char *gateway, int required_family)
{
	struct sockaddr_storage addr;
	socklen_t len;
	int ret;

	/* Resolve with AF_UNSPEC to get address regardless of family */
	ret = resolveHost(gateway, &addr, &len, NULL, AF_UNSPEC);
	if (ret != 0)
	{
		ft_dprintf(STDERR_FILENO, "%s: %s\n\n", gateway, gai_strerror(ret));
		return (EXIT_BAD_ARGS);
	}

	/* Verify family matches required family */
	if (addr.ss_family != required_family)
	{
		ft_dprintf(STDERR_FILENO, 
			"%s: Address family for hostname not supported\n\n", gateway);
		return (EXIT_BAD_ARGS);
	}

	return (EXIT_SUCCESS);
}

/**
 * Validate gateway list from command line
 * @param parseResult Parsed arguments containing gateway string
 * @param family Required address family for gateways
 * @return EXIT_SUCCESS on success, error code on failure
 * 
 * Gateway format: comma-separated list (e.g., "1.1.1.1,2.2.2.2")
 * Checks:
 * - No empty entries
 * - No leading/trailing commas
 * - No consecutive commas
 * - Maximum gateways limit (8 for IPv4, 127 for IPv6)
 * - Each gateway resolves and matches required family
 */
static int validateGateways(tParseResult *parseResult, int index, int family)
{
	char **split;
	int i;
	int ret;
	int maxGateways;
	char *original = parseResult->options.gateways[index];

	if (!original)
		return (EXIT_SUCCESS);

	/* Set maximum gateways based on address family */
	maxGateways = (family == AF_INET6) ? MAX_GATEWAYS_IPV6 : MAX_GATEWAYS_IPV4;
	
	/* Check for leading comma or consecutive commas */
	if (original[0] == ',' && !original[1])
	{
		ft_dprintf(STDERR_FILENO, ": Name or service not known\n\n");
		return (EXIT_BAD_ARGS);
	}

	/* Split gateway string by commas */
	split = ft_split(original, ',');
	if (!split)
		return (EXIT_FAILURE);

	parseResult->options.gatewayCount += ft_tablen((void **)split);

	/* Check maximum gateways limit */
	if (parseResult->options.gatewayCount > maxGateways)
	{
		ft_dprintf(STDERR_FILENO, 
			"Too many gateways specified. No more than %d\n", maxGateways);
		free_tab((void **)split);
		return (EXIT_BAD_ARGS);
	}

	/* Validate each gateway in order */
	i = 0;
	while (split[i])
	{
		ret = resolveGateway(split[i], family);
		if (ret != EXIT_SUCCESS)
		{
			free_tab((void **)split);
			return (ret);
		}
		i++;
	}

	free_tab((void **)split);
	return (EXIT_SUCCESS);
}



int resolveDestination(tParseResult *parseResult,
					  struct sockaddr_storage *dstAddr,
					  socklen_t *dstLen,
					  int argc, char **argv)
{
	int family;
	int ret;

	/* Determine address family from options */
	if (parseResult->options.v4)
		family = IP_TYPE_V4;
	else if (parseResult->options.v6)
		family = IP_TYPE_V6;
	else
#if defined (HAJ)
		family = IP_TYPE_UNSPEC;
#else
		family = IP_TYPE_V6; /* Default to IPv6 if no option specified, as modern systems prefer it */
#endif

	/* Resolve destination host */
	ret = resolveHost(parseResult->positionals[0],
					  dstAddr,
					  dstLen,
					  NULL,
					  family);
	if (ret != 0)
	{
		ft_dprintf(STDERR_FILENO,
			"%s: %s\n",
			parseResult->positionals[0],
			gai_strerror(ret));

		ft_dprintf(STDERR_FILENO, 
			"Cannot handle \"host\" cmdline arg `%s' on position 1 (argc %d)\n",
			parseResult->positionals[0], 
			findArgpos(argc, argv, parseResult->positionals[0]));

		return (EXIT_BAD_ARGS);
	}

	/* Check if second positional is a valid packet length */
	if (parseResult->posCount == 2 && !parseUnsigned(parseResult->positionals[1], &parseResult->options.packetSize))
	{
		ft_dprintf(STDERR_FILENO, 
			"Cannot handle \"packetlen\" cmdline arg `%s' on position 2 (argc %d)\n",
			parseResult->positionals[1], 
			findArgpos(argc, argv, parseResult->positionals[1]));
		return (EXIT_BAD_ARGS);
	}

	/* Validate gateways if present */
	int	gatewayIndex = 0;
	while (gatewayIndex <= 128 && parseResult->options.gateways[gatewayIndex] != NULL)
	{
		ret = validateGateways(parseResult, gatewayIndex, dstAddr->ss_family);
		if (ret != EXIT_SUCCESS)
			return (ret);
		gatewayIndex++;
	}

	return (EXIT_SUCCESS);
}
