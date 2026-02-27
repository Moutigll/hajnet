#include "../../hajlib/include/hprintf.h"

#include "../includes/network.h"
#include "../includes/traceroute.h"
#include <sys/socket.h>
#include <unistd.h>

static int validateArgs(tParseResult *result, struct sockaddr_storage *dstAddr)
{
	if (result->options.firstTtl < 1 || result->options.firstTtl > result->options.maxTtl)
		ft_dprintf(STDERR_FILENO, "first hop out of range\n");
	else if (result->options.maxTtl < 1 || result->options.maxTtl > 255)
		ft_dprintf(STDERR_FILENO, "max hops cannot be more than 255\n");
	else if (result->options.queries < 1 || result->options.queries > MAX_PROBES)
		ft_dprintf(STDERR_FILENO, "no more than " _T(MAX_PROBES) " probes per hop\n");
	else if (result->options.waitSpec.here < 0 || result->options.waitSpec.near < 0 || result->options.waitSpec.max < 0)
		ft_dprintf(STDERR_FILENO, "bad wait specifications `%f,%f,%f' used\n",
			result->options.waitSpec.max, result->options.waitSpec.here, result->options.waitSpec.near);
	else if (result->options.packetSize > 65500)
		ft_dprintf(STDERR_FILENO, "too big packetlen %d specified\n", result->options.packetSize);
	else if (result->options.sourceAddr.sa.sa_family && result->options.sourceAddr.sa.sa_family != dstAddr->ss_family)
		ft_dprintf(STDERR_FILENO, "IP version mismatch in addresses specified\n");
	else if (result->options.sendWait < 0)
		ft_dprintf(STDERR_FILENO, "bad sendtime `%f' specified\n", result->options.sendWait);
	else
		return (EXIT_SUCCESS);
	return (EXIT_BAD_ARGS);
}

static int	initSocket(tTracerouteSocket *socketCtx,
						tParseResult *parseResult,
						struct sockaddr_storage *dstAddr)
{
	int	family;

	family = (dstAddr->ss_family == AF_INET) ? AF_INET : AF_INET6;

	tracerouteSocketInit(socketCtx,
						 family,
						 parseResult->options.method);

	if (tracerouteSocketCreate(socketCtx,
							   &parseResult->options) < 0)
	{
#if defined (HAJ)
		ft_dprintf(STDERR_FILENO,
			"Failed to create socket\n");
#endif
		return (EXIT_FAILURE);
	}
	return (EXIT_SUCCESS);
}

static int	runTraceroute(tParseResult *parseResult,
							struct sockaddr_storage *dstAddr,
							socklen_t dstLen)
{
	tTracerouteSocket	socketCtx;

	(void)dstLen;
	if (initSocket(&socketCtx, parseResult, dstAddr) != EXIT_SUCCESS)
		return (EXIT_FAILURE);

	ft_printf("Traceroute to %s, %d hops max, %d byte packets\n",
			  parseResult->positionals[0],
			  parseResult->options.maxTtl,
			  0);

	/* TODO: send probes here */

	tracerouteSocketClose(&socketCtx);
	return (EXIT_SUCCESS);
}

int	main(int argc, char **argv)
{
	tParseResult			parseResult;
	int						parseRet;
	struct sockaddr_storage	dstAddr;
	socklen_t				dstLen;
	int						ret;

	if (argc == 1)
		return (printFullHelp(argv[0]), EXIT_SUCCESS);

	parseRet = parseArgs(argc, argv, &parseResult);
	if (parseRet == PARSE_HELP)
		return (printFullHelp(argv[0]), EXIT_SUCCESS);
	if (parseRet == PARSE_VERSION)
	{
		ft_printf("HajRoute (hajnet) 1.0.0\n");
		return (EXIT_SUCCESS);
	}
	if (parseRet != PARSE_OK)
		return (EXIT_FAILURE);

	ret = resolveDestination(&parseResult, &dstAddr, &dstLen, argc, argv);
	if (ret != EXIT_SUCCESS)
		return (ret);

	if (validateArgs(&parseResult, &dstAddr) != EXIT_SUCCESS)
		return (EXIT_BAD_ARGS);

	return (runTraceroute(&parseResult, &dstAddr, dstLen));
}
