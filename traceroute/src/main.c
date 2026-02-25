#include "../../hajlib/include/hprintf.h"
#include "../../hajlib/include/hstring.h"

#include "../includes/socket.h"
#include "../../common/includes/resolve.h"

#include "../includes/traceroute.h"

static int findArgpos(int argc, char **argv, const char *arg)
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

int	main(int argc, char **argv)
{
	tParseResult			parseResult;
	int						parseRet;
	struct sockaddr_storage	dstAddr;
	socklen_t				dstLen;
	tTracerouteSocket		socketCtx;

	if (argc == 1)
		return (printFullHelp(), EXIT_SUCCESS);

	parseRet = parseArgs(argc, argv, &parseResult);
	if (parseRet == PARSE_HELP)
		return (printFullHelp(), EXIT_SUCCESS);
	else if (parseRet == PARSE_VERSION)
	{
		ft_printf("HajRoute (hajnet) 1.0.0\n");
		return (EXIT_SUCCESS);
	}
	else if (parseRet != PARSE_OK)
		return (EXIT_FAILURE);

	if (resolveHost(parseResult.positionals[0], &dstAddr, &dstLen, NULL,
					(parseResult.options.v4) ? IP_TYPE_V4 :
					(parseResult.options.v6) ? IP_TYPE_V6 : IP_TYPE_UNSPEC) != 0)
	{
		ft_dprintf(STDERR_FILENO, "%s: Name or service not known\n",
				   parseResult.positionals[0]);
		ft_dprintf(STDERR_FILENO, "Cannot handle \"host\" cmdline arg `%s' on position 1 (argc %d)\n",
				   parseResult.positionals[0], findArgpos(argc, argv, parseResult.positionals[0]));
		return (EXIT_BAD_ARGS);
	}

	/* --- Initialisation et création du socket --- */
	tracerouteSocketInit(&socketCtx,
						 (dstAddr.ss_family == AF_INET) ? AF_INET : AF_INET6,
						 parseResult.options.method);
	if (tracerouteSocketCreate(&socketCtx, &parseResult.options) < 0)
	{
		ft_dprintf(STDERR_FILENO, "Failed to create socket\n");
		return (EXIT_FAILURE);
	}

	/* --- Affichage de base --- */
	ft_printf("Traceroute to %s, %d hops max, %d byte packets\n",
			  parseResult.positionals[0],
			  parseResult.options.maxTtl,
			  0);

	/* --- TODO: ici on peut commencer à envoyer les probes --- */

	tracerouteSocketClose(&socketCtx);
	return (EXIT_SUCCESS);
}
