#include "../../hajlib/include/hprintf.h"

#include "../includes/traceroute.h"

int	main(int argc, char **argv)
{
	tParseResult	parseResult;
	int				parseRet;

	parseRet = parseArgs(argc, argv, &parseResult);
	if (parseRet == PARSE_HELP)
		return (printFullHelp(argv[0]), EXIT_SUCCESS);
	else if (parseRet == PARSE_VERSION)
	{
		ft_printf("HajRoute (hajnet) 1.0.0\n");
		return (EXIT_SUCCESS);
	}
	else if (parseRet != PARSE_OK)
		return (EXIT_FAILURE);


	ft_printf("Traceroute to %s, %d hops max, %d byte packets\n",
		parseResult.positionals[0],
		parseResult.options.maxTtl,
		0);
	return (EXIT_SUCCESS);
}
