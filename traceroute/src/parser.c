#include <limits.h>

#include "../../hajlib/include/hajlib.h" /* IWYU pragma: keep */

#include "../includes/traceroute.h"

typedef enum eLongOption
{
	OPT_V4				= '4',
	OPT_V6				= '6',
	OPT_DEBUG			= 'd',
	OPT_DONT_FRAGMENT	= 'F',
	OPT_FIRST_TTL		= 'f',
	OPT_GATEWAY			= 'g',
	OPT_ICMP			= 'I',
	OPT_TCP				= 'T',
	OPT_INTERFACE		= 'i',
	OPT_MAX_HOPS		= 'm',
	OPT_SIM_QUERIES		= 'N',
	OPT_NUMERIC			= 'n',
	OPT_PORT			= 'p',
	OPT_TOS				= 't',
	OPT_FLOWLABEL		= 'l',
	OPT_WAIT			= 'w',
	OPT_QUERIES			= 'q',
	OPT_BYPASS			= 'r',
	OPT_SOURCE			= 's',
	OPT_SENDWAIT		= 'z',
	OPT_EXTENSIONS		= 'e',
	OPT_AS_LOOKUP		= 'A',
	OPT_MODULE			= 'M',
	OPT_OPTIONS			= 'O',
	OPT_SPORT			= 256,
	OPT_FWMARK			= 257,
	OPT_UDP				= 'U',
	OPT_UDPLITE			= 258,
	OPT_DCCP			= 'D',
	OPT_PROTOCOL		= 'P',
	OPT_MTU				= 259,
	OPT_BACK			= 260,
	OPT_VERSION			= 'V',
	OPT_HELP			= 261
}	tLongOption;

static const tFtLongOption g_longOptions[] = {
	{"debug", FT_GETOPT_NO_ARGUMENT, OPT_DEBUG},
	{"dont-fragment", FT_GETOPT_NO_ARGUMENT, OPT_DONT_FRAGMENT},
	{"first", FT_GETOPT_REQUIRED_ARGUMENT, OPT_FIRST_TTL},
	{"gateway", FT_GETOPT_REQUIRED_ARGUMENT, OPT_GATEWAY},
	{"icmp", FT_GETOPT_NO_ARGUMENT, OPT_ICMP},
	{"tcp", FT_GETOPT_NO_ARGUMENT, OPT_TCP},
	{"interface", FT_GETOPT_REQUIRED_ARGUMENT, OPT_INTERFACE},
	{"max-hops", FT_GETOPT_REQUIRED_ARGUMENT, OPT_MAX_HOPS},
	{"sim-queries", FT_GETOPT_REQUIRED_ARGUMENT, OPT_SIM_QUERIES},
	{"numeric", FT_GETOPT_NO_ARGUMENT, OPT_NUMERIC},
	{"port", FT_GETOPT_REQUIRED_ARGUMENT, OPT_PORT},
	{"tos", FT_GETOPT_REQUIRED_ARGUMENT, OPT_TOS},
	{"flowlabel", FT_GETOPT_REQUIRED_ARGUMENT, OPT_FLOWLABEL},
	{"wait", FT_GETOPT_REQUIRED_ARGUMENT, OPT_WAIT},
	{"queries", FT_GETOPT_REQUIRED_ARGUMENT, OPT_QUERIES},
	{"source", FT_GETOPT_REQUIRED_ARGUMENT, OPT_SOURCE},
	{"sendwait", FT_GETOPT_REQUIRED_ARGUMENT, OPT_SENDWAIT},
	{"extensions", FT_GETOPT_NO_ARGUMENT, OPT_EXTENSIONS},
	{"as-path-lookups", FT_GETOPT_NO_ARGUMENT, OPT_AS_LOOKUP},
	{"module", FT_GETOPT_REQUIRED_ARGUMENT, OPT_MODULE},
	{"options", FT_GETOPT_REQUIRED_ARGUMENT, OPT_OPTIONS},
	{"sport", FT_GETOPT_REQUIRED_ARGUMENT, OPT_SPORT},
	{"fwmark", FT_GETOPT_REQUIRED_ARGUMENT, OPT_FWMARK},
	{"udp", FT_GETOPT_NO_ARGUMENT, OPT_UDP},
	{"mtu", FT_GETOPT_NO_ARGUMENT, OPT_MTU},
	{"back", FT_GETOPT_NO_ARGUMENT, OPT_BACK},
	{"version", FT_GETOPT_NO_ARGUMENT, OPT_VERSION},
	{"help", FT_GETOPT_NO_ARGUMENT, OPT_HELP},
	{NULL, 0, 0}
};

int	parseArgs(int argc, char **argv, tParseResult *result)
{
	tFtGetopt	state;
	int			ret;
	const char	*shortOpts = "46dFf:g:ITi:m:N:np:t:l:w:q:rs:z:eAM:O:UDVP:";

	ft_bzero(result, sizeof(*result));
	result->options.firstTtl = 1;
	result->options.maxTtl = TR_DEFAULT_MAX_HOPS;
	result->options.queries = TR_DEFAULT_QUERIES;
	result->options.simQueries = TR_DEFAULT_SIM_QUERIES;
	result->options.method = PROBE_UDP;
	result->options.port = 53;
	result->options.waitSpec.max = 5.0;

	ft_getoptInit(&state, argc, argv);
	while (1)
	{
		ret = ft_getoptLong(&state, shortOpts, g_longOptions);
		if (ret == FT_GETOPT_END)
			break ;
		if (ret == FT_GETOPT_ERROR)
			exit(EXIT_FAILURE);

		switch (state.opt)
		{
			case OPT_V4: result->options.v4 = TRUE; break;
			case OPT_V6: result->options.v6 = TRUE; break;
			case OPT_DEBUG: result->options.debug = TRUE; break;
			case OPT_DONT_FRAGMENT: result->options.dontFragment = TRUE; break;
			case OPT_FIRST_TTL:
				result->options.firstTtl = ft_atoi(state.optArg);
				if (result->options.firstTtl < 1)
					exit(EXIT_FAILURE);
				break;
			case OPT_MAX_HOPS:
				result->options.maxTtl = ft_atoi(state.optArg);
				if (result->options.maxTtl < 1)
					exit(EXIT_FAILURE);
				break;
			case OPT_QUERIES:
				result->options.queries = ft_atoi(state.optArg);
				if (result->options.queries < 1)
					exit(EXIT_FAILURE);
				break;
			case OPT_SIM_QUERIES:
				result->options.simQueries = ft_atoi(state.optArg);
				if (result->options.simQueries < 1)
					exit(EXIT_FAILURE);
				break;
			case OPT_NUMERIC: result->options.numeric = TRUE; break;
			case OPT_PORT:
				result->options.port = ft_atoi(state.optArg);
				if (result->options.port <= 0 || result->options.port > 65535)
					exit(EXIT_FAILURE);
				break;
			case OPT_TOS:
				result->options.tos = ft_atoi(state.optArg);
				if (result->options.tos < 0 || result->options.tos > 255)
					exit(EXIT_FAILURE);
				break;
			case OPT_FLOWLABEL:
				result->options.flowLabel = ft_atoi(state.optArg);
				if (result->options.flowLabel < 0)
					exit(EXIT_FAILURE);
				break;
			case OPT_WAIT:
				result->options.waitSpec.max = ft_atod(state.optArg);
				if (result->options.waitSpec.max <= 0.0)
					exit(EXIT_FAILURE);
				break;
			case OPT_BYPASS: result->options.bypassRouting = TRUE; break;
			case OPT_SOURCE: result->options.sourceAddr = state.optArg; break;
			case OPT_SENDWAIT:
				result->options.sendWait = ft_atod(state.optArg);
				if (result->options.sendWait < 0.0)
					exit(EXIT_FAILURE);
				break;
			case OPT_EXTENSIONS: result->options.extensions = TRUE; break;
			case OPT_AS_LOOKUP: result->options.asLookup = TRUE; break;
			case OPT_MODULE: result->options.moduleName = state.optArg; break;
			case OPT_OPTIONS: result->options.moduleOpts = state.optArg; break;
			case OPT_SPORT:
				result->options.sourcePort = ft_atoi(state.optArg);
				if (result->options.sourcePort <= 0
					|| result->options.sourcePort > 65535)
					exit(EXIT_FAILURE);
				result->options.simQueries = 1;
				break;
			case OPT_FWMARK:
				result->options.fwmark = ft_atoi(state.optArg);
				if (result->options.fwmark < 0)
					exit(EXIT_FAILURE);
				break;
			case OPT_UDP:
				result->options.method = PROBE_UDP;
				result->options.port = 53;
				break;
			case OPT_ICMP:
				result->options.method = PROBE_ICMP;
				break;
			case OPT_TCP:
				result->options.method = PROBE_TCP;
				result->options.port = 80;
				break;
			case OPT_UDPLITE:
				result->options.method = PROBE_UDPLITE;
				break;
			case OPT_DCCP:
				result->options.method = PROBE_DCCP;
				result->options.port = 33434;
				break;
			case OPT_PROTOCOL:
				result->options.method = PROBE_RAW;
				result->options.protocol = ft_atoi(state.optArg);
				if (result->options.protocol < 0)
					exit(EXIT_FAILURE);
				break;
			case OPT_INTERFACE: result->options.interface = state.optArg; break;
			case OPT_GATEWAY: result->options.gateways = state.optArg; break;
			case OPT_MTU:
				result->options.discoverMtu = TRUE;
				result->options.dontFragment = TRUE;
				result->options.simQueries = 1;
				break;
			case OPT_BACK: result->options.backward = TRUE; break;
			case OPT_VERSION: return (PARSE_VERSION);
			case OPT_HELP: return (PARSE_HELP);
		}
	}
	while (state.index < argc)
	{
		if (result->posCount < 2)
			result->positionals[result->posCount++] = argv[state.index++];
		else
		{
			ft_dprintf(STDERR_FILENO,
				"Extra arg '%s' (position %d, argc %d)\n",
				argv[state.index], state.index, argc);
			exit(EXIT_FAILURE);
		}
	}

	if (result->posCount < 1)
		return (PARSE_HELP);
	return (PARSE_OK);
}
