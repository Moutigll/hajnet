#include <stdlib.h>

#include "../../hajlib/include/hajlib.h" /* IWYU pragma: keep */

#include "../includes/parser.h"

static void handlePositional(tFtGetopt *state, tParseResult *result, char **argv)
{
	if (result->posCount < 2)
		result->positionals[result->posCount++] = argv[state->index++];
	else
	{
		ft_dprintf(STDERR_FILENO,
			"Extra arg `%s' (position 3, argc %d)\n",
			argv[state->index], state->index);
		exit(EXIT_BAD_ARGS);
	}
}

static void handleUnknownOrError(tFtGetopt *state, tParseResult *result)
{
	if (state->status == FT_GETOPT_MISSING_ARG)
	{
		const char *orig = NULL;

		if (state->index < state->argc)
			orig = state->argv[state->index];

		if (orig && orig[0] == '-' && orig[1] == '-') /* Long option */
		{
			const char *givenName = orig + 2;
			size_t givenLen = ft_strlen(givenName);

			if (state->badOpt && ft_strcmp(state->badOpt, givenName) == 0)
				exitMissingArgument(orig, getOptDescription(state->badOpt[0]), state->index);
			else if (state->badOpt && givenLen > 0 
				&& ft_strncmp(state->badOpt, givenName, givenLen) == 0)
				exitBadOption('?', orig, state->index, NULL);
			else
				exitBadOption('?', orig, state->index, NULL);
		}
		else
		{
			if (state->badOpt != NULL)
				exitMissingArgument(state->badOpt, getOptDescription(state->opt), state->index);
			else
				exitMissingArgument((char[]){ (char)state->opt, '\0' }, 
					getOptDescription(state->opt), state->index);
		}
	}

	if (state->badOpt != NULL && state->badOpt[0] == '-')
		result->badOptArg = (char *)state->badOpt;
	else if (state->badOpt != NULL)
		result->badOpt = state->badOpt[0];
	else
		result->badOpt = '?';
		
	exitBadOption(result->badOpt, result->badOptArg, state->index, NULL);
}

static void handleUdpOption(tFtGetopt *state, tParseResult *result)
{
	result->options.method = PROBE_UDP;
	result->options.port = 53;
	
	/* Check for UDPLite "-UL" */
	if (state->index < state->argc)
	{
		const char *curArg = state->argv[state->index];
		if (curArg[state->subIndex] == 'L')
		{
			result->options.method = PROBE_UDPLITE;
			if (curArg[state->subIndex + 1] != '\0')
				exitBadOption('L', "L", state->argc - state->index, NULL);
			state->subIndex++;
			if ((size_t)state->subIndex >= ft_strlen(curArg))
			{
				state->index++;
				state->subIndex = 0;
			}
		}
	}
}

int parseArgs(int argc, char **argv, tParseResult *result)
{
	tFtGetopt state;
	int ret;
	const char *shortOpts = "46dFf:g:ITi:m:N:np:t:l:w:q:rs:z:eAM:O:UDVP:";

	ft_bzero(result, sizeof(*result));
	
	/* Set defaults */
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
		int opt_index = state.index;
		ret = ft_getoptLong(&state, shortOpts, g_longOptions);
		
		if (ret == FT_GETOPT_END)
			break;

		/* Validate long option format (requires '=' for arguments) */
		checkLongOptionFormat(&state, g_longOptions, opt_index);

		if (ret == FT_GETOPT_POSITIONAL)
		{
			handlePositional(&state, result, argv);
			continue;
		}
		
		if (ret == FT_GETOPT_UNKNOWN || ret == FT_GETOPT_ERROR)
		{
			handleUnknownOrError(&state, result);
		}

		/* Handle each option */
		switch (state.opt)
		{
			case OPT_V4:			result->options.v4				= TRUE; break;
			case OPT_V6:			result->options.v6				= TRUE; break;
			case OPT_DEBUG:			result->options.debug			= TRUE; break;
			case OPT_DONT_FRAGMENT:	result->options.dontFragment	= TRUE; break;
			case OPT_FIRST_TTL:
				if (!parseUnsigned(state.optArg, &result->options.firstTtl))
					exitInvalidNumericOpt(&state);
				break;
			case OPT_MAX_HOPS:
				if (!parseUnsigned(state.optArg, &result->options.maxTtl))
					exitInvalidNumericOpt(&state);
				break;
			case OPT_QUERIES:		result->options.queries			= ft_atoi(state.optArg);	break;
			case OPT_SIM_QUERIES:	result->options.simQueries		= ft_atoi(state.optArg);	break;
			case OPT_NUMERIC:		result->options.numeric			= TRUE;							break;
			case OPT_PORT:
				if (!parsePort(state.optArg, &result->options.port))
					exitInvalidNumericOpt(&state);
				break;
			case OPT_TOS:			result->options.tos				= ft_atoi(state.optArg);	break;
			case OPT_FLOWLABEL:		result->options.flowLabel		= ft_atoi(state.optArg);	break;
			case OPT_WAIT:			result->options.waitSpec.max	= ft_atod(state.optArg);	break;
			case OPT_BYPASS:		result->options.bypassRouting	= TRUE;							break;
			case OPT_SOURCE:
				if (getAddr(state.optArg, &result->options.sourceAddr) != 0)
					exitBadOption('s', state.optArg, state.index - 1, NULL);
				break;
			case OPT_SENDWAIT:		result->options.sendWait		= ft_atod(state.optArg);	break;
			case OPT_EXTENSIONS:	result->options.extensions		= TRUE; 						break;
			case OPT_AS_LOOKUP:		result->options.asLookup		= TRUE; 						break;
			case OPT_MODULE:		result->options.moduleName		= state.optArg;					break;
			case OPT_OPTIONS:		result->options.moduleOpts		= state.optArg;					break;
			case OPT_SPORT:
				if (!parsePort(state.optArg, &result->options.sourcePort))
					exitInvalidNumericOpt(&state);
				result->options.simQueries = 1;
				break;
			case OPT_FWMARK:		result->options.fwmark			= ft_atoi(state.optArg);	break;
			case OPT_UDP:			handleUdpOption(&state, result);							break;
			case OPT_ICMP:			result->options.method			= PROBE_ICMP;					break;
			case OPT_TCP:
				result->options.method = PROBE_TCP;
				result->options.port = 80;
				break;
			case OPT_UDPLITE:		result->options.method			= PROBE_UDPLITE;				break;
			case OPT_DCCP:
				result->options.method = PROBE_DCCP;
				result->options.port = 33434;
				break;
			case OPT_PROTOCOL:
				result->options.method = PROBE_RAW;
				result->options.protocol = ft_atoi(state.optArg);
				break;
			case OPT_INTERFACE:		result->options.interface		= state.optArg;						break;
			case OPT_GATEWAY:
			{
				int gatewayIndex = 0;
				while (gatewayIndex <= 128 && result->options.gateways[gatewayIndex] != NULL)
					gatewayIndex++;
				result->options.gateways[gatewayIndex] = state.optArg; /* Just set the pointer of ther argv argument in the table */
				break;
			}
			case OPT_MTU:
				isExactLongOption(&state, "--mtu", FALSE);
				result->options.discoverMtu = TRUE;
				result->options.dontFragment = TRUE;
				result->options.simQueries = 1;
				break;
			case OPT_BACK:			result->options.backward = TRUE;								break;
			case OPT_VERSION: 
				return (PARSE_VERSION);
			case OPT_HELP: 
				return (PARSE_HELP);
		}
	}
	
	/* Handle any remaining positional arguments */
	while (state.index < argc)
	{
		if (result->posCount < 2)
			result->positionals[result->posCount++] = argv[state.index++];
		else
		{
			ft_dprintf(STDERR_FILENO,
				"Extra arg `%s' (position 3, argc %d)\n",
				argv[state.index], state.index);
			exit(EXIT_BAD_ARGS);
		}
	}

	/* Validate required host argument */
	if (result->posCount < 1)
	{
		ft_dprintf(STDERR_FILENO, "Specify \"host\" missing argument.\n");
		exit(EXIT_BAD_ARGS);
	}
	
	return (PARSE_OK);
}
