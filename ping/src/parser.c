#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../common/includes/getopt.h"
#include "../includes/parser.h"
#include "../includes/usage.h"
#include "../includes/utils.h"

typedef enum eLongOption {
	OPT_ICMP_ADDRESS	= 256,
	OPT_ICMP_ECHO		= 257,
	OPT_ICMP_TIMESTAMP	= 258,
	OPT_TYPE			= 't',

	OPT_COUNT			= 'c',
	OPT_DEBUG			= 'd',
	OPT_INTERVAL		= 'i',
	OPT_NUMERIC			= 'n',
	OPT_IGNROUTING		= 'r',
	OPT_TTL				= 259,
	OPT_TOS				= 'T',
	OPT_VERBOSE			= 'v',
	OPT_TIMEOUT			= 'w',
	OPT_LINGER			= 'W',
#if defined(HAJ)
	OPT_V4				= '4',
	OPT_V6				= '6',
#endif

	OPT_FLOOD			= 'f',
	OPT_IP_TIMESTAMP	= 260,
	OPT_PRELOAD			= 'l',
	OPT_PATTERN			= 'p',
	OPT_QUIET			= 'q',
	OPT_RECORD_ROUTE	= 'R',
	OPT_PACKET_SIZE		= 's',

#if defined(HAJ)
	OPT_HELP			= 'h',
#else
	OPT_HELP			= '?',
#endif
	OPT_USAGE			= 261,
	OPT_VERSION			= 'V'
} tLongOption;


static const tFtLongOption g_longOptions[] = {
	{"address", 		FT_GETOPT_NO_ARGUMENT,		 OPT_ICMP_ADDRESS},
	{"echo",			FT_GETOPT_NO_ARGUMENT,		 OPT_ICMP_ECHO},
	{"mask",			FT_GETOPT_NO_ARGUMENT,	 OPT_ICMP_ADDRESS},
	{"timestamp",		FT_GETOPT_NO_ARGUMENT,		 OPT_ICMP_TIMESTAMP},
	{"type",			FT_GETOPT_REQUIRED_ARGUMENT,	 OPT_TYPE},

	{"count",			FT_GETOPT_REQUIRED_ARGUMENT,	 OPT_COUNT},
	{"debug",			FT_GETOPT_NO_ARGUMENT,		 OPT_DEBUG},
	{"interval", 		FT_GETOPT_REQUIRED_ARGUMENT,	 OPT_INTERVAL},
	{"numeric",			FT_GETOPT_NO_ARGUMENT,		 OPT_NUMERIC},
	{"ignrouting",		FT_GETOPT_NO_ARGUMENT,		 OPT_IGNROUTING},
	{"ttl",				FT_GETOPT_REQUIRED_ARGUMENT,	 OPT_TTL},
	{"tos",				FT_GETOPT_REQUIRED_ARGUMENT,	 OPT_TOS},
	{"verbose",			FT_GETOPT_NO_ARGUMENT,		 OPT_VERBOSE},
	{"timeout",			FT_GETOPT_REQUIRED_ARGUMENT,	 OPT_TIMEOUT},
	{"linger",			FT_GETOPT_REQUIRED_ARGUMENT,	 OPT_LINGER},
#if defined(HAJ)
	{"ipv4",			FT_GETOPT_NO_ARGUMENT,		 OPT_V4},
	{"ipv6",			FT_GETOPT_NO_ARGUMENT,		 OPT_V6},
#endif

	{"flood",			FT_GETOPT_NO_ARGUMENT,		 OPT_FLOOD},
	{"ip-timestamp",	FT_GETOPT_REQUIRED_ARGUMENT,		 OPT_IP_TIMESTAMP},
	{"preload",			FT_GETOPT_REQUIRED_ARGUMENT,	 OPT_PRELOAD},
	{"pattern",			FT_GETOPT_REQUIRED_ARGUMENT,	 OPT_PATTERN},
	{"quiet",			FT_GETOPT_NO_ARGUMENT,		 OPT_QUIET},
#if defined (HAJ)
	{"record-route",	FT_GETOPT_NO_ARGUMENT,		 OPT_RECORD_ROUTE},
	{"packet-size",			FT_GETOPT_REQUIRED_ARGUMENT,	 OPT_PACKET_SIZE},
#else
	{"route",	FT_GETOPT_NO_ARGUMENT,		 OPT_RECORD_ROUTE},
	{"size",		FT_GETOPT_REQUIRED_ARGUMENT,	 OPT_PACKET_SIZE},
#endif
	{"help",			FT_GETOPT_NO_ARGUMENT,		 OPT_HELP},
	{"usage",			FT_GETOPT_NO_ARGUMENT,		 OPT_USAGE},
	{"version",			FT_GETOPT_NO_ARGUMENT,		 OPT_VERSION},
	{NULL, 0, 0}
};

static void
handleIntervalOption(const char *optArg, const char *progName, double *outInterval)
{
	char	*endptr;
	double	val;

	val = strtod(optArg, &endptr);

	/* Check that the string is a valid number and there are no invalid characters */
	if (*endptr != '\0')
	{
		fprintf(stderr, "%s: invalid value (`%s' near `%s')\n",
			progName, optArg, endptr);
#if defined(HAJ)
		fprintf(stderr, "Try '" PROG_NAME " --help' or '" PROG_NAME " --usage' for more information.\n");
#else
		fprintf(stderr, "Try '%s --help' or '%s --usage' for more information.\n", progName, progName);
#endif
		exit(EXIT_INVALID_OPTION);
	}

	/* Check the minimum value for non-root users */
	if ((!isRoot() && val < (double)PING_MIN_USER_INTERVAL / PING_PRECISION) || val <= 0.0 || strcmp("nan", optArg) == 0)
	{
		fprintf(stderr, "%s: option value too small: %s\n",
			progName, optArg);
		exit(EXIT_FAILURE);
	}

	*outInterval = val;
}

static void
parseIpTsValue(const char *optArg, const char *progName, tIpTsType *outType)
{
	if (strcmp(optArg, "tsonly") == 0)
		*outType = IP_TS_ONLY;
	else if (strcmp(optArg, "tsaddr") == 0)
		*outType = IP_TS_ADDR;
#if defined(HAJ)
	else if (strcmp(optArg, "tsprespec") == 0)
		*outType = IP_TS_PRESPEC;
#endif
	else
	{
		fprintf(stderr, "%s: unsupported timestamp type: %s\n", progName, optArg);
		exit(EXIT_FAILURE);
	}
}

static void
handlePreloadOption(const char *optArg, const char *progName, unsigned int *outPreload)
{
	char *endptr;
	unsigned long val;

	val = strtoul(optArg, &endptr, 0);

	if (*endptr != '\0' || val > INT_MAX)
	{
		fprintf(stderr, "%s: invalid preload value (%s)\n", progName, optArg);
		exit(EXIT_FAILURE);
	}

	*outPreload = (unsigned int)val;
}

int parseArgs(int argc, char **argv, tParseResult *result)
{
	tFtGetopt	state;
	int			ret;

	memset(result, 0, sizeof(*result));
	result->options.packetSize = 56;

#if defined(HAJ)
	const char *shortOpts = "t:c:di:nrT:vw:W:fl:p:qRs:hV46";
#else
	const char *shortOpts = "t:c:di:nrT:vw:W:fl:p:qRs:?V";
#endif

	ftGetoptInit(&state, argc, argv);

	while (1)
	{
		ret = ftGetoptLong(&state, shortOpts, g_longOptions);
		if (ret == FT_GETOPT_END)
			break ;
		if (ret == FT_GETOPT_ERROR)
		{
			if (state.status == FT_GETOPT_AMBIGUOUS) /* Ambiguity (long option prefix matches >1) */
				exitAmbiguousOption(argv[0], state.badOpt, state.ambiguousA, state.ambiguousB);
			if (state.status == FT_GETOPT_MISSING_ARG) /* Missing argument for an option: opt holds the option char (e.g. 'W') */
				exitMissingArg(argv[0], state.opt, state.badOpt);

			/* Unknown option: distinguish long and short forms */
			if (state.badOpt != NULL && state.badOpt[0] == '-')
				result->badOptArg = (char *)state.badOpt; /* long option form: keep the whole string */
			else if (state.badOpt != NULL)
				result->badOpt = state.badOpt[0]; /* short option: pointer to the bad char inside argv, take single char */
			else /* fallback */
				result->badOpt = '?';
			exitBadOption(argv[0], result->badOpt, result->badOptArg);
		}

		switch (state.opt)
		{
			case OPT_ICMP_ADDRESS: result->options.address = TRUE; break;
			case OPT_ICMP_ECHO: result->options.echo = TRUE; break;
			case OPT_ICMP_TIMESTAMP: result->options.timestamp = TRUE; break;
			case OPT_TYPE: {
				if (strcmp(state.optArg, "timestamp") == 0)
					result->options.timestamp = TRUE;
				else if (strcmp(state.optArg, "echo") == 0)
					result->options.timestamp = FALSE;
				else
				{
					fprintf(stderr, "%s: unsupported packet type: %s\n", argv[0], state.optArg);
					exit(EXIT_FAILURE);
				}
			} break;

			case OPT_COUNT: result->options.count =
				convertNumberOption(state.optArg, 0, 1, argv[0]); break;
			case OPT_DEBUG: result->options.debug = TRUE; break;
			case OPT_INTERVAL:
				handleIntervalOption(state.optArg, argv[0], &result->options.interval); break;
			case OPT_NUMERIC: result->options.numeric = TRUE; break;
			case OPT_IGNROUTING: result->options.ignRouting = TRUE; break;
			case OPT_TTL: result->options.ttl =
				convertNumberOption(state.optArg, 255, 0, argv[0]); break;
			case OPT_TOS: result->options.tos =
				convertNumberOption(state.optArg, 255, 1, argv[0]); break;
#if defined (HAJ)
			case OPT_VERBOSE: result->options.verbose++; break;
#else
			case OPT_VERBOSE: result->options.verbose = 1; break;
#endif
			case OPT_TIMEOUT: result->options.timeout =
				convertNumberOption(state.optArg, INT_MAX, 0, argv[0]); break;
			case OPT_LINGER: result->options.linger =
				convertNumberOption(state.optArg, INT_MAX, 0, argv[0]); break;
#if defined(HAJ)
			case OPT_V4: result->options.v4 = TRUE; break;
			case OPT_V6: result->options.v6 = TRUE; break;
#endif

			case OPT_FLOOD: result->options.flood = TRUE; break;
			case OPT_IP_TIMESTAMP:
				parseIpTsValue(state.optArg, argv[0], &result->options.ipTsType); break;
			case OPT_PRELOAD:
				handlePreloadOption(state.optArg, argv[0], &result->options.preload); break;
			case OPT_PATTERN:
				decodePattern(
					argv[0],
					state.optArg,
					PATTERN_MAX_LEN,
					&result->options.patternLen,
					(unsigned char *)result->options.pattBytes);
				break;
			case OPT_QUIET: result->options.quiet = TRUE; break;
			case OPT_RECORD_ROUTE: result->options.recordRoute = TRUE; break;
			case OPT_PACKET_SIZE: result->options.packetSize =
				convertNumberOption(state.optArg, 65399, 1, argv[0]); break;

			case OPT_HELP:
				return (PARSE_HELP);
			case OPT_USAGE:
				return (PARSE_USAGE);
			case OPT_VERSION:
				return (PARSE_VERSION);
		}
	}

	while (state.index < argc)
		result->positionals[result->posCount++] = argv[state.index++];

	return (PARSE_OK);
}
