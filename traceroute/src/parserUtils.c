#include <stdlib.h>

#include "../../hajlib/include/hchar.h"
#include "../../hajlib/include/hprintf.h"
#include "../../hajlib/include/hstring.h"

#include "../includes/parser.h"

const tFtLongOption g_longOptions[] = {
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

const char *getOptDescription(char opt)
{
	switch (opt)
	{
		case 'f': return "first_ttl";
		case 'm': return "max_ttl";
		case 'N': return "sim_queries";
		case 'q': return "queries";
		case 'p': return "port";
		case 't': return "tos";
		case 'l': return "flowlabel";
		case 'w': return "wait";
		case 'z': return "sendwait";
		case 's': return "source";
		case 'M': return "module";
		case 'O': return "module_opts";
		case 156: return "sport";
		case 157: return "fwmark";
		case 'P': return "protocol";
		case 'g': return "gate,...";
		default: return "unknown";
	}
}

/* ----- Parser Safe Exit Functions ----- */

/**
 * @file parser_errors.c
 * @brief Error handling functions for command line parsing
 */

void exitBadOption(char badOpt, const char *badOptStr, int badArgp, char *badArg)
{
	if (badOptStr && *badOptStr)
		ft_dprintf(STDERR_FILENO, "Bad option `%s' ", badOptStr);
	else
		ft_dprintf(STDERR_FILENO, "Bad option `-%c' ", badOpt);

	if (badArg)
		ft_dprintf(STDERR_FILENO, "(with arg `%s') ", badArg);
	ft_dprintf(STDERR_FILENO, "(argc %d)\n", badArgp);
	exit(EXIT_BAD_ARGS);
}

void exitMissingArgument(const char *opt, const char *desc, int badArgp)
{
	if (opt[0] == '-')
		ft_dprintf(STDERR_FILENO, 
			"Option `%s' (argc %d) requires an argument: `%s=%s'\n", 
			opt, badArgp, opt, desc);
	else
		ft_dprintf(STDERR_FILENO, 
			"Option `-%c' (argc %d) requires an argument: `-%c %s'\n", 
			opt[0], badArgp, opt[0], desc);
	exit(EXIT_BAD_ARGS);
}

void exitInvalidNumericOpt(tFtGetopt *state)
{
	if (state->badOpt != NULL && state->badOpt[0] == '-')
		ft_dprintf(STDERR_FILENO,
			"Cannot handle `%s' option with arg `%s' (argc %d)\n", 
			state->badOpt, state->optArg, state->index - 1);
	else
		ft_dprintf(STDERR_FILENO,
			"Cannot handle `-%c' option with arg `%s' (argc %d)\n", 
			state->opt, state->optArg, state->index - 1);

	exit(EXIT_BAD_ARGS);
}

/* ----- Parser Validation Functions ----- */


tBool isStrictNumber(const char *str)
{
	int i;

	if (!str || !*str)
		return (FALSE);

	i = 0;
	if (str[i] == '+' || str[i] == '-')
		i++;

	if (!str[i])
		return (FALSE);

	while (str[i])
	{
		if (!ft_isdigit(str[i]))
			return (FALSE);
		i++;
	}
	return (TRUE);
}

/* ----- Long Option Format Validation ----- */

int isExactLongOption(tFtGetopt *state, const char *expected, tBool hasArg)
{
	size_t len;
	char *arg;

	arg = state->argv[state->index - 1];
	len = ft_strlen(expected);
	
	if (ft_strncmp(arg, expected, len))
		exitBadOption('m', arg, state->index - 1, NULL);

	if (!hasArg && arg[len] == '\0')
		return (1);
		
	if (!hasArg)
	{
		if (arg[len] == '=')
			exitBadOption('m', state->argv[state->index - 1], 
				state->index - 1, 
				state->argv[state->index - 1][len + 1] ? (char *)&arg[len + 1] : NULL);
		else
			exitBadOption('m', state->argv[state->index - 1], state->index - 1, NULL);
	}
	
	if (hasArg && arg[len] == '=')
		return (1);

	return (exitBadOption('m', state->argv[state->index - 1], state->index - 1, NULL), 0);
}

void checkLongOptionFormat(tFtGetopt *state, const tFtLongOption *long_opts, int opt_index)
{
	const char *token = state->argv[opt_index];
	size_t token_len = ft_strlen(token);

	/* Only care about long options starting with -- */
	if (token_len < 3 || token[0] != '-' || token[1] != '-')
		return;

	const char *name_part = token + 2;  /* Skip -- */
	size_t name_len = 0;
	
	/* Find end of option name (before = or end of string) */
	while (name_part[name_len] && name_part[name_len] != '=')
		name_len++;

	/* Look for matching long option */
	for (int i = 0; long_opts[i].name != NULL; i++)
	{
		size_t opt_name_len = ft_strlen(long_opts[i].name);
		if (name_len == opt_name_len &&
			ft_strncmp(name_part, long_opts[i].name, opt_name_len) == 0)
		{
			/* If option requires an argument, it must have '=' */
			if (long_opts[i].hasArg == FT_GETOPT_REQUIRED_ARGUMENT)
			{
				if (!name_part[name_len])
					exitMissingArgument(token, 
						getOptDescription(long_opts[i].val), opt_index);
				if (name_part[name_len] != '=')
					exitBadOption(long_opts[i].val, token, opt_index, NULL);
			}
			return;
		}
	}
}
