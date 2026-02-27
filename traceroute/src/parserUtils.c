#include <netdb.h>

#include "../../common/includes/ip.h"

#include "../../hajlib/include/hmath.h"
#include "../../hajlib/include/hmemory.h"
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
	{"protocol", FT_GETOPT_REQUIRED_ARGUMENT, OPT_PROTOCOL},
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
		case 'N': return "squeries";
		case 'q': return "nqueries";
		case 'p': return "port";
		case 't': return "tos";
		case 'l': return "flow_label";
		case 'w': return "MAX,HERE,NEAR";
		case 'z': return "sendwait";
		case 's': return "src_addr";
		case 'M': return "name";
		case 'O': return "module_opts";
		case 156: return "num";
		case 157: return "fwmark";
		case 'P': return "protocol";
		case 'g': return "gate,...";
		case 'i': return "interface";
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


tBool parsePort(const char *arg, unsigned int *port)
{
	char			*endptr;
	unsigned long	val;
	struct servent	*service;

	val = ft_strtoul(arg, &endptr, 0); /* Try to parse as number first */
	
	/* If we got a valid number and it's in the valid port range, use it */
	if (endptr != arg) {
# if defined (HAJ)
		if (val > 65535 || val < 1)
			return (FALSE);
# endif
		*port = (unsigned int)val;
		return (TRUE);
	}
	
	/* Try to resolve as service name */
	service = getservbyname(arg, NULL);
	if (service) {
		*port = ipNtohs(service->s_port);
		return (TRUE);
	}
	
	/* Neither a valid number nor a known service name */
	return (FALSE);
}

tBool parseUnsigned(const char *arg, unsigned int *value)
{
	char			*endptr;
	unsigned long	val;

	val = ft_strtoul(arg, &endptr, 0);
	
	if (endptr == arg || *endptr != '\0')
		return (FALSE); /* Not a valid number */

	*value = (unsigned int)val;
	return (TRUE);
}

tBool parseInt(const char *arg, int *value)
{
	char	*endptr;
	long	val;

	val = ft_strtol(arg, &endptr, 0);
	
	if (endptr == arg || *endptr != '\0')
		return (FALSE); /* Not a valid number */

	*value = (int)val;
	return (TRUE);
}

tBool parseDouble(const char *arg, double *value)
{
	char	*endptr;
	double	val;

	val = ft_strtod(arg, &endptr);
	
	if (endptr == arg || *endptr != '\0')
		return (FALSE); /* Not a valid number */

	*value = val;
	return (TRUE);
}

int getAddr (const char *name, t_sockaddrAny *addr) 
{
	struct addrinfo hints;
	struct addrinfo *res;
	int ret;

	if (!name || name[0] == '\0')
		return (EAI_NONAME);

	ft_bzero(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE;

	ret = getaddrinfo(name, NULL, &hints, &res);
	if (ret != 0)
		return (ret);

	if (res->ai_addrlen > sizeof(*addr))
	{
		freeaddrinfo(res);
		return (EAI_MEMORY);
	}

	ft_memcpy(addr, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);
	return (0);
}

/* ----- Long Option Format Validation ----- */

tBool isExactLongOption(tFtGetopt *state, const char *expected, tBool hasArg)
{
	size_t	len;
	char	*arg;

	arg = state->argv[state->index - 1];
	len = ft_strlen(expected);
	
	if (ft_strncmp(arg, expected, len))
		exitBadOption('m', arg, state->index - 1, NULL);

	if (!hasArg && arg[len] == '\0')
		return (TRUE);
		
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
		return (TRUE);

	return (exitBadOption('m', state->argv[state->index - 1], state->index - 1, NULL), FALSE);
}

void checkLongOptionFormat(tFtGetopt *state, const tFtLongOption *long_opts, int opt_index)
{
	const char	*token = state->argv[opt_index];
	size_t		token_len = ft_strlen(token);

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
