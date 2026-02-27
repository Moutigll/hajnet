#ifndef HAJROUTE_PARSER_H
#define HAJROUTE_PARSER_H

# include "../../hajlib/include/hgetopt.h"
# include "../../common/includes/utils.h"

# include "traceroute.h"
#include <netinet/in.h>

extern const tFtLongOption g_longOptions[];

typedef struct sTracerouteOptions
{
	tBool			v4;				/* Force IPv4 */
	tBool			v6;				/* Force IPv6 */
	tBool			debug;			/* Set the SO_DEBUG socket option */
	tBool			dontFragment;	/* Set the IP_DONTFRAG socket option */
	unsigned int	firstTtl;		/* First TTL (time to live, max hops) used in probe packets */
	unsigned int	maxTtl;			/* Max TTL (time to live, max hops) used in probe packets */
	int				queries;		/* Number of probe packets per hop */
	int				simQueries;		/* Number of probe packets per hop when using the "simultaneous" method */
	tBool			numeric;		/* Don't resolve IP addresses to their domain names */
	unsigned int	port;			/* Destination port to use when probing with UDP, DCCP or TCP */
	int				tos;			/* Type of Service (TOS) field to set in probe packets */
	int				flowLabel;		/* Flow label to set in probe packets (IPv6 only) */
	tWaitSpec		waitSpec;		/* Wait time specification for probe responses */
	tBool			bypassRouting;	/* Bypass normal routing and send probes directly to the destination */
	t_sockaddrAny	sourceAddr; /* Storage for the parsed source address */
	double			sendWait;		/* Time to wait between sending probe packets (in seconds) */
	tBool			extensions;		/* Display ICMP extensions in probe responses */
	tBool			asLookup;		/* Perform AS number lookup for IP addresses in probe responses */
	char			*moduleName;	/* Name of the module to use for probing */
	char			*moduleOpts;	/* Options to pass to the probing module */

	unsigned int	sourcePort;		/* Source port to use when probing with UDP, DCCP or TCP */
	int				fwmark;			/* Firewall mark to set on probe packets (Linux only) */
	tBool			discoverMtu;	/* Perform MTU discovery by sending probes with the "Don't Fragment" flag set and decreasing the packet size until a response is received */
	tBool			backward;		/* Perform a backward traceroute by starting with a high TTL and decreasing it until the destination is reached */
	tProbeMethod	method;			/* Method to use for probing (UDP, ICMP, TCP, UDPLite, DCCP or RAW) */
	char			*interface;		/* Network interface to use for sending probe packets */
	char			*gateways[128];/* List of gateway IP addresses to use for source routing (comma-separated in the command line);
									The list can be in multiple arguments, but the total number of gateways must not exceed 127 in all cases
									so to be safe, we can limit to 128 total entries in the array (including the NULL terminator) */
	int				gatewayCount;	/* Number of gateways specified in the list */
	int				protocol;		/* IP protocol number to use in probe packets (only relevant for RAW method) */

	unsigned int	packetSize;		/* Packet size to use for probes (if specified as a positional argument) */
}	tTracerouteOptions;

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
	OPT_SPORT			= 156,
	OPT_FWMARK			= 157,
	OPT_UDP				= 'U',
	OPT_UDPLITE			= 158,
	OPT_DCCP			= 'D',
	OPT_PROTOCOL		= 'P',
	OPT_MTU				= 159,
	OPT_BACK			= 160,
	OPT_VERSION			= 'V',
	OPT_HELP			= 161
}	tLongOption;

typedef struct sParseResult
{
	tTracerouteOptions	options;
	char				*positionals[2]; /* positionals[0] = destination, positionals[1] = packet size (optional) */
	int					posCount;
	char				badOpt;
	char				*badOptArg;
}	tParseResult;

# define PARSE_OK		0
# define PARSE_HELP		1
# define PARSE_VERSION	2

/**
 * @brief Parse command line arguments and fill result structure
 * @param argc Argument count
 * @param argv Argument vector
 * @param result Structure to fill with parsed values
 * @return PARSE_OK, PARSE_HELP, or PARSE_VERSION
 */
int			parseArgs(int argc, char **argv, tParseResult *result);

/* ----- Parser utility functions ----- */

/**
 * @brief Get description of expected argument format for an option
 * @param opt Option character
 * @return String describing the expected argument format
 */
const char	*getOptDescription(char opt);

/**
 * @brief Print error for bad option and exit
 * @param badOpt The bad option character
 * @param badOptStr The bad option string (for long options)
 * @param badArgp Argument position where error occurred
 * @param badArg The argument value that caused the error (if any)
 */
void		exitBadOption(char badOpt, const char *badOptStr, int badArgp, char *badArg);

/**
 * @brief Print error for missing argument and exit
 * @param opt The option that requires an argument
 * @param desc Description of expected argument format
 * @param badArgp Argument position where error occurred
 */
void		exitMissingArgument(const char *opt, const char *desc, int badArgp);

/**
 * @brief Print error for invalid numeric option argument and exit
 * @param state Getopt state containing the option and argument
 */
void		exitInvalidNumericOpt(tFtGetopt *state);

/* ----- Parser validation functions ----- */

/** 
 * @brief Parse a port number from a string, which can be either a numeric port or a service name
 * @param arg The argument string to parse
 * @param port Pointer to store the parsed port number (in host byte order)
 * @return TRUE on success, FALSE on failure (invalid port number or service name)
 */
tBool parsePort(const char *arg, unsigned int *port);

/**
 * @brief Parse an unsigned integer from a string
 * @param arg The argument string to parse
 * @param value Pointer to store the parsed unsigned integer
 * @return TRUE on success, FALSE on failure (invalid integer)
 */
tBool parseUnsigned(const char *arg, unsigned int *value);

/**
 * @brief Parse a signed integer from a string
 * @param arg The argument string to parse
 * @param value Pointer to store the parsed integer
 * @return TRUE on success, FALSE on failure (invalid integer)
 */
tBool parseInt(const char *arg, int *value);

/**
 * @brief Parse a double from a string
 * @param arg The argument string to parse
 * @param value Pointer to store the parsed double
 * @return TRUE on success, FALSE on failure (invalid double)
 */
tBool parseDouble(const char *arg, double *value);

/**
 * @brief Resolve a hostname to an IP address
 * @param name The hostname to resolve
 * @param addr Pointer to store the resolved address (as a sockaddrAny)
 * @return 0 on success, non-zero error code on failure
 */
int getAddr(const char *name, t_sockaddrAny *addr);

/* ----- Long option parsing functions ----- */

/**
 * @brief Check if the current long option matches the expected name and argument format
 * This function is used to enforce that long options with required arguments use the `--option=value` format
 * and to provide specific error messages for mismatches. Because the traceroute implementation doesn't allow
 * long options with separate arguments (like `--option value`) or autocompletion (like `--opt` for `--option`),
 * this function ensures that the provided long option matches exactly
 * @param state The getopt state containing the current option being processed 
 * @param expected The expected long option name
 * @param hasArg Whether the option expects an argument
 * @return TRUE if the option matches exactly, FALSE otherwise
 */
tBool			isExactLongOption(tFtGetopt *state, const char *expected, tBool hasArg);

/**
 * Check if a long option is in the correct format (with '=' for required arguments)
 * @param state Getopt state containing the current option
 * @param long_opts Array of valid long options
 * @param opt_index Index of the current option in argv
 */
void		checkLongOptionFormat(tFtGetopt *state, const tFtLongOption *long_opts, int opt_index);

#endif /* HAJROUTE_PARSER_H */
