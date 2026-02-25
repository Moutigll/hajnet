#ifndef HAJROUTE_H
#define HAJROUTE_H


# include "../../common/includes/utils.h"

# define EXIT_SUCCESS 0
# define EXIT_FAILURE 1
# define TR_DEFAULT_MAX_HOPS 30
# define TR_DEFAULT_QUERIES 3
# define TR_DEFAULT_SIM_QUERIES 16

typedef enum eProbeMethod
{
	PROBE_UDP = 0,
	PROBE_ICMP,
	PROBE_TCP,
	PROBE_UDPLITE,
	PROBE_DCCP,
	PROBE_RAW
}	tProbeMethod;

typedef struct sWaitSpec
{
	double	max;
	double	here;
	double	near;
}	tWaitSpec;

typedef struct sTracerouteOptions
{
	tBool			v4;				/* Force IPv4 */
	tBool			v6;				/* Force IPv6 */
	tBool			debug;			/* Set the SO_DEBUG socket option */
	tBool			dontFragment;	/* Set the IP_DONTFRAG socket option */
	int				firstTtl;		/* First TTL (time to live, max hops) used in probe packets */
	int				maxTtl;			/* Max TTL (time to live, max hops) used in probe packets */
	int				queries;		/* Number of probe packets per hop */
	int				simQueries;		/* Number of probe packets per hop when using the "simultaneous" method */
	tBool			numeric;		/* Don't resolve IP addresses to their domain names */
	int				port;			/* Destination port to use when probing with UDP, DCCP or TCP */
	int				tos;			/* Type of Service (TOS) field to set in probe packets */
	int				flowLabel;		/* Flow label to set in probe packets (IPv6 only) */
	tWaitSpec		waitSpec;		/* Wait time specification for probe responses */
	tBool			bypassRouting;	/* Bypass normal routing and send probes directly to the destination */
	char			*sourceAddr;	/* Source IP address to use in probe packets */
	double			sendWait;		/* Time to wait between sending probe packets (in seconds) */
	tBool			extensions;		/* Display ICMP extensions in probe responses */
	tBool			asLookup;		/* Perform AS number lookup for IP addresses in probe responses */
	char			*moduleName;	/* Name of the module to use for probing */
	char			*moduleOpts;	/* Options to pass to the probing module */

	int				sourcePort;		/* Source port to use when probing with UDP, DCCP or TCP */	int				fwmark;			/* Firewall mark to set on probe packets (Linux only) */
	tBool			discoverMtu;	/* Perform MTU discovery by sending probes with the "Don't Fragment" flag set and decreasing the packet size until a response is received */
	tBool			backward;		/* Perform a backward traceroute by starting with a high TTL and decreasing it until the destination is reached */
	tProbeMethod	method;			/* Method to use for probing (UDP, ICMP, TCP, UDPLite, DCCP or RAW) */
	char			*interface;		/* Network interface to use for sending probe packets */
	char			*gateways;		/* Comma-separated list of gateway IP addresses to use for probing (instead of the default route) */
	int				protocol;		/* IP protocol number to use in probe packets (only relevant for RAW method) */
}	tTracerouteOptions;

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

int	parseArgs(int argc, char **argv, tParseResult *result);

void	printFullHelp(char *progName);

void	printUsage(char *progName);

#endif
