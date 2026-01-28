#ifndef HP_PARSER_H
# define HP_PARSER_H

# include <stddef.h>

#include "../../common/includes/utils.h"

#define PATTERN_MAX_LEN 256
#define PING_PRECISION 1000
#define PING_MIN_USER_INTERVAL (200000.0/PING_PRECISION)


/**
 * @brief Enumeration for IP timestamp option types
 * - IP_TS_NONE: no timestamp option
 * - IP_TS_ONLY: timestamp only
 * - IP_TS_ADDR: timestamp with address
 */
typedef enum eIpTsType
{
	IP_TS_NONE = 0,
	IP_TS_ONLY,
	IP_TS_ADDR
} tIpTsType;


typedef struct sPingOptions
{
	/* Options ICMP type */
	tBool			address;	/* send ICMP_ADDRESS packets */
	tBool			echo;		/* send ICMP_ECHO packets */
	tBool			timestamp;	/* send ICMP_TIMESTAMP packets */
	char			*type;		/* send ICMP type as string */

	/* Options for all types */
	int			 	count;		/* number of packets to send */
	tBool		 	debug;		/* set the SO_DEBUG option on the socket */
	double		 	interval;	/* wait interval seconds between sending each packet */
	tBool		 	numeric;	/* do not resolve hostnames */
	tBool		 	ignRouting;	/* set the SO_DONTROUTE option on the socket */
	int			 	ttl;		/* time to live */
	int			 	tos;		/* type of service */
	tBool		 	verbose;	/* verbose output */
	int			 	timeout;	/* stop after timeout seconds */
	int			 	linger;		/* time to linger before close */

	/* Options for ICMP_ECHO only */
	tBool		 	flood;		/* flood ping */
	tIpTsType		ipTsType;	/* IP timestamp option type */
	unsigned int	preload;	/* number of packets to send before waiting for replies */
	char			pattBytes[PATTERN_MAX_LEN]; /* pattern bytes */
	int				patternLen; /* length of pattern */
	tBool			quiet;		/* quiet output */
	tBool			recordRoute;/* record route option */
	int				packetSize;	/* size of ICMP payload */
} tPingOptions;

/* Parser result */
typedef struct sParseResult
{
	tPingOptions options;
	char        *positionals[16];
	int          posCount;
	char         badOpt;
	char        *badOptArg;
} tParseResult;


#define PARSE_OK				0
#define PARSE_HELP				1
#define PARSE_USAGE				2
#define PARSE_VERSION			3


/**
 * @brief - Parse arguments using getopt_long
 * @param argc - argument count
 * @param argv - argument vector
 * @param result - pointer to store parse result
 * @return 0 on success, non-zero on failure
 */
int parseArgs(int argc, char **argv, tParseResult *result);

#endif
