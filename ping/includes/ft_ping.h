#ifndef FT_PING_H
# define FT_PING_H

#include "parser.h"
#include "socket.h"
#include <signal.h>
#include <sys/socket.h>
# define EXIT_SUCCESS 0
# define EXIT_FAILURE 1

#define PING_DEFAULT_COUNT		0	/**< 0 = infinite */
#define PING_DEFAULT_INTERVAL	1.0	/**< seconds */
#define PING_MAX_PATTERN_LEN	256
#define PING_MAX_POSITIONALS	16
#define PING_MAX_PACKET_SIZE	1024
#define ICMP_DATA_OFFSET sizeof(struct icmphdr)

#if defined (HAJ)
	# define EXIT_MISSING_HOST 2
	# define EXIT_INVALID_OPTION 2
	# define PROG_NAME "hajping"
	#define HELP_SHORT_OPT "h"
#else
	# define EXIT_MISSING_HOST 64
	# define EXIT_INVALID_OPTION 64
	# define PROG_NAME "ping"
	#define HELP_SHORT_OPT "?"
#endif

extern volatile sig_atomic_t g_pingInterrupted; /**< Flag set when SIGINT is received */

/**
 * @brief Enumeration for IP address types
 * - IP_TYPE_UNSPEC: unspecified
 * - IP_TYPE_V4: IPv4
 * - IP_TYPE_V6: IPv6
 */
typedef enum eIpType
{
	IP_TYPE_V4 = 1,
#if defined(HAJ)
	IP_TYPE_UNSPEC = 0,
	IP_TYPE_V6 = 2
#endif
} tIpType;

/**
 * @brief Ping statistics
 * - sent: number of packets sent
 * - received: number of packets received
 * - lost: number of lost packets
 * - rttMin: minimum round-trip time (ms)
 * - rttMax: maximum round-trip time (ms)
 * - rttSum: sum of RTTs (for average)
 * - rttSumSq: sum of squares of RTTs (for stddev)
 */
typedef struct sPingStats
{
	unsigned int	sent;		/* number of packets sent */
	unsigned int	received;	/* number of packets received */
	unsigned int	lost;		/* number of lost packets */
	double			rttMin;		/* minimum round-trip time (ms) */
	double			rttMax;		/* maximum round-trip time (ms) */
	double			rttSum;		/* sum of RTTs (for average) */
	double			rttSumSq;	/* sum of squares of RTTs (for stddev) */
} tPingStats;

/**
 * @brief Ping context holding all state
 * - opts: parsed CLI options
 * - sock: socket context
 * - targetAddr: primary resolved IP address
 * - addrLen: length of targetAddr
 * - allAddrs: optional full addrinfo list
 * - stats: ping statistics
 * - seq: current ICMP sequence number
 * - startTime: timestamp of first ping sent
 */
typedef struct sPingContext
{
	tParseResult			opts;		/* parsed CLI options */
	tPingSocket				sock;		/* socket context */
	struct sockaddr_storage	targetAddr;	/* primary resolved IP */
	socklen_t				addrLen;	/* length of targetAddr */
	struct addrinfo			*allAddrs;	/* optional full addrinfo list */
	tPingStats				stats;		/* ping statistics */
	unsigned int			seq;		/* current ICMP sequence number */
	struct timeval			startTime;	/* timestamp of first ping sent */
} tPingContext;

/**
 * @brief Run the main ping loop according to options
 * @param ctx - initialized ping context
 */
void	runPingLoop(tPingContext *ctx);

#endif
