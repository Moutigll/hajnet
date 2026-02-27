#ifndef HAJROUTE_H
#define HAJROUTE_H

#include <netinet/in.h>

#if defined(HAJ)
# define PROG_NAME "hajroute"
#else
# define PROG_NAME "traceroute"
#endif

#define __T(X)       #X
#define _T(X)        __T(X)

# define EXIT_SUCCESS 0
# define EXIT_FAILURE 1
# define EXIT_BAD_ARGS 2
# define TR_DEFAULT_MAX_HOPS 30
# define TR_DEFAULT_QUERIES 3
# define TR_DEFAULT_SIM_QUERIES 16
# define MAX_GATEWAYS_IPV4 8
# define MAX_GATEWAYS_IPV6 127
# define MAX_PROBES 10
# define MAX_PACKET_SIZE 65500

typedef union u_sockaddrAny
{
	struct sockaddr		sa;
	struct sockaddr_in	in;
	struct sockaddr_in6	in6;
}	t_sockaddrAny;

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

void	printFullHelp(char *progName);

void	printUsage(char *progName);

#endif
