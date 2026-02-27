#ifndef HAJROUTE_NETWORK_H
#define HAJROUTE_NETWORK_H

#include <sys/socket.h>

#include "parser.h"

typedef enum eSocketPrivilege
{
	SOCKET_PRIV_USER,
	SOCKET_PRIV_RAW
}	tSocketPrivilege;

/**
 * @brief Hold the context of the currently used socket
 * contains:
 * 	- fd: file descriptor of the socket
 * 	- family: address family (AF_INET or AF_INET6)
 * 	- method: probe method (UDP, ICMP, TCP, etc.)
 * 	- privilege: whether the socket is raw (requires root) or not
 * 	- targetAddr: the destination address to which probes will be sent (used for binding and sending)
 */
typedef struct sTracerouteSocket
{
	int						fd;
	int						family;
	tProbeMethod			method;
	tSocketPrivilege		privilege;
	struct sockaddr_storage	targetAddr;
}	tTracerouteSocket;

/* ----- Socket functions ----- */

/**
 * @brief Initialize a traceroute socket context
 * @param ctx Pointer to the socket context to initialize
 * @param family Address family (AF_INET, AF_INET6)
 * @param method Probe method (PROBE_ICMP, PROBE_UDP, etc.)
 */
void tracerouteSocketInit(tTracerouteSocket *ctx, int family, tProbeMethod method);

/**
 * @brief Create a socket based on the traceroute options
 * @param ctx Pointer to the initialized socket context
 * @param opts Traceroute options to determine socket type and protocol
 * @return 0 on success, -1 on failure
 */
int tracerouteSocketCreate(tTracerouteSocket *ctx, const tTracerouteOptions *opts);

/**
 * @brief Apply options to an existing traceroute socket
 * @param ctx Pointer to the socket context
 * @param opts Traceroute options to apply
 * @return 0 on success, -1 on failure
 */
int tracerouteSocketApplyOptions(tTracerouteSocket *ctx, const tTracerouteOptions *opts);

/**
 * @brief Close the traceroute socket and clean up resources
 * @param ctx Pointer to the socket context to close
 */
void tracerouteSocketClose(tTracerouteSocket *ctx);


/* ----- Resolver functions ----- */

/**
 * Resolve destination host and validate gateways
 * @param parseResult Parsed arguments
 * @param dstAddr Destination address storage (output)
 * @param dstLen Destination address length (output)
 * @param argc Original argument count
 * @param argv Original argument vector
 * @return EXIT_SUCCESS on success, error code on failure
 */
int resolveDestination(tParseResult *parseResult,
					  struct sockaddr_storage *dstAddr,
					  socklen_t *dstLen,
					  int argc, char **argv);

#endif /* HAJROUTE_NETWORK_H */
