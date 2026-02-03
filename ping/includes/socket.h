#ifndef HAJPING_SOCKET_H
# define HAJPING_SOCKET_H

# include "parser.h"

/**
 * @brief Enumeration describing the privilege level available
 * - SOCKET_PRIV_USER: unprivileged user
 * - SOCKET_PRIV_RAW: root or CAP_NET_RAW
 */
typedef enum eSocketPrivilege
{
	SOCKET_PRIV_USER = 0,
	SOCKET_PRIV_RAW
} tSocketPrivilege;

/**
 * @brief Enumeration describing the ICMP usage of the socket
 * - PING_SOCKET_ECHO: ICMP echo request
 * - PING_SOCKET_TIMESTAMP: ICMP timestamp request
 * - PING_SOCKET_ADDRESS: ICMP address mask request
 */
typedef enum ePingSocketType
{
	PING_SOCKET_ECHO = 0,
	PING_SOCKET_TIMESTAMP,
	PING_SOCKET_ADDRESS
} tPingSocketType;

/**
 * @brief Structure holding all socket-related information for ping
 * - fd: socket file descriptor
 * - family: address family (AF_INET / AF_INET6)
 * - protocol: socket protocol (IPPROTO_ICMP / IPPROTO_ICMPV6)
 * - privilege: detected privilege level
 * - type: ICMP packet type handled by the socket
 */
typedef struct sPingSocket
{
	int					fd;
	int					family;
	int					protocol;
	tSocketPrivilege	privilege;
	tPingSocketType		type;
} tPingSocket;

/**
 * @brief Detect whether the process has permission to create raw sockets
 * @return SOCKET_PRIV_RAW if allowed, SOCKET_PRIV_USER otherwise
 */
tSocketPrivilege	sockDetectPrivilege(void);

/**
 * @brief Initialize a ping socket context without creating the socket
 * @param ctx - socket context to initialize
 * @param family - address family to use
 * @param type - ICMP packet type
 * @param privilege - detected privilege level
 */
void				socketInit(	tPingSocket			*ctx,
								int					family,
								tPingSocketType		type,
								tSocketPrivilege	privilege);
							
/**
 * @brief Check whether an ICMP type requires raw socket privileges
 * @param type - ICMP socket type
 * @return non-zero if raw privileges are required
 */
int					icmpRequiresPrivilege(tPingSocketType type);

/**
 * @brief Validate that the selected options are allowed
 *        with the current privilege level
 * @param opts - parsed ping options
 * @param privilege - detected privilege level
 * @return 0 if valid, -1 if forbidden options are used
 */
int					sockValidatePrivileges(
						const tPingOptions	*opts,
						tSocketPrivilege	privilege);

/**
 * @brief Create the socket according to the initialized context
 * @param ctx - socket context
 * @return 0 on success, -1 on error
 */
int					pingSocketCreate(tPingSocket *ctx);

/**
 * @brief Close the socket and reset its file descriptor
 * @param ctx - socket context
 */
void				pingSocketClose(tPingSocket *ctx);

/**
 * @brief Apply common socket options
 * - SO_DEBUG
 * - SO_DONTROUTE
 * - SO_LINGER
 * @param ctx - socket context
 * @param opts - parsed ping options
 * @return 0 on success, -1 on error
 */
int					socketApplyCommonOptions(tPingSocket *ctx, const tPingOptions *opts);

/**
 * @brief Apply socket options specific to ping
 * - IP_TTL
 * - IP_TOS
 * - IP_OPTIONS (record route, timestamp)
 * @param ctx - socket context
 * @param opts - parsed ping options
 * @return 0 on success, -1 on error
 */
int					socketApplyOptions(tPingSocket *ctx, const tPingOptions *opts);

#endif
