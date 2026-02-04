#ifndef HAJPING_RESOLVE_H
# define HAJPING_RESOLVE_H

#include <stddef.h>
#include <sys/socket.h>

#include "ping.h"

/**
 * @brief Resolve a hostname or IP string to a sockaddr_storage structure
 * @param host - hostname or IP string to resolve
 * @param outAddr - output sockaddr_storage structure
 * @param outLen - output length of the sockaddr structure
 * @param outList - output addrinfo list (optional, can be NULL)
 * @param ipMode - IP version preference (IPv4, IPv6, or unspecified)
 * @return 0 on success, non-zero gai_strerror() code on failure
 */
int resolveHost(
	const char				*host,
	struct sockaddr_storage	*outAddr,
	socklen_t				*outLen,
	struct addrinfo			**outList,
	tIpType					ipMode);

/**
 * @brief Reverse resolve a sockaddr_storage to a hostname
 * @param addr - pointer to sockaddr_storage structure
 * @param addrLen - length of the sockaddr structure
 * @param canonName - canonical name
 * @param out - output buffer for hostname
 * @param outSize - size of the output buffer
 * @return 0 on success, -1 on failure
 */
int resolvePeerName(
		const struct sockaddr_storage	*addr,
					socklen_t			addrLen,
					const char			*canonName,
					char				*out,
					size_t				outSize);

#endif /* HAJPING_RESOLVE_H */