#ifndef HAJPING_RESOLVE_H
# define HAJPING_RESOLVE_H

#include <netdb.h>
#include <sys/socket.h>

/**
 * @brief Enumeration for IP address types
 * - IP_TYPE_UNSPEC: unspecified
 * - IP_TYPE_V4: IPv4
 * - IP_TYPE_V6: IPv6
 */
typedef enum eIpType
{
	IP_TYPE_UNSPEC = 0,
	IP_TYPE_V4 = 1,
	IP_TYPE_V6 = 2
} tIpType;

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
