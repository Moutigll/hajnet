#include <netdb.h>
#include <string.h>

#include "../includes/ping.h"
#include "../includes/resolve.h"

/**
 * @brief Resolve a hostname or IP string to a sockaddr_storage structure
 * @param host - hostname or IP string to resolve
 * @param outAddr - output sockaddr_storage structure
 * @param outLen - output length of the sockaddr structure
 * @param outList - output addrinfo list (optional, can be NULL)
 * @param ipMode - IP version preference (IPv4, IPv6, or unspecified)
 * @return 0 on success, non-zero gai_strerror() code on failure
 */
int
resolveHost(const char				*host,
				struct sockaddr_storage	*outAddr,
				socklen_t				*outLen,
				struct addrinfo			**outList,
				tIpType					ipMode)
{
	struct addrinfo hints;
	struct addrinfo *res = NULL, *cur;
	int ret;

	if (!host || !outAddr || !outLen)
		return EAI_FAIL;

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_RAW;	// ICMP requires raw socket
	hints.ai_flags = AI_ADDRCONFIG;	// Only return addresses for configured interfaces
	hints.ai_flags |= AI_CANONNAME;	// Optional: get canonical name

	// Set preferred IP family
#if defined(HAJ)
	if (ipMode == IP_TYPE_V4)
		hints.ai_family = AF_INET;
	else if (ipMode == IP_TYPE_V6)
		hints.ai_family = AF_INET6;
	else
		hints.ai_family = AF_UNSPEC; // allow both
#else
	(void)ipMode;
	hints.ai_family = AF_INET; // default to IPv4
#endif

	// If host is an IP literal, getaddrinfo will skip DNS resolution
	hints.ai_flags |= AI_NUMERICHOST;

	// Attempt resolution
	ret = getaddrinfo(host, NULL, &hints, &res);
	if (ret != 0) {
		// Retry without AI_NUMERICHOST in case it's a hostname
		hints.ai_flags &= ~AI_NUMERICHOST;
		ret = getaddrinfo(host, NULL, &hints, &res);
		if (ret != 0)
			return ret;
	}

	// Pick first usable address
	struct addrinfo *firstUsable = NULL;
	for (cur = res; cur; cur = cur->ai_next)
	{
		if (cur->ai_family == AF_INET || cur->ai_family == AF_INET6)
		{
			if (!firstUsable)
				firstUsable = cur; // keep first usable address
		}
	}

	if (!firstUsable)
	{
		freeaddrinfo(res);
		return EAI_NONAME; // No usable address found
	}

	memcpy(outAddr, firstUsable->ai_addr, firstUsable->ai_addrlen);
	*outLen = firstUsable->ai_addrlen;

	if (outList) // Return the list if requested
		*outList = res; // caller will freeaddrinfo
	else
		freeaddrinfo(res);

	return (0);
}

int
resolvePeerName(
		const struct sockaddr_storage	*addr,
					socklen_t			addrLen,
					const char			*canonName,
					char				*out,
					size_t				outSize)
{
	int	ret;

	if (!addr || !out || outSize == 0)
		return (-1);

	out[0] = '\0';

	/* Try reverse DNS (PTR) */
	ret = getnameinfo((const struct sockaddr *)addr,
					  addrLen,
					  out,
					  outSize,
					  NULL,
					  0,
					  NI_NAMEREQD);
	if (ret == 0)
		return (0);

	/* Fallback to canonical name */
	if (canonName && canonName[0])
	{
		strncpy(out, canonName, outSize - 1);
		out[outSize - 1] = '\0';
		return (0);
	}

	return (-1);
}