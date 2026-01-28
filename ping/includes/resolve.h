#ifndef HAJPING_RESOLVE_H
# define HAJPING_RESOLVE_H

#include <sys/types.h>
#include <sys/socket.h>

#include "ft_ping.h"

int resolveHost(
	const char				*host,
	struct sockaddr_storage	*outAddr,
	socklen_t				*outLen,
	struct addrinfo			**outList,
	tIpType					ipMode);

#endif /* HAJPING_RESOLVE_H */