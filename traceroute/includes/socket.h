#ifndef HAJROUTE_SOCKET_H
#define HAJROUTE_SOCKET_H

#include <sys/socket.h>

#include "traceroute.h"

typedef enum eSocketPrivilege
{
	SOCKET_PRIV_USER,
	SOCKET_PRIV_RAW
}	tSocketPrivilege;

typedef struct sTracerouteSocket
{
	int						fd;
	int						family;
	tProbeMethod			method;
	tSocketPrivilege		privilege;
	struct sockaddr_storage	targetAddr;
}	tTracerouteSocket;

void tracerouteSocketInit(tTracerouteSocket *ctx, int family, tProbeMethod method);
int tracerouteSocketCreate(tTracerouteSocket *ctx, const tTracerouteOptions *opts);
int tracerouteSocketApplyOptions(tTracerouteSocket *ctx, const tTracerouteOptions *opts);
void tracerouteSocketClose(tTracerouteSocket *ctx);

#endif /* HAJROUTE_SOCKET_H */
