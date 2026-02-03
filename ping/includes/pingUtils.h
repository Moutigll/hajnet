#ifndef HAJ_PING_UTILS_H
# define HAJ_PING_UTILS_H

#include <stdint.h>
#include <sys/time.h>

#include "../includes/parser.h"

void timevalFromDouble(struct timeval *tv, double seconds);

void normalizeTimeval(struct timeval *tv);

uint32_t computeUserPayloadSize(const tPingOptions *opts);

#endif /* HAJ_PING_UTILS_H */