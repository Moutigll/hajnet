#include <ctype.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "../includes/ft_ping.h" // IWYU pragma: keep
#include "../includes/utils.h"

size_t
convertNumberOption(
	const char	*optArg,
	size_t		maxVal,
	int			allowZero,
	const char	*progName)
{
	char			*endptr;
	unsigned long	n;

	n = strtoul(optArg, &endptr, 0);

	if (*endptr != '\0')  // invalid value (ex : "3 4")
		fprintf(stderr, "%s: invalid value (`%s' near `%s')\n", progName, optArg, endptr);
	else if (n == 0 && !allowZero)  // zero not allowed
		fprintf(stderr, "%s: option value too small: %s\n", progName, optArg);
	else if (maxVal != 0 && n > maxVal)  // value too big
		fprintf(stderr, "%s: option value too big: %s\n", progName, optArg);
	else // valid value we return it
		return (n);

	exit(EXIT_FAILURE);
}

static int
hexCharToInt(char c)
{
	if (c >= '0' && c <= '9')
		return (c - '0');
	if (c >= 'a' && c <= 'f')
		return (c - 'a' + 10);
	if (c >= 'A' && c <= 'F')
		return (c - 'A' + 10);
	return (-1);
}

static void
patternError(const char *progName, const char *text)
{
#if defined(HAJ)
	(void)progName;
	fprintf(stderr, PROG_NAME ": error in pattern near %s\n", text);
#else
	fprintf(stderr, "%s: error in pattern near %s\n", progName, text);
#endif
	exit(EXIT_FAILURE);
}

void
decodePattern(
	const char		*progName,
	const char		*text,
	int				maxLen,
	int				*patternLen,
	unsigned char	*patternData)
{
	int i = 0;

	while (*text && i < maxLen)
	{
		const char *start = text;

		/* skip spaces */
		while (*text && isspace((unsigned char)*text))
			text++;

		if (!*text)
			patternError(progName, start);

		int hi = hexCharToInt(*text++);
		if (hi == -1)
			patternError(progName, start);
		int lo = 0;
		if (*text && !isspace((unsigned char)*text))
		{
			lo = hexCharToInt(*text++);
			if (lo == -1)
				patternError(progName, text - 1);
		}

		patternData[i++] = (unsigned char)((hi << 4) | lo);
	}

	*patternLen = i;
}

tBool
isRoot(void)
{
	return (geteuid() == 0);
}

const char *protoToStr(int proto)
{
	if (proto == IPPROTO_ICMP)
		return "ICMP";
	else if (proto == IPPROTO_ICMPV6)
		return "ICMPv6";
	else if (proto == IPPROTO_UDP)
		return "UDP";
	else if (proto == IPPROTO_TCP)
		return "TCP";
	else
		return "UNKNOWN";
}

const char *sockTypeToStr(tPingSocketType type)
{
	if (type == PING_SOCKET_ECHO)
		return "ECHO";
	else if (type == PING_SOCKET_TIMESTAMP)
		return "TIMESTAMP";
	else if (type == PING_SOCKET_ADDRESS)
		return "ADDRESS";
	else
		return "UNKNOWN";
}
