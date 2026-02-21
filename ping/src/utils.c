#include "../../hajlib/include/hajlib.h" /* IWYU pragma: keep */

#include "../../common/includes/ip.h"
#if defined(HAJ)
#include "../includes/ping.h"
#endif
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

	n = ft_strtoul(optArg, &endptr, 0);

	if (*endptr != '\0')  // invalid value (ex : "3 4")
		ft_dprintf(STDERR_FILENO, "%s: invalid value (`%s' near `%s')\n", progName, optArg, endptr);
	else if (n == 0 && !allowZero)  // zero not allowed
		ft_dprintf(STDERR_FILENO, "%s: option value too small: %s\n", progName, optArg);
	else if (maxVal != 0 && n > maxVal)  // value too big
		ft_dprintf(STDERR_FILENO, "%s: option value too big: %s\n", progName, optArg);
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
	ft_dprintf(STDERR_FILENO, PROG_NAME ": error in pattern near %s\n", text);
#else
	ft_dprintf(STDERR_FILENO, "%s: error in pattern near %s\n", progName, text);
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
		while (*text && ft_isspace((unsigned char)*text))
			text++;

		if (!*text)
			patternError(progName, start);

		int hi = hexCharToInt(*text++);
		if (hi == -1)
			patternError(progName, start);
		int lo = 0;
		if (*text && !ft_isspace((unsigned char)*text))
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
	if (proto == IP_PROTO_ICMP)
		return ("ICMP");
	else if (proto == IP_PROTO_ICMPV6)
		return ("ICMPv6");
	else if (proto == IP_PROTO_UDP)
		return ("UDP");
	else if (proto == IP_PROTO_TCP)
		return ("TCP");
	else
		return ("UNKNOWN");
}

const char *sockTypeToStr(tPingSocketType type)
{
	if (type == PING_SOCKET_ECHO)
		return ("ECHO");
	else if (type == PING_SOCKET_TIMESTAMP)
		return ("TIMESTAMP");
	else if (type == PING_SOCKET_ADDRESS)
		return ("ADDRESS");
	else
		return ("UNKNOWN");
}

int
clampInt(int val, int min, int max)
{
	if (val < min)
		return (min);
	if (val > max)
		return (max);
	return (val);
}

void
truncateAndMark(
	char		*dest,
	size_t		dest_size,
	const char	*src,
	size_t		max_len)
{
	size_t src_len = ft_strlen(src);

	if (dest_size == 0)
		return;

	if (max_len == 0)
	{
		/* copy whole string up to dest_size - 1 */
		size_t copy_len = src_len;
		if (copy_len >= dest_size)
			copy_len = dest_size - 1;
		ft_memcpy(dest, src, copy_len);
		dest[copy_len] = '\0';
		return;
	}

	if (src_len <= max_len)
	{
		/* copy whole string */
		size_t copy_len = src_len;
		if (copy_len >= dest_size)
			copy_len = dest_size - 1;
		ft_memcpy(dest, src, copy_len);
		dest[copy_len] = '\0';
	}
	else
	{
		/* truncated: copy max_len - 1 bytes then put '.' as last char */
		size_t copy_len = max_len;
		if (copy_len > dest_size - 1)
			copy_len = dest_size - 1;
		if (copy_len == 0)
		{
			dest[0] = '\0';
			return;
		}
		if (copy_len == 1)
		{
			dest[0] = '.';
			dest[1] = '\0';
			return;
		}
		/* copy copy_len bytes and set last char '.' */
		ft_memcpy(dest, src, copy_len);
		dest[copy_len - 1] = '.';
		dest[copy_len] = '\0';
	}
}
