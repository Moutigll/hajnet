#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "../includes/getopt.h"


static int
isEndOptions(const char *arg)
{
	if (!arg)
		return (0);
	if (strcmp(arg, "--") == 0)
		return (1);
	return (0);
}

static int
isShortOption(const char *arg)
{
	if (!arg)
		return (0);
	if (arg[0] == '-' && arg[1] && arg[1] != '-')
		return (1);
	return (0);
}

static int
isLongOption(const char *arg)
{
	if (!arg)
		return (0);
	if (arg[0] == '-' && arg[1] == '-' && arg[2])
		return (1);
	return (0);
}


static tFtGetoptHasArg
shortHasArg(const char c, const char *short_opts)
{
	int	i;

	i = 0;
	while (short_opts[i])
	{
		if (short_opts[i] == c)
		{
			if (short_opts[i + 1] == ':')
				return (FT_GETOPT_REQUIRED_ARGUMENT);
			return (FT_GETOPT_NO_ARGUMENT);
		}
		i++;
	}
	return (FT_GETOPT_INVALID_ARGUMENT);
}

/**
 * @brief Find exact match for long option name
 * @param name - option name to find
 * @param opts - array of long options
 * @return pointer to matching option, or NULL if not found
 */
static const tFtLongOption
*findLongExact(
	const char			*name,
	const tFtLongOption	*opts)
{
	int	i;

	i = 0;
	while (opts[i].name)
	{
		if (strcmp(opts[i].name, name) == 0)
			return (&opts[i]);
		i++;
	}
	return (NULL);
}

/**
 * @brief Find partial matches for long option name
 * @param name - option name to find
 * @param opts - array of long options
 * @param a - first matching option (output)
 * @param b - second matching option (output)
 * @return number of matches found
 */
static int	findLongMatches(
	const char *name,
	const tFtLongOption *opts,
	const tFtLongOption **a,
	const tFtLongOption **b)
{
	int		i;
	size_t	len;
	int		count;

	i = 0;
	count = 0;
	len = strlen(name);
	while (opts[i].name)
	{
		if (strncmp(opts[i].name, name, len) == 0)
		{
			if (count == 0)
				*a = &opts[i];
			else if (count == 1)
				*b = &opts[i];
			count++;
		}
		i++;
	}
	return (count);
}

/**
 * @brief Parse long option argument (after '--option' or '--option=')
 * @param st - getopt state
 * @param name - buffer to store option name
 * @param size - size of name buffer
 * @return 1 if argument was found after '=', 0 otherwise 
 */
static int
parseLongArg(tFtGetopt *st, char *name, size_t size)
{
	const char	*arg;
	const char	*eq;
	size_t		len;

	arg = st->argv[st->index] + 2;
	eq = strchr(arg, '=');
	if (eq)
	{
		len = (size_t)(eq - arg);
		if (len >= size)
			len = size - 1;
		strncpy(name, arg, len);
		name[len] = '\0';
		st->optArg = (char *)(eq + 1);
		return (1);
	}
	strncpy(name, arg, size - 1);
	name[size - 1] = '\0';
	st->optArg = NULL;
	return (0);
}

/* ============================================================= */
/* 							Main functions						 */
/* ============================================================= */

static tFtGetoptStatus
handleShort(tFtGetopt *st, const char *short_opts)
{
	const char		c = st->argv[st->index][st->subIndex];
	tFtGetoptHasArg	arg_type;

	arg_type = shortHasArg(c, short_opts);
	if (arg_type == FT_GETOPT_INVALID_ARGUMENT) /* unknown option */
	{
		st->badOpt = &st->argv[st->index][st->subIndex];
		st->status = FT_GETOPT_UNKNOWN;
		return (FT_GETOPT_ERROR);
	}
	st->opt = c;
	if (arg_type == FT_GETOPT_REQUIRED_ARGUMENT)
	{
		if (st->argv[st->index][st->subIndex + 1]) /* arg is concatenated */
		{
			st->optArg = &st->argv[st->index][st->subIndex + 1]; /* point to arg */
			st->index++;
			st->subIndex = 0;
			return (FT_GETOPT_OK);
		}
		if (st->index + 1 >= st->argc) /* no more argv -> missing arg */
		{
			st->badOpt = &st->argv[st->index][st->subIndex];
			st->status = FT_GETOPT_MISSING_ARG;
			return (FT_GETOPT_ERROR);
		}
		st->optArg = st->argv[st->index + 1]; /* take next argv as arg */
		st->index += 2;
		st->subIndex = 0;
		return (FT_GETOPT_OK);
	}
	st->subIndex++;
	if (!st->argv[st->index][st->subIndex]) // end of this argv
	{
		st->index++;
		st->subIndex = 0;
	}
	return (FT_GETOPT_OK);
}

static tFtGetoptStatus
resolveLongOption(
	tFtGetopt *st,
	const tFtLongOption *opts,
	const char *name,
	const tFtLongOption **outOpt)
{
	const tFtLongOption	*exact;
	const tFtLongOption	*a;
	const tFtLongOption	*b;
	int					mCount;

	a = NULL;
	b = NULL;
	exact = findLongExact(name, opts);
	mCount = findLongMatches(name, opts, &a, &b);
	if (!exact && mCount > 1)
	{
		st->badOpt = st->argv[st->index];
		st->ambiguousA = a ? a->name : NULL;
		st->ambiguousB = b ? b->name : NULL;
		st->status = FT_GETOPT_AMBIGUOUS;
		return (FT_GETOPT_ERROR);
	}
	if (!exact && mCount == 0)
	{
		st->badOpt = st->argv[st->index];
		st->status = FT_GETOPT_UNKNOWN;
		return (FT_GETOPT_ERROR);
	}
	*outOpt = exact ? exact : a;
	return (FT_GETOPT_OK);
}

static tFtGetoptStatus
handleLong(tFtGetopt *st, const tFtLongOption *opts)
{
	char					name[256];
	const tFtLongOption		*opt;
	int						hasArg;

	hasArg = parseLongArg(st, name, sizeof(name));
	if (resolveLongOption(st, opts, name, &opt) != FT_GETOPT_OK)
		return (FT_GETOPT_ERROR);
	st->opt = opt->val;
	if (opt->hasArg != FT_GETOPT_REQUIRED_ARGUMENT)
	{
		st->index++;
		return (FT_GETOPT_OK);
	}
	if (hasArg)
	{
		st->index++;
		return (FT_GETOPT_OK);
	}
	if (st->index + 1 < st->argc)
	{
		st->optArg = st->argv[st->index + 1];
		st->index += 2;
		return (FT_GETOPT_OK);
	}
	st->badOpt = opt->name;
	st->status = FT_GETOPT_MISSING_ARG;
	return (FT_GETOPT_ERROR);
}

void
ftGetoptInit(tFtGetopt *st, int argc, char **argv)
{
	st->argc = argc;
	st->argv = argv;
	st->index = 1;
	st->subIndex = 0;
	st->optArg = NULL;
	st->opt = 0;
	st->badOpt = NULL;
	st->ambiguousA = NULL;
	st->ambiguousB = NULL;
	st->status = FT_GETOPT_OK;
}

tFtGetoptStatus
ftGetoptLong(
	tFtGetopt			*st,
	const char			*short_opts,
	const tFtLongOption	*long_opts)
{
	st->optArg = NULL;
	st->opt = 0;
	st->badOpt = NULL;
	st->ambiguousA = NULL;
	st->ambiguousB = NULL;
	st->status = FT_GETOPT_OK;
	if (st->index >= st->argc)
		return (FT_GETOPT_END);
	if (isEndOptions(st->argv[st->index]))
	{
		st->index++;
		return (FT_GETOPT_END);
	}
	if (isLongOption(st->argv[st->index]))
		return (handleLong(st, long_opts));
	if (isShortOption(st->argv[st->index]))
	{
		if (st->subIndex == 0)
			st->subIndex = 1;
		return (handleShort(st, short_opts));
	}
	return (FT_GETOPT_END);
}
