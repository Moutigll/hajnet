#ifndef FT_GETOPT_LONG_H
#define FT_GETOPT_LONG_H

/**
 * @brief Enumeration for option argument requirements
 * - FT_GETOPT_NO_ARGUMENT: option does not take an argument
 * - FT_GETOPT_REQUIRED_ARGUMENT: option requires an argument
 * - FT_GETOPT_OPTIONAL_ARGUMENT: option may have an optional argument
 */
typedef enum eFtGetoptHasArg
{
	FT_GETOPT_NO_ARGUMENT		= 0,
	FT_GETOPT_REQUIRED_ARGUMENT	= 1,
	FT_GETOPT_OPTIONAL_ARGUMENT	= 2,
	FT_GETOPT_INVALID_ARGUMENT	= -1
}	tFtGetoptHasArg;

/**
 * @brief Enumeration for getopt status codes
 * - FT_GETOPT_OK: option parsed successfully
 * - FT_GETOPT_END: end of options reached
 * - FT_GETOPT_ERROR: an error occurred
 * - FT_GETOPT_UNKNOWN: unknown option encountered
 * - FT_GETOPT_AMBIGUOUS: ambiguous long option encountered
 * - FT_GETOPT_MISSING_ARG: required argument missing for option
 */
typedef enum eFtGetoptStatus
{
	FT_GETOPT_OK			= 0,
	FT_GETOPT_END			= -1,
	FT_GETOPT_ERROR			= -2,
	FT_GETOPT_UNKNOWN		= -4,
	FT_GETOPT_AMBIGUOUS		= -3,
	FT_GETOPT_MISSING_ARG	= -5
}	tFtGetoptStatus;

/**
 * @brief Structure describing a long option
 * Should contain:
 * - name: the long option name (without the leading --)
 * - hasArg: whether the option requires an argument
 * - val: the value to return when this option is found
 */
typedef struct sFtLongOption
{
	const char		*name;
	tFtGetoptHasArg	hasArg;
	int				val;
}	tFtLongOption;

/**
 * @brief Structure holding the state of the getopt parser
 * Should contain:
 * - argc, argv: the argument count and vector
 * - index: current index in argv
 * - subIndex: current index in argv[index] (for short options)
 * - optArg: the argument of the current option (if any)
 * - opt: the current option character or value
 * - badOpt: pointer to the invalid or ambiguous option string
 * - ambiguousA, ambiguousB: pointers to the two possible matches for ambiguous long options
 * - status: the last status code
 */
typedef struct sFtGetopt
{
	int				argc;
	char			**argv;

	int				index;			/* current argv index */
	int				subIndex;		/* current char index in argv[index] */

	char			*optArg;		/* current option argument */
	int				opt;			/* current option character */

	const char		*badOpt;		/* invalid or ambiguous option */
	const char		*ambiguousA;	/* first possible match */
	const char		*ambiguousB;	/* second possible match */

	tFtGetoptStatus	status;			/* last status code */
}	tFtGetopt;

/**
 * @brief Initialize the getopt state structure
 * @param state - pointer to the tFtGetopt structure to initialize
 * @param argc - argument count
 * @param argv - argument vector
 */
void	ftGetoptInit(tFtGetopt *state, int argc, char **argv);

/**
 * @brief Parse the next option from the argument vector
 * @param state - pointer to the tFtGetopt structure
 * @param shortOpts - string of valid short options
 * - a colon (:) after a character means it requires an argument
 * - two colons (::) means the argument is optional
 * @param longOpts - array of valid long options
 * @return the option character or value, or a negative status code
 */
tFtGetoptStatus	ftGetoptLong(
		tFtGetopt			*state,
		const char			*shortOpts,
		const tFtLongOption	*longOpts);

#endif
