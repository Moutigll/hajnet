#ifndef FT_PING_H
# define FT_PING_H

# include <unistd.h>
# include <stdlib.h>
# include <stdio.h>
# include <signal.h>
# include <string.h>

# define EXIT_SUCCESS 0
# define EXIT_FAILURE 1

# define ERR_MISSING_HOST "missing host operand"
# define TRY_HELP_MSG "Try 'ping --help' or 'ping --usage' for more information."

#if defined (HAJ)
	# define EXIT_MISSING_HOST 2
	# define EXIT_INVALID_OPTION 2
	# define PROG_NAME "hajping"
	#define HELP_SHORT_OPT "h"
#else
	# define EXIT_MISSING_HOST 64
	# define EXIT_INVALID_OPTION 64
	# define PROG_NAME "ping"
	#define HELP_SHORT_OPT "?"
#endif


void	handleSigint(int signum);

#endif
