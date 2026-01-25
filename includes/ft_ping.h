#ifndef FT_PING_H
# define FT_PING_H

# include <unistd.h>
# include <stdlib.h>
# include <stdio.h>
# include <signal.h>
# include <string.h>

# define EXIT_SUCCESS 0
# define EXIT_FAILURE 1

void	handleSigint(int signum);

#endif
