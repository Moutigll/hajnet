#include "../includes/ft_ping.h"

static void	printUsage(void)
{
	printf("Usage: ft_ping [-v] [-?] destination\n");
}

void	handleSigint(int signum)
{
	(void)signum;
	printf("\n--- ft_ping statistics ---\n");
	printf("0 packets transmitted, 0 received, 100%% packet loss\n");
	exit(EXIT_SUCCESS);
}

int	main(int argc, char **argv)
{
	int	i;

	i = 1;
	if (argc < 2)
	{
		printUsage();
		return (EXIT_FAILURE);
	}
	while (i < argc)
	{
		if (strcmp(argv[i], "-?") == 0)
		{
			printUsage();
			return (EXIT_SUCCESS);
		}
		i++;
	}
	signal(SIGINT, handleSigint);
	printf("PING %s\n", argv[argc - 1]);
	while (1)
		sleep(1);
	return (EXIT_SUCCESS);
}
