#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#include "../includes/ft_ping.h"
#include "../includes/parser.h"
#include "../includes/usage.h"
#include "../includes/utils.h"

void handleSigint(int signum)
{
	(void)signum;
	printf("\n--- ping statistics ---\n");
	printf("0 packets transmitted, 0 received, 100%% packet loss\n");
	exit(EXIT_SUCCESS);
}

int main(int argc, char **argv)
{
	tParseResult res;
	int ret;

	ret = parseArgs(argc, argv, &res);

	switch (ret)
	{
		case PARSE_HELP:
			printFullHelp(argv[0]);
			return EXIT_SUCCESS;

		case PARSE_USAGE:
			printUsage(argv[0]);
			return EXIT_SUCCESS;

		case PARSE_OK:
			break;
	}

	if (res.posCount == 0)
	{
		printMissingHost(argv[0]);
		return EXIT_MISSING_HOST;
	}

#if defined(haj)
	fprintf(stderr, PROG_NAME ": unknown host\n");
#else
	fprintf(stderr, "%s: unknown host\n", argv[0]);
#endif

	// startPing(res.positionals[res.posCount - 1], &res.options);
	return 1;
}
