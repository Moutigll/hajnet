#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>

#include "../includes/usage.h"
#include "../includes/utils.h"

void printUsage(char *progName)
{
	printf("\
Usage: %s [-dnrvfqR?V] [-t TYPE] [-c NUMBER] [-i NUMBER] [-T NUM] [-w N]\n\
            [-W N] [-l NUMBER] [-p PATTERN] [-s NUMBER] [--address] [--echo]\n\
            [--mask] [--timestamp] [--type=TYPE] [--count=NUMBER] [--debug]\n\
            [--interval=NUMBER] [--numeric] [--ignore-routing] [--ttl=N]\n\
            [--tos=NUM] [--verbose] [--timeout=N] [--linger=N] [--flood]\n\
            [--ip-timestamp=FLAG] [--preload=NUMBER] [--pattern=PATTERN]\n\
            [--quiet] [--route] [--size=NUMBER] [--help] [--usage] [--version]\n\
            HOST ...\n"
	, progName);
}

void printFullHelp(char *progName)
{
#if defined(HAJ)
	(void)progName;
	printf("Usage: " PROG_NAME " [OPTION...] HOST ...\n");
#else
	printf("Usage: %s [OPTION...] HOST ...\n", progName);
#endif
	printf("Send ICMP ECHO_REQUEST packets to network hosts.\n\n");
	printf(" Options controlling ICMP request types:\n");
	printf("\
      --address              send ICMP_ADDRESS packets (root only)\n\
      --echo                 send ICMP_ECHO packets (default)\n\
      --mask                 same as --address\n\
      --timestamp            send ICMP_TIMESTAMP packets\n\
  -t, --type=TYPE            send TYPE packets\n\n");
	printf(" Options valid for all request types:\n\n");
	printf("\
  -c, --count=NUMBER         stop after sending NUMBER packets\n\
  -d, --debug                set the SO_DEBUG option\n\
  -i, --interval=NUMBER      wait NUMBER seconds between sending each packet\n\
  -n, --numeric              do not resolve host addresses\n\
  -r, --ignore-routing       send directly to a host on an attached network\n\
      --ttl=N                specify N as time-to-live\n\
  -T, --tos=NUM              set type of service (TOS) to NUM\n\
  -v, --verbose              verbose output\n\
  -w, --timeout=N            stop after N seconds\n\
  -W, --linger=N             number of seconds to wait for response\n\n");
	printf(" Options valid for --echo requests:\n\n");
	printf("\
  -f, --flood                flood ping (root only)\n\
      --ip-timestamp=FLAG    IP timestamp of type FLAG, which is one of\n\
                             \"tsonly\" and \"tsaddr\"\n\
  -l, --preload=NUMBER       send NUMBER packets as fast as possible before\n\
                             falling into normal mode of behavior (root only)\n\
  -p, --pattern=PATTERN      fill ICMP packet with given pattern (hex)\n\
  -q, --quiet                quiet output\n");
#if defined(HAJ)
	printf("\
  -R, --record-route         record route (root only)\n\
  -s, --packet-size=NUMBER   send NUMBER data octets\n\n");
#else
	printf("\
  -R, --route                record route\n\
  -s, --size=NUMBER          send NUMBER data octets\n\n");
#endif
	printf("\
  -%s, --help                 give this help list\n\
      --usage                give a short usage message\n\
  -V, --version              print program version\n\n", HELP_SHORT_OPT);
	printf("\
Mandatory or optional arguments to long options are also mandatory or optional\n\
for any corresponding short options.\n\n\
Options marked with (root only) are available only to superuser.\n");
#if !defined(HAJ)
	printf("\nReport bugs to <bug-inetutils@gnu.org>.\n");
#endif
}

void
exitBadOption(const char *progName, char badOpt, const char *badOptStr)
{
	if (badOptStr && *badOptStr)
		fprintf(stderr, "%s: unrecognized option '%s'\n", progName, badOptStr);
	else
		fprintf(stderr, "%s: invalid option -- '%c'\n", progName, badOpt);
	fprintf(stderr, "Try '%s --help' or '%s --usage' for more information.\n", progName, progName);
	exit(EXIT_INVALID_OPTION);
}

void
exitMissingArg(const char *progName, char opt, const char *optStr)
{
	if (optStr && *optStr && optStr[1] != '\0')  // long option
		fprintf(stderr, "%s: option '--%s' requires an argument\n", progName, optStr);
	else  // simple short option
		fprintf(stderr, "%s: option requires an argument -- '%c'\n", progName, opt);
	fprintf(stderr, "Try '%s --help' or '%s --usage' for more information.\n", progName, progName);
	exit(EXIT_INVALID_OPTION);
}

void
exitAmbiguousOption(const char *progName, const char *badOpt, const char *optA, const char *optB)
{
	fprintf(stderr,
		"%s: option '%s' is ambiguous; possibilities: '--%s' '--%s'\n",
		progName,
		badOpt,
		optA,
		optB);
	fprintf(stderr,
		"Try '%s --help' or '%s --usage' for more information.\n",
		progName, progName);
	exit(EXIT_INVALID_OPTION);
}

void
printMissingHost(const char *progName)
{
	fprintf(stderr, "%s: missing host operand\n", progName);
	fprintf(stderr, "Try '%s --help' or '%s --usage' for more information.\n", progName, progName);
}

void
printPingSummary(tPingContext *ctx)
{
	if (!ctx)
		return;

#if defined(HAJ)
	printf("\n--- %s " PROG_NAME " statistics ---\n", ctx->targetHost);
#else
	printf("--- %s " PROG_NAME " statistics ---\n", ctx->targetHost);
#endif
	unsigned int actualReceived = ctx->stats.received - ctx->stats.duplicates;
	double lossPercent = ctx->stats.sent > 0
		? ((double)(ctx->stats.sent - actualReceived) * 100.0 / (double)ctx->stats.sent)
		: 0.0;


	printf("%u packets transmitted, %u received, %.0f%% packet loss",
		   ctx->stats.sent,
		   ctx->stats.received,
		   lossPercent);

#if defined(HAJ)
	if (ctx->stats.errors > 0)
		printf(" +%u errors", ctx->stats.errors);
	if (ctx->stats.duplicates > 0)
		printf(" ++%u duplicates", ctx->stats.duplicates);
#endif
	/* Calculate average RTT and standard deviation */
	if (ctx->stats.received > 0 && (ctx->opts.packetSize == 0 || ctx->opts.packetSize >= (int)sizeof(struct timeval))) /* if the size is smaller than 16 octets we can't fit a timestamp so no rtt srry :/ */
	{
		double rttAvg = ctx->stats.rttSum / ctx->stats.received;
		double rttSddev = 0.0;	/* Average deviation of packet relative to mean RTT */
		if (ctx->stats.received > 1)
		{
			/**
			 * stdev: σ = sqrt(σ²); = n ​∑(xi​−μ)²; (μ = average RTT; xi = each RTT)
			 * ctx->stats.rttSumSq = ∑(xi²)
			 * variance = sqrt( (∑(xi²)/n) - (μ²) )
			 */
			double variance = (ctx->stats.rttSumSq / ctx->stats.received) - (rttAvg * rttAvg);
			rttSddev = ftSqrtNewton(variance);
		}
		printf("\nround-trip min/avg/max/stdev = %.3f/%.3f/%.3f/%.3f ms",
				ctx->stats.rttMin,
				rttAvg,
				ctx->stats.rttMax,
				rttSddev);
	}
}
