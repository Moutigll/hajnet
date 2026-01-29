#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>

#include "../includes/usage.h"

static double ft_sqrt(double x)
{
	if (x < 0.0)
		return -1.0;
	if (x == 0.0)
		return 0.0;
	
	double guess = x;
	double prev;
	
	while (1)
	{
		prev = guess;
		guess = (guess + x / guess) / 2.0;
		if (guess == prev)
			break;
	}
	return guess;
}

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

	printf("\n--- Ping statistics ---\n");
	printf("%u packets transmitted, %u received, %.2f%% packet loss\n",
		   ctx->stats.sent,
		   ctx->stats.received,
		   ctx->stats.sent > 0 ? ((ctx->stats.sent - ctx->stats.received) * 100.0 / ctx->stats.sent) : 0.0);

	if (ctx->stats.received > 0)
	{
		double rttAvg = ctx->stats.rttSum / ctx->stats.received;
		double rttMdev = 0.0;
		if (ctx->stats.received > 1)
		{
			double variance = (ctx->stats.rttSumSq / ctx->stats.received) - (rttAvg * rttAvg);
			rttMdev = ft_sqrt(variance);
		}
		printf("rtt min/avg/max/mdev = %.2f/%.2f/%.2f/%.2f ms\n",
			   ctx->stats.rttMin,
			   rttAvg,
			   ctx->stats.rttMax,
			   rttMdev);
	}
}

void printIcmpHeader(const unsigned char *buf, int len, int isIPv4)
{
	if (!buf || len < 8)
	{
		printf("Invalid buffer\n");
		return;
	}

	int offset = 0;
	int ttl = -1;

	if (isIPv4)
	{
		struct iphdr
		{
			unsigned char ihl:4;
			unsigned char version:4;
			unsigned char tos;
			unsigned short tot_len;
			unsigned short id;
			unsigned short frag_off;
			unsigned char ttl;
			unsigned char protocol;
			unsigned short check;
			unsigned int saddr;
			unsigned int daddr;
		} *ip = (void *)buf;

		offset = ip->ihl * 4;
		ttl = ip->ttl;
	}

	// ICMP header
	struct icmpHeader
	{
		unsigned char type;
		unsigned char code;
		unsigned short checksum;
		unsigned short id;
		unsigned short seq;
	} *icmp = (void *)(buf + offset);

	printf("+---------------------+---------------------+\n");
	printf("| Field               | Value               |\n");
	printf("+---------------------+---------------------+\n");
	printf("| Type                | %u                  |\n", icmp->type);
	printf("| Code                | %u                  |\n", icmp->code);
	printf("| Checksum            | 0x%04x             |\n", ntohs(icmp->checksum));
	printf("| Identifier (id)     | %u                  |\n", ntohs(icmp->id));
	printf("| Sequence number     | %u                  |\n", ntohs(icmp->seq));
	if (ttl >= 0)
		printf("| TTL                 | %d                  |\n", ttl);
	printf("+---------------------+---------------------+\n");
}