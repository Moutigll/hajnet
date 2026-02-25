#include "../../hajlib/include/hprintf.h"

void	printUsage(char *progName)
{
	ft_printf("\
Usage: %s [-46dFnreAUV] [-f FIRST_TTL] [-g GATE,...] [-i IFACE]\n\
            [-m MAX_TTL] [-N SQUERIES] [-p PORT] [-t TOS]\n\
            [-l FLOW] [-w MAX] [-q NQUERIES] [-s SRC]\n\
            [-z SENDWAIT] [-M NAME] [-O OPTS] [-P PROT]\n\
            [--sport=PORT] [--fwmark=NUM] [--mtu] [--back]\n\
            HOST ... [ packetlen ]\n",
		progName);
}

void	printFullHelp(char *progName)
{
	ft_printf("Usage: %s [OPTION...] HOST ... [ packetlen ]\n", progName);
	ft_printf("Print the route packets take to network host.\n\n");

	ft_printf(" Address family selection:\n\n");
	ft_printf("\
  -4                         use IPv4\n\
  -6                         use IPv6\n\n");

	ft_printf(" Probe method selection (mutually exclusive):\n\n");
	ft_printf("\
  -U, --udp                  use UDP for probing (default port 53)\n\
  -I, --icmp                 use ICMP ECHO for probing\n\
  -T, --tcp                  use TCP SYN (default port 80)\n\
      --udplite              use UDPLITE for probing\n\
  -D, --dccp                 use DCCP request (default port 33434)\n\
  -P, --protocol=PROT        use raw IP protocol number PROT\n\n");

	ft_printf(" General options:\n\n");
	ft_printf("\
  -d, --debug                enable socket-level debugging\n\
  -F, --dont-fragment        set Don't Fragment flag\n\
  -f, --first=FIRST_TTL      start from FIRST_TTL (default 1)\n\
  -m, --max-hops=MAX_TTL     set maximum hops (default 30)\n\
  -q, --queries=NQUERIES     probes per hop (default 3)\n\
  -N, --sim-queries=NUM      simultaneous probes (default 16)\n\
  -n                         do not resolve hostnames\n\
  -r                         bypass normal routing\n\
  -i, --interface=IFACE      specify outgoing interface\n\
  -s, --source=SRC           specify source address\n\
  -p, --port=PORT            destination port\n\
      --sport=PORT           source port (implies -N 1)\n\
      --fwmark=NUM           set firewall mark\n\n");

	ft_printf(" Packet options:\n\n");
	ft_printf("\
  -t, --tos=TOS              set TOS (IPv4) or traffic class (IPv6)\n\
  -l, --flowlabel=FLOW       set IPv6 flow label\n\
  -z, --sendwait=TIME        interval between probes\n\
  -w, --wait=MAX             max wait time for responses (seconds)\n\
      --mtu                  discover MTU (implies -F -N 1)\n\
      --back                 attempt backward path detection\n\n");

	ft_printf(" Advanced options:\n\n");
	ft_printf("\
  -g, --gateway=G1,G2,...    route through specified gateways\n\
  -e, --extensions           show ICMP extensions\n\
  -A, --as-path-lookups      display AS path information\n\
  -M, --module=NAME          use specified traceroute module\n\
  -O, --options=OPTS         module-specific options\n\n");

	ft_printf("\
  -V, --version              print program version\n\
      --help                 display this help and exit\n\n");

	ft_printf("\
Mandatory or optional arguments to long options are also mandatory or optional\n\
for the corresponding short options.\n");
}
