/* usage.c */
#include <unistd.h> /* STDERR_FILENO */
#include "../../hajlib/include/hprintf.h"
#include "../includes/traceroute.h"

void printUsage(void)
{
	ft_dprintf(STDERR_FILENO,
		"Usage:\n"
		"  %s [ -46dFITnreAUDV ] [ -f first_ttl ] [ -g gate,... ] [ -i device ] [ -m max_ttl ] [ -N squeries ] [ -p port ] [ -t tos ] [ -l flow_label ] [ -w MAX,HERE,NEAR ] [ -q nqueries ] [ -s src_addr ] [ -z sendwait ] [ --fwmark=num ] host [ packetlen ]\n",
		PROG_NAME);
}

void printFullHelp(void)
{
	/* Usage line (same as system) */
	printUsage();

	/* short description */
	ft_dprintf(STDERR_FILENO,
		"Options:\n");

	/* options block - part 1 */
	ft_dprintf(STDERR_FILENO,
		"  -4                          Use IPv4\n"
		"  -6                          Use IPv6\n"
		"  -d  --debug                 Enable socket level debugging\n"
		"  -F  --dont-fragment         Do not fragment packets\n"
		"  -f first_ttl  --first=first_ttl\n"
		"                              Start from the first_ttl hop (instead from 1)\n"
		"  -g gate,...  --gateway=gate,...\n"
		"                              Route packets through the specified gateway\n"
		"                              (maximum 8 for IPv4 and 127 for IPv6)\n"
		"  -I  --icmp                  Use ICMP ECHO for tracerouting\n"
		"  -T  --tcp                   Use TCP SYN for tracerouting (default port is 80)\n"
		"  -i device  --interface=device\n"
		"                              Specify a network interface to operate with\n"
		"  -m max_ttl  --max-hops=max_ttl\n"
		"                              Set the max number of hops (max TTL to be\n"
		"                              reached). Default is 30\n"
		"  -N squeries  --sim-queries=squeries\n"
		"                              Set the number of probes to be tried\n"
		"                              simultaneously (default is 16)\n");

	/* options block - part 2 */
	ft_dprintf(STDERR_FILENO,
		"  -n                          Do not resolve IP addresses to their domain names\n"
		"  -p port  --port=port        Set the destination port to use. It is either\n"
		"                              initial udp port value for \"default\" method\n"
		"                              (incremented by each probe, default is 33434), or\n"
		"                              initial seq for \"icmp\" (incremented as well,\n"
		"                              default from 1), or some constant destination\n"
		"                              port for other methods (with default of 80 for\n"
		"                              \"tcp\", 53 for \"udp\", etc.)\n"
		"  -t tos  --tos=tos           Set the TOS (IPv4 type of service) or TC (IPv6\n"
		"                              traffic class) value for outgoing packets\n"
		"  -l flow_label  --flowlabel=flow_label\n"
		"                              Use specified flow_label for IPv6 packets\n");

	/* options block - part 3 */
	ft_dprintf(STDERR_FILENO,
		"  -w MAX,HERE,NEAR  --wait=MAX,HERE,NEAR\n"
		"                              Wait for a probe no more than HERE (default 3)\n"
		"                              times longer than a response from the same hop,\n"
		"                              or no more than NEAR (default 10) times than some\n"
		"                              next hop, or MAX (default 5.0) seconds (float\n"
		"                              point values allowed too)\n"
		"  -q nqueries  --queries=nqueries\n"
		"                              Set the number of probes per each hop. Default is\n"
		"                              3\n"
		"  -r                          Bypass the normal routing and send directly to a\n"
		"                              host on an attached network\n"
		"  -s src_addr  --source=src_addr\n"
		"                              Use source src_addr for outgoing packets\n"
		"  -z sendwait  --sendwait=sendwait\n"
		"                              Minimal time interval between probes (default 0).\n"
		"                              If the value is more than 10, then it specifies a\n"
		"                              number in milliseconds, else it is a number of\n"
		"                              seconds (float point values allowed too)\n");

	/* options block - part 4 */
	ft_dprintf(STDERR_FILENO,
		"  -e  --extensions            Show ICMP extensions (if present), including MPLS\n"
		"  -A  --as-path-lookups       Perform AS path lookups in routing registries and\n"
		"                              print results directly after the corresponding\n"
		"                              addresses\n"
		"  -M name  --module=name      Use specified module (either builtin or external)\n"
		"                              for traceroute operations. Most methods have\n"
		"                              their shortcuts (`-I' means `-M icmp' etc.)\n"
		"  -O OPTS,...  --options=OPTS,...\n"
		"                              Use module-specific option OPTS for the\n"
		"                              traceroute module. Several OPTS allowed,\n"
		"                              separated by comma. If OPTS is \"help\", print info\n"
		"                              about available options\n");

	/* options block - final part */
	ft_dprintf(STDERR_FILENO,
		"  --sport=num                 Use source port num for outgoing packets. Implies\n"
		"                              `-N 1'\n"
		"  --fwmark=num                Set firewall mark for outgoing packets\n"
		"  -U  --udp                   Use UDP to particular port for tracerouting\n"
		"                              (instead of increasing the port per each probe),\n"
		"                              default port is 53\n"
		"  -UL                         Use UDPLITE for tracerouting (default dest port\n"
		"                              is 53)\n"
		"  -D  --dccp                  Use DCCP Request for tracerouting (default port\n"
		"                              is 33434)\n"
		"  -P prot  --protocol=prot    Use raw packet of protocol prot for tracerouting\n"
		"  --mtu                       Discover MTU along the path being traced. Implies\n"
		"                              `-F -N 1'\n"
		"  --back                      Guess the number of hops in the backward path and\n"
		"                              print if it differs\n"
		"  -V  --version               Print version info and exit\n"
		"  --help                      Read this help and exit\n\n");

	/* Arguments block - match spacing/format exactly */
	ft_dprintf(STDERR_FILENO,
		"Arguments:\n"
		"+     host          The host to traceroute to\n"
		"      packetlen     The full packet length (default is the length of an IP\n"
		"                    header plus 40). Can be ignored or increased to a minimal\n"
		"                    allowed value\n");
}
