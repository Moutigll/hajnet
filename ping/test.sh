#!/usr/bin/env bash

set -u

if [ $# -ne 2 ]; then
	printf '\033[31mUsage: %s <executable1> <executable2>\033[0m\n' "$0"
	exit 1
fi

EXE1="$1"
EXE2="$2"

# colors
GREEN="\033[32m"; RED="\033[31m"; YELLOW="\033[33m"; CYAN="\033[36m"; RESET="\033[0m"


ARGS_LIST=(
	""					  # no args
	"-h"				  # help short
	"'  -h'"			  # leading spaces
	"-?"				  # help alternative
	"--help"			  # long help
	"--usage"			  # long usage
	"--help --usage"	  # both long options
	"--usage --help"	  # reversed order
	"-c"				  # short option missing argument
	"-c 0"				  # zero argument (allowed or not)
	"-c -1"				  # negative argument
	"-c 500000000000000000000000000000" # should still be accepted as numeric
	"-c '3 4'"			  # value with space
	"-c '3 '"			  # value with trailing space
	"-c 1 -- --help"	  # stop parsing with --
	"-c=1"				  # attached equals
	"--count=2"			  # long option attached
	"--count 2"			  # long option separate
	"--count==2"		  # double equals
	"'--count 2'"		  # leading space
	"'--count= 2'"		  # space after =
	"'--count =2'"		  # space before =
	"'--count=' 2s"		  # invalid numeric value
	"'--c=2'"			  # partial long option
	"--count="			  # missing value
	"--c="				  # missing value short form
	"--c=2"				  # short form with value
	"--cou=2"			  # ambiguous or partial
	"--ti"				  # ambiguous option
	"--tim"				  # ambiguous option
	"--timeou=5"		  # partial long option
	"--wefwf"			  # unknown long option
	"--z"				  # unknown long
	"-z"				  # unknown short

	# ----- COMBINED SHORT OPTIONS -----
	"-vn"				  # -v and -n together
	"-vc 3"				  # combined short with argument
	"-vf"				  # -v and -f together

	# ----- SHORT OPTIONS WITH IMMEDIATE ARGUMENT -----
	"-c3"				  # -c value attached
	"-w5"				  # -w value attached
	"-W10"				  # -W value attached

	# ----- LONG OPTIONS WITH ARGUMENT -----
	"--count 4"			  # separated
	"--timeout=10"		  # attached
	"--timeout 10"		  # separated
	"--pattern=abcd"	  # attached
	"--pattern abcd"	  # separated

	# ----- LONG OPTION AMBIGUOUS PREFIX -----
	"--co"				  # ambiguous prefix for count (if others added)
	"--pa"				  # ambiguous between pattern and preload

	# ----- LONG OPTION WITH SPACES -----
	"'--pattern =abcd'"	  # space before =
	"'--pattern= abcd'"	  # space after =
	"'--count =5'"		  # space before =
	"'--count= 5'"		  # space after =

	# ----- FINISH PARSING WITH -- -----
	"-- --count=5"		  # stop parsing at --
	"-v -- -c 2"		  # stop parsing after --

	# ----- INVALID NUMERIC VALUES -----
	"-c abc"			  # non-numeric short
	"--count=abc"		  # non-numeric long
	"--timeout=abc"		  # non-numeric long
	"--preload=-1"		  # negative value if forbidden
	"--preload=-255"	  # negative value if forbidden

	# ----- REPEATED OPTIONS -----
	"-v -v -v"			  # multiple verbose
	"--count=1 --count=2" # repeated long option

	# ----- EXTREME COMBINATIONS -----
	"-v -n -f -c3 --timeout=5 --pattern=aa --preload=2"
	"-c 1 -- --count=5 -v"


	# ----- COUNT (-c / --count) -----
	"-c 1"						# normal value
	"-c 0001"					# leading zeros
	"-c +1"						# explicit plus
	"-c -0"						# negative zero
	"-c +0"						# explicit zero
	"-c 4294967295"				# UINT32_MAX
	"-c 18446744073709551615"	# UINT64_MAX
	"-c --1"					# malformed
	"-c ++1"					# malformed

	"--count=1"
	"--count=0001"
	"--count=+1"
	"--count=-1"
	"--count=18446744073709551615"
	"--count=abc"

	# ----- INTERVAL (-i) : double parsing via strtod -----
	"-i 1"						# integer
	"-i 0.1"					# decimal
	"-i .5"						# leading dot
	"-i 1."						# trailing dot
	"-i 1e3"					# scientific notation
	"-i 1e-3"					# scientific notation
	"-i 0"						# zero interval
	"-i -1"						# negative
	"-i nan"					# NaN (strtod accepts)
	"-i inf"					# infinity (strtod accepts)
	"-i 1.2.3"					# malformed
	"-i 1,5"					# locale-dependent format

	# ----- DATA SIZE (-s) -----
	"-s 1"						# minimal valid
	"-s 8"						# small payload
	"-s 56"						# default ping size
	"-s 1472"					# typical MTU payload
	"-s 65400"					# maximum size for ICMP payload
	"-s 65399"					# maximum size for IP packet
	"-s 65535"					# overflow
	"-s 65536"					# overflow
	"-s -1"						# negative
	"-s +1"						# explicit plus
	"-s 01"						# leading zero
	"-s 1.5"					# float
	"-s abc"					# non-numeric

	# ----- TOS (-T) -----
	"-T 0"						# minimum
	"-T 1"
	"-T 255"					# maximum
	"-T 256"					# overflow
	"-T -1"						# negative
	"-T +1"						# explicit plus
	"-T 01"						# leading zero
	"-T 1.5"					# float
	"-T abc"					# non-numeric

	# ----- TIMEOUT (-w) -----
	"-w 1"
	"-w 0"						# forbidden (allowZero = 0)
	"-w -1"
	"-w 2147483647"				# INT_MAX
	"-w 2147483648"				# INT_MAX + 1
	"-w +1"
	"-w 01"
	"-w 1.0"
	"-w abc"

	# ----- LINGER (-W) -----
	"-W 1"
	"-W 0"						# forbidden
	"-W -1"
	"-W 2147483647"
	"-W 2147483648"
	"-W +1"
	"-W 01"
	"-W 1.0"
	"-W abc"

	# ----- PRELOAD (-l) -----
	"-l 0"
	"-l 1"
	"-l -1"						# should fail (inetutils behavior)
	"-l 2147483647"
	"-l 2147483648"				# overflow
	"-l 999999999999"
	"-l +1"
	"-l 01"
	"-l 1.5"
	"-l abc"

	# ----- TTL (--ttl) -----
	"--ttl 1"
	"--ttl 255"
	"--ttl 0"					# forbidden (allowZero = 0)
	"--ttl 256"
	"--ttl -1"
	"--ttl +1"
	"--ttl 01"
	"--ttl 1.5"
	"--ttl abc"

	# ----- PATTERN (--pattern) -----
	"-p ab"					# valid: single byte
	"-p deadbeef"			# valid: classic hex pattern
	"-p 00ff"				# valid: null byte + max byte
	"-p 01020304"			# valid: incremental bytes

	"--pattern=abcd"		# valid hex (should NOT be treated as ASCII)
	"--pattern deadbeef"	# valid, separated argument
	"--pattern=DEADBEEF"	# valid: uppercase hex
	"--pattern=deAdBeEf"	# valid: mixed case
	"-p ''"					# empty string
	"-p 0"					# invalid: odd number of hex digits
	"-p abc"				# invalid: odd length
	"-p abcg"				# invalid: non-hex char
	"-p ' ' "				# invalid: space inside quoted value
	"-p '    s'"			# invalid: non-hex inside quotes
	"-p zz"					# invalid: non-hex
	"-p 12gohepgihwe"		# invalid: non-hex
	"-p '12 34'"			# valid: spaces inside quotes

	# ----- IP-TIMESTAMP (--ip-timestamp) -----
	"--ip-timestamp"				# no arg, default mode
	"--ip-timestamp=1"				# invalid num value
	"--ip-timestamp=dsdfsdf"		# invalid str value
	"--ip-timestamp=tsonly"			# valid mode
	"--ip-timestamp=addronly"		# valid mode
	"--ip-timestamp="				# missing value

	# ----- MULTI-NUMERIC COMBINATIONS -----
	"-c 1 -s 65464 -T 255 -w 1 -W 1 -l 1 --ttl 255"
	"-c 0 -s 0 -T 0 -w 0 -W 0 -l 0 --ttl 0"
	"-c -1 -s -1 -T -1 -w -1 -W -1 -l -1 --ttl -1"
	"-c abc -s abc -T abc -w abc -W abc -l abc --ttl abc"
)

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

echo -e "${CYAN}Comparing ${EXE1} and ${EXE2}...${RESET}"

quote_cmd() {
	local -n arr=$1
	local i out=""
	for i in "${arr[@]}"; do
		out+=" $(printf '%q' "$i")"
	done
	printf '%s' "${out# }"
}

run_with_argv0_ping() {
	local exe="$1"; shift
	bash -c 'exec -a pingu "$0" "$@"' "$exe" "$@"
}

total=0
success=0

for test in "${ARGS_LIST[@]}"; do
	total=$((total + 1))
	echo -e "${YELLOW}[$total] ==============================${RESET}"
	printf "${CYAN}Testing arguments:${RESET} '%s'\n" "$test"

	ARGS_ARRAY=()
	if [ -n "$test" ]; then
		if ! eval "ARGS_ARRAY=( $test )"; then
			echo -e "${RED}Invalid test string (eval failed): $test${RESET}"
			continue
		fi
	fi

	CMDLINE=$(quote_cmd ARGS_ARRAY)
	printf "Command args: %s\n" "$CMDLINE"

	STDOUT1="$TMP_DIR/stdout1.txt"; STDERR1="$TMP_DIR/stderr1.txt"
	STDOUT2="$TMP_DIR/stdout2.txt"; STDERR2="$TMP_DIR/stderr2.txt"

	if run_with_argv0_ping "$EXE1" "${ARGS_ARRAY[@]}" >"$STDOUT1" 2>"$STDERR1"; then
		CODE1=0
	else
		CODE1=$?
	fi

	if run_with_argv0_ping "$EXE2" "${ARGS_ARRAY[@]}" >"$STDOUT2" 2>"$STDERR2"; then
		CODE2=0
	else
		CODE2=$?
	fi

	diff --color=always -u "$STDOUT1" "$STDOUT2" >"$TMP_DIR/diff_stdout.txt" 2>/dev/null
	STDOUT_MATCH=$([ -s "$TMP_DIR/diff_stdout.txt" ] && echo 0 || echo 1)

	diff --color=always -u "$STDERR1" "$STDERR2" >"$TMP_DIR/diff_stderr.txt" 2>/dev/null
	STDERR_MATCH=$([ -s "$TMP_DIR/diff_stderr.txt" ] && echo 0 || echo 1)

	CODE_MATCH=$([ "$CODE1" -eq "$CODE2" ] && echo 1 || echo 0)

	if [ "$STDOUT_MATCH" -eq 1 ] && [ "$STDERR_MATCH" -eq 1 ] && [ "$CODE_MATCH" -eq 1 ]; then
		echo -e "${GREEN}✅ All match (exit code: ${CODE1})${RESET}"
		success=$((success + 1))
	else
		echo -e "${RED}❌ Differences detected:${RESET}"
		if [ "$STDOUT_MATCH" -eq 0 ]; then
			echo -e "${YELLOW}--- Stdout diff ---${RESET}"
			cat "$TMP_DIR/diff_stdout.txt"
			echo -e "${YELLOW}------------------${RESET}"
		else
			echo -e "${GREEN}Stdout identical${RESET}"
		fi
		if [ "$STDERR_MATCH" -eq 0 ]; then
			echo -e "${YELLOW}--- Stderr diff ---${RESET}"
			cat "$TMP_DIR/diff_stderr.txt"
			echo -e "${YELLOW}------------------${RESET}"
		else
			echo -e "${GREEN}Stderr identical${RESET}"
		fi
		if [ "$CODE_MATCH" -eq 0 ]; then
			echo -e "${RED}Exit codes differ:${RESET} $EXE1=$CODE1, $EXE2=$CODE2"
		else
			echo -e "${GREEN}Exit codes identical: $CODE1${RESET}"
		fi
	fi
done

echo -e "${CYAN}==============================${RESET}"
echo -e "${CYAN}Test summary:${RESET} ${success}/${total} tests passed."