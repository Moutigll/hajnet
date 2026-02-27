#!/usr/bin/env bash
# Exhaustive traceroute CLI comparator
# Usage: ./tester.sh <exe1> <exe2>

set -u
IFS=$'\n\t'

if [ $# -ne 2 ]; then
	printf '\033[31mUsage: %s <executable1> <executable2>\033[0m\n' "$0"
	exit 1
fi

EXE1="$1"
EXE2="$2"

# colours
GREEN="\033[32m"; RED="\033[31m"; YELLOW="\033[33m"; CYAN="\033[36m"; RESET="\033[0m"

# Array of argument test-cases (quoted fragments will be eval'ed into arrays)
# This list is long but tries to be exhaustive for traceroute options from the spec you provided
ARGS_LIST=(
	""
	"-h"
	"--help"
	"--usage"
	"-4"
	"-6"
	"-d"
	"-F"
	"-I"
	"-T"
	"-U"
	"-UL"
	"--mt"
	"--mtu"

	"-f"
	"-f dsad"
	"-f 5"
	"-f 0 exemple.com"
	"-f -1000 exemple.com"
	"-f 31 exemple.com"
	"traceroute -f 3.0"

	"traceroute -m 0 exemple.com"
	"traceroute -m 10000 exemple.com"
	"traceroute -m 256 exemple.com"
	"traceroute -m 3.0"
	"traceroute -f 30 -m 15 exemple.com"

	"-g"
	"-g "
	"--g"
	"--gateway"
	"--gateway="
	"-g exemple.com"
	"--gateway=exemple.com"
	"-6 -g 2001:4860:4860::8888 exemple.com"
	"-g 2001:db8::1 exemple.com"
	"--gateway=2001:db8::1 exemple.com"
	"-g 1.1.1.1,2.2.2.2,3.3.3.3,4.4.4.4,5.5.5.5,6.6.6.6,7.7.7.7,8.8.8.8,9.9.9.9 exemple.com" # 9 FAIL
	"-g , exemple.com"
	"-g s example.com"
	"-g :: example.com"
	"-g ,1.1.1.1 exemple.com"
	"-g 1.1.1.1, ,2.2.2.2 exemple.com"
	"-g 999.999.999.999 exemple.com"
	"-g 256.256.256.256 exemple.com"
	"-g abc.def.ghi.jkl exemple.com"
	"-g 2001:::1 exemple.com"
	"-g gggg::1 exemple.com"
	"-g 1.1.1.1,2001:db8::1 exemple.com"
	"-4 -g 2001:db8::1 exemple.com"
	"-6 -g 1.1.1.1 exemple.com"
	"-g 2001:db8::1,2001:db8::1 exemple.com"
	"-g $(printf '1.1.1.1,' {1..50})exemple.com"
	"-g $(printf '2001:db8::1,' {1..200})exemple.com"
	"-g 1.1.1.1"
	"-g 1.1.1.1 exemple.com extra"
	"-g 255.255.255.255 exemple.com"
	"-g ::1 exemple.com"
	"-g :: exemple.com"
	"-g fe80::1 exemple.com"
	"-g-1 exemple.com"
	"-g--help exemple.com"
	"--gateway--help exemple.com"
	"--gateway --help exemple.com"

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

# Run executable but keep argv[0] as "traceroute" to mimic typical invocations
run_with_argv0_tr() {
	local exe="$1"; shift
	# keep argv0 as 'traceroute' (some programs inspect argv[0])
	bash -c 'exec -a traceroute "$0" "$@"' "$exe" "$@"
}

total=0
success=0

for test in "${ARGS_LIST[@]}"; do
	total=$((total + 1))
	echo -e "${YELLOW}[$total] ==============================${RESET}"
	printf "${CYAN}Testing arguments:${RESET} '%s'\n" "$test"

	# build ARGS_ARRAY by eval of the test string (to handle quotes/spaces)
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

	# run first exe
	if run_with_argv0_tr "$EXE1" "${ARGS_ARRAY[@]}" >"$STDOUT1" 2>"$STDERR1"; then
		CODE1=0
	else
		CODE1=$?
	fi

	# run second exe
	if run_with_argv0_tr "$EXE2" "${ARGS_ARRAY[@]}" >"$STDOUT2" 2>"$STDERR2"; then
		CODE2=0
	else
		CODE2=$?
	fi

	# diffs
	diff --color=always -u "$STDOUT1" "$STDOUT2" >"$TMP_DIR/diff_stdout.txt" 2>/dev/null || true
	diff --color=always -u "$STDERR1" "$STDERR2" >"$TMP_DIR/diff_stderr.txt" 2>/dev/null || true

	STDOUT_MATCH=$([ ! -s "$TMP_DIR/diff_stdout.txt" ] && echo 1 || echo 0)
	STDERR_MATCH=$([ ! -s "$TMP_DIR/diff_stderr.txt" ] && echo 1 || echo 0)
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
