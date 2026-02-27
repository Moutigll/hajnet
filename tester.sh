#!/usr/bin/env bash
# Exhaustive CLI comparator with external args file
# Usage: ./tester.sh <args_file> <exe1> <exe2>

set -u
IFS=$'\n\t'

if [ $# -ne 3 ]; then
	printf '\033[31mUsage: %s <args_file> <executable1> <executable2>\033[0m\n' "$0"
	printf '\033[33m  args_file: file containing one test case per line (arguments as they would be typed)\033[0m\n'
	exit 1
fi

ARGS_FILE="$1"
EXE1="$2"
EXE2="$3"

# colours
GREEN="\033[32m"; RED="\033[31m"; YELLOW="\033[33m"; CYAN="\033[36m"; RESET="\033[0m"

# Check if args file exists
if [ ! -f "$ARGS_FILE" ]; then
	echo -e "${RED}Error: Args file '$ARGS_FILE' not found${RESET}"
	exit 1
fi

# Check if executables exist and are executable
if [ ! -x "$EXE1" ]; then
	echo -e "${RED}Error: '$EXE1' is not executable or not found${RESET}"
	exit 1
fi
if [ ! -x "$EXE2" ]; then
	echo -e "${RED}Error: '$EXE2' is not executable or not found${RESET}"
	exit 1
fi

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

echo -e "${CYAN}Comparing ${EXE1} and ${EXE2} using test cases from ${ARGS_FILE}...${RESET}"
echo -e "${YELLOW}Each line in the file is treated as a separate test case${RESET}"
echo ""

# Read test cases from file (skip empty lines and comments starting with #)
mapfile -t ARGS_LIST < <(grep -v '^\s*$\|^\s*#' "$ARGS_FILE")

quote_cmd() {
	local -n arr=$1
	local i out=""
	for i in "${arr[@]}"; do
		out+=" $(printf '%q' "$i")"
	done
	printf '%s' "${out# }"
}

run_with_argv0_tr() {
	local exe="$1"; shift
	bash -c 'exec -a someProgramme:3 "$0" "$@"' "$exe" "$@"
}

total=0
success=0
test_num=0

for test in "${ARGS_LIST[@]}"; do
	# Trim leading/trailing whitespace
	test=$(echo "$test" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
	
	# Skip if empty after trimming
	if [ -z "$test" ]; then
		continue
	fi
	
	test_num=$((test_num + 1))
	total=$((total + 1))
	echo -e "${YELLOW}[${test_num}] ==============================${RESET}"
	printf "${CYAN}Testing arguments:${RESET} '%s'\n" "$test"

	# Build ARGS_ARRAY by eval of the test string (to handle quotes/spaces)
	ARGS_ARRAY=()
	if ! eval "ARGS_ARRAY=( $test )" 2>/dev/null; then
		echo -e "${RED}⚠ Invalid test string (eval failed), skipping: $test${RESET}"
		continue
	fi

	CMDLINE=$(quote_cmd ARGS_ARRAY)
	printf "Command args: %s\n" "$CMDLINE"

	STDOUT1="$TMP_DIR/stdout1_${test_num}.txt"
	STDERR1="$TMP_DIR/stderr1_${test_num}.txt"
	STDOUT2="$TMP_DIR/stdout2_${test_num}.txt"
	STDERR2="$TMP_DIR/stderr2_${test_num}.txt"

	# Run first exe
	if run_with_argv0_tr "$EXE1" "${ARGS_ARRAY[@]}" >"$STDOUT1" 2>"$STDERR1"; then
		CODE1=0
	else
		CODE1=$?
	fi

	# Run second exe
	if run_with_argv0_tr "$EXE2" "${ARGS_ARRAY[@]}" >"$STDOUT2" 2>"$STDERR2"; then
		CODE2=0
	else
		CODE2=$?
	fi

	# Diffs
	diff --color=always -u "$STDOUT1" "$STDOUT2" >"$TMP_DIR/diff_stdout_${test_num}.txt" 2>/dev/null || true
	diff --color=always -u "$STDERR1" "$STDERR2" >"$TMP_DIR/diff_stderr_${test_num}.txt" 2>/dev/null || true

	STDOUT_MATCH=$([ ! -s "$TMP_DIR/diff_stdout_${test_num}.txt" ] && echo 1 || echo 0)
	STDERR_MATCH=$([ ! -s "$TMP_DIR/diff_stderr_${test_num}.txt" ] && echo 1 || echo 0)
	CODE_MATCH=$([ "$CODE1" -eq "$CODE2" ] && echo 1 || echo 0)

	if [ "$STDOUT_MATCH" -eq 1 ] && [ "$STDERR_MATCH" -eq 1 ] && [ "$CODE_MATCH" -eq 1 ]; then
		echo -e "${GREEN}✅ All match (exit code: ${CODE1})${RESET}"
		success=$((success + 1))
	else
		echo -e "${RED}❌ Differences detected:${RESET}"
		if [ "$STDOUT_MATCH" -eq 0 ]; then
			echo -e "${YELLOW}--- Stdout diff ---${RESET}"
			cat "$TMP_DIR/diff_stdout_${test_num}.txt"
			echo -e "${YELLOW}------------------${RESET}"
		else
			echo -e "${GREEN}Stdout identical${RESET}"
		fi
		if [ "$STDERR_MATCH" -eq 0 ]; then
			echo -e "${YELLOW}--- Stderr diff ---${RESET}"
			cat "$TMP_DIR/diff_stderr_${test_num}.txt"
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
	echo ""
done

echo -e "${CYAN}==============================${RESET}"
echo -e "${CYAN}Test summary:${RESET} ${success}/${total} tests passed."

if [ $success -eq $total ]; then
	echo -e "${GREEN}All tests passed! 🎉${RESET}"
	exit 0
else
	echo -e "${RED}Some tests failed.${RESET}"
	exit 1
fi
