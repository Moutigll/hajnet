#ifndef HAJPING_USAGE_H
#define HAJPING_USAGE_H

#include "ft_ping.h"

void printUsage(char *progName);
void printFullHelp(char *progName);

/**
 * @brief Print an error message for an unrecognized option
 * @param progName - program name
 * @param badOpt - invalid option character
 * @param badOptStr - invalid option string (for long options)
 */
void exitBadOption(const char *progName, char badOpt, const char *badOptStr);

/**
 * @brief Print an error message for a missing argument
 * @param progName - program name
 * @param opt - option character
 * @param optStr - option string (for long options)
 */
void exitMissingArg(const char *progName, char opt, const char *optStr);

/**
 * @brief Print an error message for an ambiguous option
 * @param progName - program name
 * @param badOpt - ambiguous option string
 * @param optA - first possible option string
 * @param optB - second possible option string
 */
void exitAmbiguousOption(const char *progName, const char *badOpt, const char *optA, const char *optB);

/**
 * @brief Print an error message for missing host operand
 * @param progName - program name
 */
void printMissingHost(const char *progName);

/**
 * @brief Print a summary of ping statistics
 * @param ctx - ping context containing statistics
 */
void printPingSummary(tPingContext *ctx);

void printIcmpHeader(const unsigned char *buf, int len, int isIPv4);

#endif /* HAJPING_USAGE_H */