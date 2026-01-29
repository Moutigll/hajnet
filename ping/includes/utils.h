#ifndef HAJPING_UTILS
# define HAJPING_UTILS

#include <stddef.h>

#include "../../common/includes/utils.h"
#include "socket.h"

/**
 * @brief Convert a numeric option value with validation
 * @param optArg - option argument string
 * @param maxVal - maximum allowed value (0 for no limit)
 * @param allowZero - whether zero is allowed
 * @param progName - program name (for error messages)
 * @return converted numeric value
 */
size_t convertNumberOption(const char *optArg, size_t maxVal, int allowZero, const char *progName);

/**
 * @brief Decode a hex pattern string into bytes
 * @param progName - program name (for error messages)
 * @param text - input hex string
 * @param maxLen - maximum length of the pattern
 * @param patternLen - output length of the decoded pattern
 * @param patternData - output buffer for decoded bytes
 */
void decodePattern(
	const char		*progName,
	const char		*text,
	int				maxLen,
	int				*patternLen,
	unsigned char	*patternData);

/**
 * @brief Check if the current user is root
 * @return 1 if root, 0 otherwise
 */
tBool isRoot(void);

/**
 * @brief Convert protocol number to string
 * @param proto - protocol number
 * @return string representation of the protocol
 */
const char *protoToStr(int proto);

/**
 * @brief Convert socket type to string
 * @param type - ping socket type
 * @return string representation of the socket type
 */
const char *sockTypeToStr(tPingSocketType type);

#endif
