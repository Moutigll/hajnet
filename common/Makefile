CC      = gcc
CFLAGS  = -Wall -Wextra -Werror --pedantic -fsanitize=address -fno-omit-frame-pointer
INCLUDES= -I includes

include ../colors.mk
include sources.mk

.PHONY: all clean fclean re

all: $(COMMON_OBJ)

$(COMMON_BUILD):
	@printf "$(YELLOW)Common: Creating build directory...$(RESET)\n"
	mkdir -p $(COMMON_BUILD)

$(COMMON_BUILD)/%.o: $(COMMON_DIR)/%.c | $(COMMON_BUILD)
	@mkdir -p $(dir $@)
	@total=$(words $(COMMON_OBJ)); \
	current=$$(echo $(COMMON_OBJ) | tr ' ' '\n' | grep -n "$@" | cut -d: -f1); \
	printf "$(YELLOW)[$$current/$$total] Compiling $<...$(RESET)\r"; \
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@; \
	printf "$(GREEN)[$$current/$$total] Compiled $<        $(RESET)\n"

clean:
	@printf "$(YELLOW)Common: Cleaning build directory...$(RESET)\n"
	rm -rf $(COMMON_BUILD)

fclean: clean

re: fclean all