NAME		= ft_ping
HAJ_NAME	= hajping

CC			= gcc
CFLAGS		= -Wall -Wextra -Werror --pedantic -g -fsanitize=address -fno-omit-frame-pointer
INCLUDES	= -I includes -I ../common/includes

include ../colors.mk
include sources.mk

.PHONY: all clean fclean re haj

all: $(COMMON_OBJ) $(OBJ) $(NAME)

$(COMMON_OBJ):
	@printf "$(CYAN)ping: Building common objects...$(RESET)\n"
	$(MAKE) -C ../common

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	@total=$(words $(OBJ)); \
	current=$$(echo $(OBJ) | tr ' ' '\n' | grep -n "$@" | cut -d: -f1); \
	printf "$(YELLOW)[$$current/$$total] Compiling $<...$(RESET)\r"; \
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@; \
	printf "$(GREEN)[$$current/$$total] Compiled $<        $(RESET)\n"

$(NAME): $(OBJ) $(COMMON_OBJ)
	@printf "$(CYAN)Linking $(NAME)...$(RESET)\n"
	$(CC) $(CFLAGS) $(INCLUDES) -o $(NAME) $(OBJ) $(COMMON_OBJ)



HAJ_BUILD_DIR := $(BUILD_DIR)/haj

haj: $(COMMON_OBJ) $(HAJ_OBJ) $(HAJ_NAME)

$(HAJ_BUILD_DIR):
	@mkdir -p $(HAJ_BUILD_DIR)

$(HAJ_BUILD_DIR)/%.o: $(HAJ_DIR)/%.c | $(HAJ_BUILD_DIR)
	@total=$(words $(HAJ_OBJ)); \
	current=$$(echo $(HAJ_OBJ) | tr ' ' '\n' | grep -n "$@" | cut -d: -f1); \
	printf "$(YELLOW)[$$current/$$total] Compiling $< with -DHAJ...$(RESET)\r"; \
	$(CC) $(CFLAGS) -DHAJ $(INCLUDES) -c $< -o $@; \
	printf "$(GREEN)[$$current/$$total] Compiled $<        $(RESET)\n"

$(HAJ_NAME): $(COMMON_OBJ) $(HAJ_OBJ)
	@printf "$(CYAN)Linking $(HAJ_NAME)...$(RESET)\n"
	$(CC) $(CFLAGS) $(INCLUDES) -o $(HAJ_NAME) $(HAJ_OBJ) $(COMMON_OBJ)


clean:
	@printf "$(YELLOW)ping: Cleaning build directory...$(RESET)\n"
	rm -rf $(BUILD_DIR)
	$(MAKE) -C ../common clean

fclean: clean
	@printf "$(YELLOW)ping: Removing binaries...$(RESET)\n"
	rm -f $(NAME) $(HAJ_NAME)
	$(MAKE) -C ../common fclean

re: fclean all
