NAME	= ft_ping
BONUS_NAME = hajping

CC		= gcc
CFLAGS	= -Wall -Wextra -Werror
INCLUDES = -I includes

include sources.mk

all: $(NAME)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.o: src/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(NAME): $(OBJ)
	$(CC) $(CFLAGS) $(INCLUDES) -o $(NAME) $(OBJ)

bonus: $(BONUS_NAME)

$(BUILD_DIR)/%.o: bonus_src/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(BONUS_NAME): $(BONUS_OBJ)
	$(CC) $(CFLAGS) $(INCLUDES) -o $(BONUS_NAME) $(BONUS_OBJ)

clean:
	rm -rf $(BUILD_DIR)

fclean: clean
	rm -f $(NAME) $(BONUS_NAME)

re: fclean all

.PHONY: all clean fclean re bonus
