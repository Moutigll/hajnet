.PHONY: all ping clean fclean re

include colors.mk

all: common ping

common:
	@echo "Building common..."
	$(MAKE) -C common

ping:
	@echo "Building ping..."
	$(MAKE) -C ping

clean:
	@printf "$(YELLOW)Cleaning all...$(RESET)\n"
	$(MAKE) -C common clean
	$(MAKE) -C ping clean

fclean:
	@printf "$(YELLOW)Removing all binaries and object files...$(RESET)\n"
	$(MAKE) -C common fclean
	$(MAKE) -C ping fclean

re: fclean all
