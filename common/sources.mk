COMMON_BUILD = build
COMMON_DIR   = src

COMMON_SRC = $(COMMON_DIR)/getopt.c \
			 $(COMMON_DIR)/ip/print4.c \
			 $(COMMON_DIR)/icmp/print.c \
			 $(COMMON_DIR)/icmp/utils.c \

COMMON_OBJ = $(COMMON_SRC:$(COMMON_DIR)/%.c=$(COMMON_BUILD)/%.o)
