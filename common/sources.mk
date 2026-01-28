COMMON_BUILD = build
COMMON_DIR   = src

COMMON_SRC = $(COMMON_DIR)/getopt.c 

COMMON_OBJ = $(addprefix $(COMMON_BUILD)/, $(notdir $(COMMON_SRC:.c=.o)))
