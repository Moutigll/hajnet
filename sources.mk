SRC_DIR	= src
BONUS_DIR = bonus_src
BUILD_DIR = build

SRC		= $(SRC_DIR)/main.c

BONUS_SRC = 

OBJ		= $(addprefix $(BUILD_DIR)/, $(notdir $(SRC:.c=.o)))
BONUS_OBJ	= $(addprefix $(BUILD_DIR)/, $(notdir $(SRC:.c=.o) $(BONUS_SRC:.c=.o)))
