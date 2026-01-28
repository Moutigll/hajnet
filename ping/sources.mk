include ../common/sources.mk

SRC_DIR		= src
BUILD_DIR	= build
HAJ_DIR		= src

COMMON_DIR		= ../common
COMMON_BUILD	= $(COMMON_DIR)/build

# Sources
SRC			= $(SRC_DIR)/main.c \
			  $(SRC_DIR)/parser.c \
			  $(SRC_DIR)/utils.c \
			  $(SRC_DIR)/usage.c

HAJ_SRC		= 

# Objects
OBJ			= $(addprefix $(BUILD_DIR)/, $(notdir $(SRC:.c=.o)))
HAJ_OBJ		= $(addprefix $(BUILD_DIR)/haj/, $(notdir $(SRC:.c=.o)))
