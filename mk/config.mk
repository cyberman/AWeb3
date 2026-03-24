# Global build configuration for compiler-agnostic C89 builds

PROJECT_ROOT := .
SRC_DIR := Source/AWebAPL
BUILD_DIR := build/c89
OBJ_DIR := $(BUILD_DIR)/obj
BIN_DIR := $(BUILD_DIR)/bin
GEN_DIR := $(BUILD_DIR)/gen

AMIGA_ROOT ?= /opt/amiga
AMIGA_NDK ?= $(AMIGA_ROOT)/ndk32
AMIGA_VBCC ?= $(AMIGA_ROOT)/vbcc

NDK_INCLUDE_H := $(AMIGA_NDK)/include_H
NDK_INCLUDE_I := $(AMIGA_NDK)/include_I
NDK_LIB := $(AMIGA_NDK)/lib
NDK_C := $(AMIGA_NDK)/C

VBCC_BIN := $(AMIGA_VBCC)/bin
VBCC_CONFIG := $(AMIGA_VBCC)/config

# Host locale compiler - start
FLEXCAT ?= $(AMIGA_ROOT)/bin/Linux-i386/flexcat
LOCALE_COMPILER ?= $(FLEXCAT)

FLEXCAT_SD_DIR ?= 3rdparty/flexcat/sd
FLEXCAT_C_SD ?= $(FLEXCAT_SD_DIR)/C_c.sd
FLEXCAT_H_SD ?= $(FLEXCAT_SD_DIR)/C_h.sd

ifeq ($(wildcard $(LOCALE_COMPILER)),)
$(error Locale compiler not found: $(LOCALE_COMPILER))
endif

ifeq ($(wildcard $(FLEXCAT_C_SD)),)
$(error FlexCat source descriptor not found: $(FLEXCAT_C_SD))
endif

ifeq ($(wildcard $(FLEXCAT_H_SD)),)
$(error FlexCat source descriptor not found: $(FLEXCAT_H_SD))
endif
# Host locale compiler - end

CPPFLAGS_COMMON :=
CFLAGS_COMMON :=
LDFLAGS_COMMON :=

INCLUDES_COMMON := \
	-I$(SRC_DIR) \
	-I$(GEN_DIR) \
	-I$(NDK_INCLUDE_H) \
	-I$(NDK_INCLUDE_I)

CFG_SRC_NAMES := \
	cfgmainstr \
	awebcfg \
	cfgnw \
	cfgpr \
	cfgbr \
	cfgui \
	memory \
	defprefs

CFG_SRCS := $(addprefix $(SRC_DIR)/,$(addsuffix .c,$(CFG_SRC_NAMES)))
CFG_OBJ_FILES := $(addprefix $(OBJ_DIR)/,$(addsuffix .o,$(CFG_SRC_NAMES)))

CFG_CD := $(SRC_DIR)/awebcfg.cd
CFG_LOCALE_C := $(GEN_DIR)/awebcfg_cat.c
CFG_LOCALE_H := $(GEN_DIR)/awebcfg_cat.h
CFG_CATCOMP_OBJ := $(OBJ_DIR)/cfglocale.o

CFG_STAMP := $(OBJ_DIR)/awebcfg.stamp
