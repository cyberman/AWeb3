# vbcc reference toolchain profile for C89 builds

CC := vc
LD := vlink

CPPFLAGS := $(CPPFLAGS_COMMON)
CFLAGS := $(CFLAGS_COMMON) $(INCLUDES_COMMON)
LDFLAGS := $(LDFLAGS_COMMON)

COMPILE.c = $(CC) -c $(CPPFLAGS) $(CFLAGS)
LINK.bin = $(LD) $(LDFLAGS)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(GEN_DIR):
	mkdir -p $(GEN_DIR)

$(CFG_LOCALE_C) $(CFG_LOCALE_H): $(CFG_CD) $(FLEXCAT_C_SD) $(FLEXCAT_H_SD) | $(GEN_DIR)
	$(LOCALE_COMPILER) $(CFG_CD) \
		$(CFG_LOCALE_C)=$(FLEXCAT_C_SD) \
		$(CFG_LOCALE_H)=$(FLEXCAT_H_SD)

$(CFG_CATCOMP_OBJ): $(CFG_LOCALE_C) $(CFG_LOCALE_H) | $(OBJ_DIR)
	$(COMPILE.c) $(CFG_LOCALE_C) -o=$@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(COMPILE.c) $< -o=$@
