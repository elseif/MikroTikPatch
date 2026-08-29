TOOLCHAIN_DIR ?= $(HOME)/musl-toolchains/i686-linux-musl-cross
CROSS_COMPILE ?= $(TOOLCHAIN_DIR)/bin/i686-linux-musl-

CC      = $(CROSS_COMPILE)gcc
STRIP   = $(CROSS_COMPILE)strip

TARGET  = npkextract
SRC     = npkextract.c
OBJ     = $(SRC:.c=.o)

CFLAGS  ?= -O2 -Wall -Wextra -D_GNU_SOURCE
CFLAGS  += -static -m32
LDFLAGS += -static -s


.PHONY: all clean info

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^
	@$(STRIP) --strip-all $(TARGET) 2>/dev/null || true
	@echo "=========================================================="
	@echo " Successfully built static binary: $(TARGET)"
	@ls -lh $(TARGET)
	@file $(TARGET) 2>/dev/null || true
	@echo "=========================================================="

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

info:
	@echo "Compiler: $(CC)"
	@echo "Strip:    $(STRIP)"
	@echo "CFLAGS:   $(CFLAGS)"
	@echo "LDFLAGS:  $(LDFLAGS)"

clean:
	rm -f $(TARGET) $(OBJ)
