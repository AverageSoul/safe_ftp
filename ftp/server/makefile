CC := gcc
CFLAGS := -Wall -g -Os

SHDIR := ../common
BUILDDIR := ./build
LDFLAGS = -lgmp
OBJS = $(BUILDDIR)/ftserve.o $(SHDIR)/common.o


all: $(BUILDDIR) ftserve

$(BUILDDIR):
	@mkdir -p $(BUILDDIR)
CRYPTO_UTILS_PATH = ../../crypto_utils/
CRYPTO_UTILS_LIBS = $(CRYPTO_UTILS_PATH)/build/ecdh/ecdh.o \
										$(CRYPTO_UTILS_PATH)/build/ecdh/ecdh_protocol.o \
										$(CRYPTO_UTILS_PATH)/build/ecdsa/ecdsa.o \
										$(CRYPTO_UTILS_PATH)/build/sha256/sha256.o \
										$(CRYPTO_UTILS_PATH)/build/aes/aes.o \
										$(CRYPTO_UTILS_PATH)/build/aes/aes_cfb.o \

INCLUDE_DIRS = -I$(CRYPTO_UTILS_PATH)/include

ftserve: $(OBJS)
	@$(CC) $(INCLUDE_DIRS) -o $(BUILDDIR)/ftserve $(CFLAGS) $(OBJS) $(CRYPTO_UTILS_LIBS) $(LDFLAGS) 

$(BUILDDIR)/%.o: %.c
	@$(CC) $(INCLUDE_DIRS) -c $(CFLAGS) $< -o $@

.PHONY: clean
clean:
	@rm -f $(BUILDDIR)/*.o $(BUILDDIR)/ftserve
	@rm -f ../common/*.o
	@echo Done cleaning
