CC := gcc
CFLAGS := -Wall -g -Os

SHDIR := ../common
BUILDDIR := ./build
LDFLAGS = -lgmp
OBJS = $(BUILDDIR)/ftclient.o $(SHDIR)/common.o


all: $(BUILDDIR) ftclient

$(BUILDDIR):
	@mkdir -p $(BUILDDIR)
CRYPTO_UTILS_PATH = ../../crypto_utils/
CRYPTO_UTILS_LIBS = $(CRYPTO_UTILS_PATH)/build/ecdh/ecdh.o \
										$(CRYPTO_UTILS_PATH)/build/ecdh/ecdh_protocol.o \
										$(CRYPTO_UTILS_PATH)/build/ecdsa/ecdsa.o \
										$(CRYPTO_UTILS_PATH)/build/sha256/sha256.o

INCLUDE_DIRS = -I$(CRYPTO_UTILS_PATH)/include

ftclient: $(OBJS)
	@$(CC) $(INCLUDE_DIRS) -o $(BUILDDIR)/ftclient $(CFLAGS) $(OBJS) $(CRYPTO_UTILS_LIBS) $(LDFLAGS) -g

$(BUILDDIR)/%.o: %.c
	@$(CC) $(INCLUDE_DIRS) -c $(CFLAGS) $< -o $@ -g

.PHONY: clean
clean:
	@rm -f $(BUILDDIR)/*.o $(BUILDDIR)/ftclient
	@rm -f ../common/*.o
	@echo Done cleaning
