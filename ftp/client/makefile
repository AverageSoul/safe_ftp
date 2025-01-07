CC := gcc
CFLAGS := -Wall -g -Os

SHDIR := ../common
BUILDDIR := build

OBJS = $(BUILDDIR)/ftclient.o $(SHDIR)/common.o

all: $(BUILDDIR) ftclient

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

ftclient: $(OBJS)
	@$(CC) -o $(BUILDDIR)/ftclient $(CFLAGS) $(OBJS)

$(BUILDDIR)/%.o: %.c
	@$(CC) -c $(CFLAGS) $< -o $@

.PHONY: clean
clean:
	@rm -rf $(BUILDDIR)
	@echo Done cleaning

