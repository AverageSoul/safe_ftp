CC := gcc
CFLAGS := -Wall -g -Os

SHDIR := ../common
BUILDDIR := ./build

OBJS = $(BUILDDIR)/ftserve.o $(SHDIR)/common.o

all: $(BUILDDIR) ftserve

$(BUILDDIR):
	@mkdir -p $(BUILDDIR)

ftserve: $(OBJS)
	@$(CC) -o $(BUILDDIR)/ftserve $(CFLAGS) $(OBJS)

$(BUILDDIR)/%.o: %.c
	@$(CC) -c $(CFLAGS) $< -o $@

.PHONY: clean
clean:
	@rm -f $(BUILDDIR)/*.o $(BUILDDIR)/ftserve
	@rm -f ../common/*.o
	@echo Done cleaning
