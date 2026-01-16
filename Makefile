PREFIX ?= /usr/local
LIBDIR ?= $(PREFIX)/lib
INCLUDEDIR ?= $(PREFIX)/include

ROOT_DIR := $(shell pwd)
BUILD_DIR := $(ROOT_DIR)/target/ffi
HEADER_DIR := $(BUILD_DIR)/include

.PHONY: all build install uninstall clean

all: build

build:
	@./scripts/build-ffi.sh

install: build
	@install -d $(LIBDIR)
	@install -d $(INCLUDEDIR)
	@install -m 644 $(BUILD_DIR)/libstedy.a $(LIBDIR)/
	@install -m 644 $(HEADER_DIR)/stedy.h $(INCLUDEDIR)/

uninstall:
	@rm -f $(LIBDIR)/libstedy.a
	@rm -f $(INCLUDEDIR)/stedy.h

clean:
	@cargo clean --quiet
