# Makefile for compiling BPF programs for AF_XDP
# Assumes Linux kernel 6.18+ with BPF support

CLANG ?= clang
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
ARCH_TRIPLET := $(shell uname -m | sed 's/x86_64/x86_64-linux-gnu/' | sed 's/aarch64/aarch64-linux-gnu/')
KERNEL_VERSION := $(shell uname -r)
KERNEL_SRC := /lib/modules/$(KERNEL_VERSION)/build

# BPF source files
BPF_SRC := xdp_kern.c
BPF_OBJ := $(BPF_SRC:.c=.o)

# Clang flags for BPF compilation
CLANG_FLAGS := \
	-target bpf \
	-O2 -g \
	-I$(KERNEL_SRC)/arch/$(ARCH)/include \
	-I$(KERNEL_SRC)/arch/$(ARCH)/include/uapi \
	-I/usr/include/$(ARCH_TRIPLET)

.PHONY: all clean

all: $(BPF_OBJ)

$(BPF_OBJ): $(BPF_SRC)
	@echo "  CLANG  $@"
	@$(CLANG) $(CLANG_FLAGS) -c $< -o $@

clean:
	rm -f $(BPF_OBJ)

# Verify the BPF object can be loaded
verify: $(BPF_OBJ)
	@echo "Verifying BPF object..."
	@readelf -h $< > /dev/null 2>&1 && echo "✓ Valid ELF object" || echo "✗ Invalid ELF object"
	@llvm-objdump -h $< > /dev/null 2>&1 && echo "✓ Valid BPF object" || echo "✗ Invalid BPF object"

help:
	@echo "BPF Compilation Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all     - Compile BPF programs (default)"
	@echo "  clean   - Remove compiled objects"
	@echo "  verify  - Verify compiled BPF object"
	@echo "  help    - Show this help message"
	@echo ""
	@echo "Variables:"
	@echo "  MAX_SOCKS - Maximum number of sockets (default: 64)"
	@echo "  CLANG     - Clang compiler path (default: clang)"
	@echo ""
	@echo "Example:"
	@echo "  make MAX_SOCKS=128"
