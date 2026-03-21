# Project variables
BINARY_NAME=bpfcat
CLANG ?= clang
STRIP ?= llvm-strip
ARCH ?= $(shell uname -m)


# Try to find the architecture-specific include directory (Debian/Ubuntu style)
DEBIAN_INCLUDE = /usr/include/$(ARCH)-linux-gnu
# Try to find the generic arch directory (RedHat/Fedora style)
FEDORA_INCLUDE = /usr/include/asm

# Automatically determine CFLAGS based on existing paths
CFLAGS = -Ibpf
ifneq ($(wildcard $(DEBIAN_INCLUDE)/asm/types.h),)
    CFLAGS += -I$(DEBIAN_INCLUDE)
endif

# Default target
.PHONY: all
all: build

# Help target to guide users on different environments
.PHONY: help
help:
	@echo "bpfcat Build System"
	@echo ""
	@echo "Usage:"
	@echo "  make            - Build the bpfcat binary (default)"
	@echo "  make generate   - Only generate eBPF Go bindings"
	@echo "  make test       - Run integration tests (requires sudo)"
	@echo "  make clean      - Remove all generated files and binaries"
	@echo ""
	@echo "Cross-Distribution Overrides:"
	@echo "  If your system headers are in a non-standard location, override CFLAGS:"
	@echo "  Example: make CFLAGS=\"-Ibpf -I/custom/include/path\""
	@echo ""
	@echo "Toolchain Overrides:"
	@echo "  CLANG=clang-15 STRIP=llvm-strip-15 make"

# Generate eBPF Go bindings
.PHONY: generate
generate: bpf/bpfcat.c bpf/bpf_helpers.h
	@echo "Generating eBPF Go bindings for $(ARCH)..."
	@echo "Using CFLAGS: $(CFLAGS)"
	GOPACKAGE=main go run github.com/cilium/ebpf/cmd/bpf2go \
		-cc $(CLANG) \
		-strip $(STRIP) \
		-cflags "$(CFLAGS)" \
		bpfcat bpf/bpfcat.c

# Build the Go binary
.PHONY: build
build: generate
	@echo "Building $(BINARY_NAME)..."
	go build -o $(BINARY_NAME) .

# Run integration tests (requires sudo)
.PHONY: test
test: build
	@echo "Running tests with sudo..."
	sudo go test -v .

# Clean generated files and binary
.PHONY: clean
clean:
	@echo "Cleaning up..."
	rm -f $(BINARY_NAME)
	rm -f bpfcat_bpfeb.go bpfcat_bpfeb.o
	rm -f bpfcat_bpfel.go bpfcat_bpfel.o
	rm -f target_output bpfcat_log *.test
