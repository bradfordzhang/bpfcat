# Project variables
BINARY_NAME=bpfcat
export GOEXPERIMENT=newinliner,runtimefreegc,simd
export CGO_ENABLED ?= 0
CLANG ?= clang
STRIP ?= llvm-strip
ARCH ?= $(shell uname -m)
TARGET ?= bpfel,bpfeb
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)
GOARM ?=
OUTPUT ?= $(BINARY_NAME)
DIST_DIR ?= dist
PLATFORMS ?= linux/amd64 linux/arm64 linux/arm/v7


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
	@echo "  make cross      - Cross-compile binaries for multiple platforms"
	@echo "  make test       - Run integration tests (requires sudo)"
	@echo "  make clean      - Remove all generated files and binaries"
	@echo ""
	@echo "Cross-Distribution Overrides:"
	@echo "  If your system headers are in a non-standard location, override CFLAGS:"
	@echo "  Example: make CFLAGS=\"-Ibpf -I/custom/include/path\""
	@echo ""
	@echo "Toolchain Overrides:"
	@echo "  CLANG=clang-15 STRIP=llvm-strip-15 make"
	@echo ""
	@echo "Cross-Compile Overrides:"
	@echo "  make build GOOS=linux GOARCH=arm64 OUTPUT=bpfcat-linux-arm64"
	@echo "  make build GOOS=linux GOARCH=arm GOARM=7 OUTPUT=bpfcat-linux-armv7"
	@echo "  make cross PLATFORMS="\"linux/amd64 linux/arm64 linux/arm/v7\"""

# Generate eBPF Go bindings
.PHONY: generate
generate: bpf/bpfcat.c bpf/bpf_helpers.h
	@echo "Generating eBPF Go bindings for $(ARCH) (target: $(TARGET))..."
	@echo "Using CFLAGS: $(CFLAGS)"
	@unset GOOS GOARCH GOARM && \
	GOPACKAGE=main go run github.com/cilium/ebpf/cmd/bpf2go \
		-cc $(CLANG) \
		-strip $(STRIP) \
		-target $(TARGET) \
		-cflags "$(CFLAGS)" \
		bpfcat bpf/bpfcat.c

# Build the Go binary
.PHONY: build
build: generate
	@echo "Building $(OUTPUT) for $(GOOS)/$(GOARCH)$(if $(GOARM), (GOARM=$(GOARM)))..."
	GOOS=$(GOOS) GOARCH=$(GOARCH) GOARM=$(GOARM) go build -o $(OUTPUT) .

# Build binaries for multiple target platforms.
.PHONY: cross
cross: generate
	@echo "Cross-compiling to $(DIST_DIR): $(PLATFORMS)"
	@mkdir -p $(DIST_DIR)
	@set -e; \
	for platform in $(PLATFORMS); do \
		os=$${platform%%/*}; \
		rest=$${platform#*/}; \
		arch=$${rest%%/*}; \
		variant=$${rest#*/}; \
		output="$(DIST_DIR)/$(BINARY_NAME)-$$os-$$arch"; \
		if [ "$$variant" != "$$rest" ]; then \
			output="$$output-$$variant"; \
		fi; \
		echo "Building $$output"; \
		if [ "$$arch" = "arm" ] && [ "$$variant" != "$$rest" ]; then \
			GOOS=$$os GOARCH=$$arch GOARM=$${variant#v} go build -o "$$output" .; \
		else \
			GOOS=$$os GOARCH=$$arch go build -o "$$output" .; \
		fi; \
	done

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
	rm -f $(BINARY_NAME)-*
	rm -rf $(DIST_DIR)
	rm -f bpfcat_bpfeb.go bpfcat_bpfeb.o
	rm -f bpfcat_bpfel.go bpfcat_bpfel.o
	rm -f target_output bpfcat_log *.test
