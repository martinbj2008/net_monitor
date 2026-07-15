# bpf/Makefile — build probe_xdp.bpf.o on the hub.
#
# Usage on hub:
#   cd ~/git/net_monitor/bpf && make
#
# Outputs: probe_xdp.bpf.o (BPF ELF), vmlinux.h (generated from BTF)
#
# Requirements (all present on bangkok per xdp_env_check.sh):
#   clang, llvm, libbpf-dev, bpftool, /sys/kernel/btf/vmlinux

CLANG    ?= clang
BPFTOOL  ?= bpftool
ARCH     := $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/')

# Ubuntu multi-arch header dir (fixes: fatal error: 'asm/types.h' file not found)
ARCH_INC := $(firstword $(wildcard /usr/include/x86_64-linux-gnu \
                                    /usr/include/aarch64-linux-gnu))

CFLAGS := -O2 -g -Wall \
          -target bpf \
          -D__TARGET_ARCH_$(ARCH) \
          $(if $(ARCH_INC),-I$(ARCH_INC),) \
          -I.

OBJ := probe_xdp.bpf.o
SRC := probe_xdp.bpf.c
HDR := probe_xdp.h vmlinux.h

.PHONY: all clean vmlinux

all: $(OBJ)

# Generate vmlinux.h from the running kernel's BTF once per hub.
vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(OBJ): $(SRC) $(HDR)
	$(CLANG) $(CFLAGS) -c $(SRC) -o $@
	@echo "[ok] built $@"
	@file $@

clean:
	rm -f $(OBJ) vmlinux.h
