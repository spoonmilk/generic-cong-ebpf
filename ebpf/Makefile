CLANG ?= clang
BPFTOOL ?= bpftool
ARCH := $(shell uname -m | sed 's/x86_64/x86/')

.PHONY: all clean vmlinux

all: vmlinux .output/datapath.bpf.o

vmlinux.h:
	@if [ ! -f /sys/kernel/btf/vmlinux ]; then \
		echo "ERROR: /sys/kernel/btf/vmlinux not found"; \
		exit 1; \
	fi
	@echo "Generating vmlinux.h..."
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

vmlinux: vmlinux.h

.output/datapath.bpf.o: datapath.bpf.c vmlinux.h common.h
	@mkdir -p .output
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		-c datapath.bpf.c -o .output/datapath.bpf.o
	@echo "eBPF object compiled: .output/datapath.bpf.o"

clean:
	rm -rf .output vmlinux.h

regen-vmlinux:
	rm -f vmlinux.h
	$(MAKE) vmlinux.h
