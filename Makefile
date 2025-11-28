.PHONY: all check ebpf rust clean test test-basic test-quick test-full install cleanup

all: check ebpf rust

ebpf:
	@echo "Building eBPF datapath..."
	$(MAKE) -C ebpf

rust: ebpf
	@echo "Building Rust components..."
	cargo build --release

clean:
	$(MAKE) -C ebpf clean
	cargo clean

cleanup:
	@echo "Cleaning up ebpf_cubic registration..."
	sudo ./scripts/cleanup_ebpf_cubic.sh

test-basic: cleanup all
	@echo "Running basic registration test..."
	sudo ./scripts/test_ebpf_cubic.sh basic

test-quick: cleanup all
	@echo "Running quick iperf test..."
	sudo ./scripts/test_ebpf_cubic.sh quick

test-full: cleanup all
	@echo "Running full iperf test..."
	sudo ./scripts/test_ebpf_cubic.sh full

test: test-basic

run: all
	sudo ./target/release/ebpf-ccp-cubic
