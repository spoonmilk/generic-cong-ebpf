.PHONY: all check ebpf rust clean test test-basic test-quick test-full install

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

test-basic: all
	@echo "Running basic registration test..."
	sudo ./scripts/test_ebpf_cubic.sh basic

test-quick: all
	@echo "Running quick iperf test..."
	sudo ./scripts/test_ebpf_cubic.sh quick

test-full: all
	@echo "Running full iperf test..."
	sudo ./scripts/test_ebpf_cubic.sh full

test: test-basic

run: all
	sudo ./target/release/ebpf-ccp-cubic
