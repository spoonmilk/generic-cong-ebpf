#!/bin/bash

set -e
set -o pipefail

# --- Configuration ---
TEST_HOST="10.0.0.1"
TEST_SERVER="10.0.0.2"
LATENCY="20ms"
BANDWIDTH="10mbit"
LOSS="1%"
TEST_DURATION=10
BPF_BINARY_PATH="./target/release/ebpf-ccp-cubic"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# --- Helper Functions ---

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_dependencies() {
    log_info "Checking dependencies..."

    local missing_deps=()

    for cmd in ip tc iperf3 sysctl; do
        if ! command -v $cmd &> /dev/null; then
            missing_deps+=("$cmd")
        fi
    done

    if [ ${#missing_deps[@]} -ne 0 ]; then
        log_error "Missing required dependencies: ${missing_deps[*]}"
        echo "Install them with:"
        echo "  sudo apt-get install iproute2 iperf3"
        exit 1
    fi

    # Check if running as root or with sudo
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root or with sudo"
        exit 1
    fi

    # Check if BPF binary exists
    if [ ! -f "${BPF_BINARY_PATH}" ]; then
        log_error "BPF binary not found at ${BPF_BINARY_PATH}"
        echo "Run 'make all' or 'cargo build --release' first"
        exit 1
    fi

    # Check for BTF support
    if [ ! -f /sys/kernel/btf/vmlinux ]; then
        log_warn "BTF not available at /sys/kernel/btf/vmlinux"
        log_warn "This may cause issues loading the eBPF program"
    fi

    log_info "All dependencies satisfied"
}

cleanup_network() {
    log_info "Cleaning up network namespaces..."

    # Clean up any existing namespaces
    ip netns del client 2>/dev/null || true
    ip netns del server 2>/dev/null || true

    log_info "Network cleanup complete"
}

cleanup_processes() {
    log_info "Cleaning up processes..."

    # Kill any running iperf3 servers
    pkill -9 iperf3 2>/dev/null || true

    # Kill the BPF daemon if it's running
    if [ ! -z "$BPF_PID" ] && kill -0 $BPF_PID 2>/dev/null; then
        kill $BPF_PID 2>/dev/null || true
        wait $BPF_PID 2>/dev/null || true
    fi

    log_info "Process cleanup complete"
}

cleanup_all() {
    cleanup_processes
    cleanup_network
}

setup_network() {
    log_info "Setting up network namespaces..."

    # Create namespaces
    ip netns add client || { log_error "Failed to create client namespace"; exit 1; }
    ip netns add server || { log_error "Failed to create server namespace"; cleanup_network; exit 1; }

    # Create veth pair
    ip link add veth-client type veth peer name veth-server || {
        log_error "Failed to create veth pair"
        cleanup_network
        exit 1
    }

    # Move interfaces to namespaces
    ip link set veth-client netns client
    ip link set veth-server netns server

    # Configure client namespace
    ip netns exec client ip addr add ${TEST_HOST}/24 dev veth-client
    ip netns exec client ip link set dev veth-client up
    ip netns exec client ip link set dev lo up
    ip netns exec client ip route add default via ${TEST_SERVER}

    # Configure server namespace
    ip netns exec server ip addr add ${TEST_SERVER}/24 dev veth-server
    ip netns exec server ip link set dev veth-server up
    ip netns exec server ip link set dev lo up
    ip netns exec server ip route add default via ${TEST_HOST}

    # Apply network emulation
    ip netns exec server tc qdisc add dev veth-server root netem \
        delay ${LATENCY} \
        loss ${LOSS} \
        rate ${BANDWIDTH}

    # Test connectivity
    if ! ip netns exec client ping -c 1 -W 2 ${TEST_SERVER} &>/dev/null; then
        log_error "Network connectivity test failed"
        cleanup_network
        exit 1
    fi

    log_info "Network setup complete (${LATENCY} latency, ${BANDWIDTH} bandwidth, ${LOSS} loss)"
}

start_bpf_daemon() {
    log_info "Starting eBPF datapath daemon..."

    # Start the daemon in the background
    ${BPF_BINARY_PATH} &
    BPF_PID=$!

    # Wait for it to initialize
    sleep 3

    # Check if it's still running
    if ! kill -0 $BPF_PID 2>/dev/null; then
        log_error "eBPF daemon failed to start or crashed immediately"
        wait $BPF_PID 2>/dev/null || true
        exit 1
    fi

    # Verify the struct_ops is registered
    sleep 1
    if ! sysctl net.ipv4.tcp_available_congestion_control | grep -q ebpf_cubic; then
        log_error "ebpf_cubic not found in available congestion control algorithms"
        kill $BPF_PID 2>/dev/null || true
        exit 1
    fi

    log_info "eBPF daemon started successfully (PID: $BPF_PID)"
}

run_basic_test() {
    log_info "Running registration test..."

    start_bpf_daemon

    echo ""
    log_info "ebpf_cubic is registered and available"
    sysctl net.ipv4.tcp_available_congestion_control
    echo ""

    cleanup_processes
}

run_iperf_test() {
    log_info "Running iperf3 network test..."

    start_bpf_daemon
    setup_network

    # Start iperf3 server in server namespace
    log_info "Starting iperf3 server..."
    ip netns exec server iperf3 -s &
    IPERF_SERVER_PID=$!
    sleep 2

    # Check if server is running
    if ! kill -0 $IPERF_SERVER_PID 2>/dev/null; then
        log_error "iperf3 server failed to start"
        cleanup_all
        exit 1
    fi

    # Run iperf3 client
    log_info "Running iperf3 client for ${TEST_DURATION}s..."
    echo ""

    if ip netns exec client iperf3 -c ${TEST_SERVER} -t ${TEST_DURATION}; then
        echo ""
        log_info "✓ Test completed successfully"
    else
        echo ""
        log_error "iperf3 test failed"
        cleanup_all
        exit 1
    fi

    cleanup_all
}

run_quick_test() {
    log_info "Running quick connectivity test..."

    start_bpf_daemon
    setup_network

    # Short iperf test
    log_info "Starting iperf3 server..."
    ip netns exec server iperf3 -s -1 &
    IPERF_SERVER_PID=$!
    sleep 2

    log_info "Running 3-second iperf3 test..."
    if ip netns exec client iperf3 -c ${TEST_SERVER} -t 3; then
        echo ""
        log_info "✓ Quick test passed"
    else
        log_error "Quick test failed"
        cleanup_all
        exit 1
    fi

    cleanup_all
}

show_usage() {
    cat << EOF
Usage: $0 [MODE]

Test modes:
  basic    - Just verify eBPF CUBIC loads and registers (default)
  quick    - Run a 3-second iperf3 test
  full     - Run full ${TEST_DURATION}-second iperf3 test with network emulation

Environment variables:
  TEST_DURATION  - Duration of iperf test in seconds (default: 10)
  LATENCY        - Network latency to emulate (default: 20ms)
  BANDWIDTH      - Bandwidth limit (default: 10mbit)
  LOSS           - Packet loss percentage (default: 1%)

Examples:
  sudo $0              # Run basic test
  sudo $0 quick        # Run quick test
  sudo $0 full         # Run full test
  sudo TEST_DURATION=30 $0 full  # Run 30-second test

EOF
}

trap cleanup_all EXIT INT TERM

MODE="${1:-basic}"

case "$MODE" in
    basic)
        check_dependencies
        run_basic_test
        ;;
    quick)
        check_dependencies
        run_quick_test
        ;;
    full)
        check_dependencies
        run_iperf_test
        ;;
    -h|--help|help)
        show_usage
        exit 0
        ;;
    *)
        log_error "Unknown mode: $MODE"
        echo ""
        show_usage
        exit 1
        ;;
esac

log_info "All tests completed successfully!"
