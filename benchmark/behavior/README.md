# eBPF Algorithm-Agnostic Datapath Behavior Benchmarks

## Usage

### List available algorithms (verify your eBPF algorithm appears)
```sudo python3 tcp_cong_test.py --list-algorithms```

### Test your algorithm against baselines
sudo python3 tcp_cong_test.py -a cubic bbr your_ebpf_alg -d 21 81 162

### Quick test
sudo python3 tcp_cong_test.py -a your_ebpf_alg cubic -d 21 -t 30 -s 10
