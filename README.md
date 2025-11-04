# eBPF-CUBIC CCP Congestion Control

## Dependencies

See Vagrantfile in upper-level directory.
Requires cargo installed and libbpf-sys.
Make sure vmlinux is supported on your kernel version.

## Architecture

This project implements the CUBIC datapath from generic-cong-avoid in eBPF,
replacing the CCP datapath language programs with eBPF hooked into the TCP
stack with tcp_struct_ops.

Previous attempts have used a userspace libccp hooked to an eBPF program
which implemented struct_ops updates, but required a full userspace libccp
running process throughout. This implementation removes that layer of indirection.

### Components

1. **eBPF Datapath** (`ebpf/datapath.bpf.c`): Kernel-space BPF program that:
   - Registers as a TCP congestion control algorithm via `struct_ops`
   - Hooks into TCP stack callbacks
   - Sends measurements and flow events to userspace via ring buffers
   - Receives cwnd updates from userspace via BPF hash map

2. **Rust Userspace Daemon** (`src/main.rs`, `src/bpf.rs`):
   - Loads and attaches the eBPF program using libbpf-rs
   - Polls ring buffers for measurements and flow events
   - Runs CUBIC algorithm logic per-flow
   - Sends cwnd updates back to kernel via BPF maps

3. **CUBIC Implementation** (`src/cubic.rs`, `src/lib.rs`):
   - Taken from `ccp-project/GenericCongAvoid`
   - Implements `GenericCongAvoidFlow` trait

## Running

> [!NOTE]
> PLEASE DO NOT RUN THIS OUTSIDE OF A VIRTUAL MACHINE! IT CAN AND MIGHT BREAK
> YOUR KERNEL IN WAYS I REALLY DON'T WANT TO BE HELD RESPONSIBLE FOR, OKEY?

Once you've got your VM up and running (I built on Ubuntu 24.04) and have
all your dependencies satisfied, you can run `make all` to build both the
eBPF and userspace Rust component.

There are three different configurations for testing functionality.

```bash
make test # Run registration test, succeeds if ebpf-cubic hooks into struct_ops
make test-quick # 3-second iperf test
make test-full # 10 second iperf test w/ packet drops
```

>[!NOTE]
> YOU MUST RUN WITH SUDO. IF THE MAKEFILE DOESN'T WORK FOR YOU, RUN THE SCRIPT
> MANUALLY UNDER SUDO

## Issues I've had

### Can't build because of cargo stuff

Solution:

```bash
rm -rf ~/.cargo/git
rm -rf ~/.cargo/registry
```

### Can't halt VM

Solution:

Still trying to fix this one. I just power the VM off, pray, then restart

## Acknowledgments

This repo was created and written by Alex Khosrowshahi (Brown '27) for research
under Professor Akshay Narayan as part of the CCP project.
A large part of the code is taken from the `ccp-project/generic-cong-avoid` repository.
