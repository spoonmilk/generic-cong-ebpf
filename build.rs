use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=ebpf/datapath.bpf.c");
    println!("cargo:rerun-if-changed=ebpf/common.h");

    // Compile eBPF code
    let status = Command::new("make")
        .current_dir("ebpf")
        .status()
        .expect("Failed to run make in ebpf/");

    if !status.success() {
        panic!("eBPF compilation failed");
    }

    println!("cargo:warning=eBPF datapath compiled successfully");
}
