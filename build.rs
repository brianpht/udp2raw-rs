//! Build script: conditionally compile the eBPF XDP program when `xdp` feature is enabled.

fn main() {
    #[cfg(feature = "xdp")]
    {
        println!("cargo::rerun-if-changed=udp2raw-ebpf/src");
        println!("cargo::rerun-if-changed=udp2raw-ebpf/Cargo.toml");
        aya_build::build_ebpf(["udp2raw-ebpf"])
            .expect("eBPF build failed — install bpf-linker: cargo install bpf-linker");
    }
}

