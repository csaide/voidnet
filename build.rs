use std::process::Command;

fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-changed=bpf/xdp_kern.c");
    println!("cargo::rerun-if-env-changed=TARGET");

    let target = std::env::var("TARGET").unwrap();
    let target_arch_triplet = match target.as_str() {
        "x86_64-unknown-linux-gnu" => "x86_64-linux-gnu",
        "aarch64-unknown-linux-gnu" => "aarch64-linux-gnu",
        _ => panic!(
            "Unsupported target: {}, only x86_64-unknown-linux-gnu and aarch64-unknown-linux-gnu are currently supported",
            target
        ),
    };

    let clang_cmd = std::env::var("CLANG").unwrap_or("clang".to_string());
    let output = Command::new(clang_cmd)
        .arg("-target")
        .arg("bpf")
        .arg("-O2")
        .arg("-g")
        .arg(format!("-I/usr/include/{}", target_arch_triplet))
        .arg("-c")
        .arg("bpf/xdp_kern.c")
        .arg("-o")
        .arg("bpf/xdp_kern.o")
        .output()
        .expect("Failed to compile BPF program");

    assert!(
        output.status.success(),
        "Failed to compile BPF program: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
