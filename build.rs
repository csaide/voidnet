use std::process::Command;

fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-changed=bpf/xdp_kern.c");
    println!("cargo::rerun-if-env-changed=TARGET");

    let max_socks = std::env::var("MAX_SOCKS").unwrap_or_else(|_| 256.to_string());
    let mut args = vec![
        "-target".to_string(),
        "bpf".to_string(),
        "-O2".to_string(),
        "-g".to_string(),
        "-march=native".to_string(),
        format!("-DMAX_SOCKS={}", max_socks),
    ];

    let kernel_version = Command::new("uname")
        .arg("-r")
        .output()
        .expect("Failed executing uname: unable to determine kernel version");
    let kernel_version = String::from_utf8(kernel_version.stdout).unwrap();

    let target = std::env::var("TARGET").unwrap();
    let (target_arch, target_arch_triplet) = match target.as_str() {
        "x86_64-unknown-linux-gnu" => ("x86", "x86_64-linux-gnu"),
        "aarch64-unknown-linux-gnu" => ("aarch64", "aarch64-linux-gnu"),
        _ => panic!(
            "Unsupported target: {}, only x86_64-unknown-linux-gnu and aarch64-unknown-linux-gnu are supported",
            target
        ),
    };

    args.push(format!(
        "-I/lib/modules/{}/build/arch/{}/include",
        kernel_version, target_arch
    ));
    args.push(format!(
        "-I/lib/modules/{}/build/arch/{}/include/uapi",
        kernel_version, target_arch
    ));
    args.push(format!("-I/usr/include/{}", target_arch_triplet));

    Command::new("clang")
        .args(&args)
        .arg("-c")
        .arg("bpf/xdp_kern.c")
        .arg("-o")
        .arg("bpf/xdp_kern.o")
        .output()
        .expect("Failed to compile BPF program");
}
