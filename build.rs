use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

fn main() {
    // Create target directory for RISC0 ELF files
    let out_dir = env::var("OUT_DIR").unwrap();
    let target_dir = Path::new(&out_dir).join("riscv");
    fs::create_dir_all(&target_dir).unwrap();

    // Build message verification circuit
    println!("cargo:rerun-if-changed=circuits/message_verify.rs");
    let status = Command::new("risc0-build")
        .arg("circuits/message_verify.rs")
        .arg("-o")
        .arg(target_dir.join("message_verify.elf"))
        .status()
        .expect("Failed to build message verification circuit");
    assert!(status.success());

    // Build transaction verification circuit
    println!("cargo:rerun-if-changed=circuits/tx_verify.rs");
    let status = Command::new("risc0-build")
        .arg("circuits/tx_verify.rs")
        .arg("-o")
        .arg(target_dir.join("tx_verify.elf"))
        .status()
        .expect("Failed to build transaction verification circuit");
    assert!(status.success());

    // Build block verification circuit
    println!("cargo:rerun-if-changed=circuits/block_verify.rs");
    let status = Command::new("risc0-build")
        .arg("circuits/block_verify.rs")
        .arg("-o")
        .arg(target_dir.join("block_verify.elf"))
        .status()
        .expect("Failed to build block verification circuit");
    assert!(status.success());

    // Print cargo directives
    println!("cargo:rustc-env=RISC0_ELF_DIR={}", target_dir.display());
} 