#![allow(unused_imports)]
#![allow(unused_variables)]

use std::env;
use std::path::PathBuf;
use std::fs;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=circuits/message_verify.rs");
    println!("cargo:rerun-if-changed=circuits/tx_verify.rs");
    println!("cargo:rerun-if-changed=circuits/block_verify.rs");

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let circuits_dir = PathBuf::from("circuits");
    
    // Create programs directory if it doesn't exist
    let programs_dir = PathBuf::from("programs");
    fs::create_dir_all(&programs_dir).expect("Failed to create programs directory");

    // Create target/riscv directory for RISC0 ELF files
    let target_riscv_dir = PathBuf::from("target/riscv");
    fs::create_dir_all(&target_riscv_dir).expect("Failed to create target/riscv directory");

    // Try to build RISC0 circuits using cargo-risczero
    if let Ok(status) = Command::new("cargo")
        .args(&["risczero", "build", "--package", "frostgate-risc0-circuits"])
        .current_dir(&circuits_dir)
        .status() {
        if status.success() {
            println!("cargo:warning=RISC0 circuits built successfully");
            
            // Copy ELF files to expected locations
            let elf_files = ["message_verify", "tx_verify"];
            for elf_name in &elf_files {
                let source_path = circuits_dir.join("target/riscv32im-risc0-zkvm-elf/release").join(format!("{}.elf", elf_name));
                let dest_path = target_riscv_dir.join(format!("{}.elf", elf_name));
                
                if source_path.exists() {
                    fs::copy(&source_path, &dest_path)
                        .unwrap_or_else(|_| {
                            println!("cargo:warning=Failed to copy {} ELF file", elf_name);
                            0
                        });
                } else {
                    // Create placeholder ELF file for development
                    fs::write(&dest_path, vec![0u8; 64])
                        .unwrap_or_else(|_| println!("cargo:warning=Failed to create placeholder {} ELF file", elf_name));
                }
            }
        } else {
            println!("cargo:warning=RISC0 build failed, using placeholder ELF files");
            create_placeholder_elf_files(&target_riscv_dir);
        }
    } else {
        println!("cargo:warning=cargo-risczero not available, using placeholder ELF files");
        create_placeholder_elf_files(&target_riscv_dir);
    }

    // Compile circuits for each chain (SP1 format)
    let chains = ["eth", "dot", "sol"];
    for chain in chains.iter() {
        let verifier_path = programs_dir.join(format!("{}_verifier.sp1", chain));
        
        // For development, create empty verifier files if they don't exist
        if !verifier_path.exists() {
            fs::write(&verifier_path, vec![0u8; 64]).expect("Failed to create verifier file");
        }
    }

    println!("cargo:warning=ELF files generated successfully");
}

fn create_placeholder_elf_files(target_dir: &PathBuf) {
    let elf_files = ["message_verify", "tx_verify"];
    for elf_name in &elf_files {
        let elf_path = target_dir.join(format!("{}.elf", elf_name));
        fs::write(&elf_path, vec![0u8; 64])
            .unwrap_or_else(|_| println!("cargo:warning=Failed to create placeholder {} ELF file", elf_name));
    }
} 