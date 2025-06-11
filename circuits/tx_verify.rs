#![no_std]
#![no_main]

use risc0_zkvm::guest::env;
use sha2::{Sha256, Digest};
use serde_json_core::from_slice;

risc0_zkvm::guest::entry!(main);

#[derive(serde::Deserialize)]
struct Transaction<'a> {
    from: &'a str,
    to: &'a str,
    value: &'a str,
}

fn main() {
    // Read transaction from private input
    let tx_bytes: Vec<u8> = env::read();
    
    // Read expected hash from public input
    let mut expected_hash = [0u8; 32];
    for i in 0..8 {
        let word = env::read::<u32>();
        expected_hash[i*4..(i+1)*4].copy_from_slice(&word.to_le_bytes());
    }
    
    // Parse and validate transaction
    let tx: Transaction = from_slice(&tx_bytes)
        .expect("Failed to parse transaction JSON").0;
    
    // Validate transaction fields
    assert!(tx.from.starts_with("0x"), "Invalid from address");
    assert!(tx.to.starts_with("0x"), "Invalid to address");
    assert!(tx.value.parse::<u64>().is_ok(), "Invalid value");
    
    // Compute transaction hash
    let mut hasher = Sha256::new();
    hasher.update(&tx_bytes);
    let computed_hash = hasher.finalize();
    
    // Verify hash matches expected
    assert_eq!(computed_hash.as_slice(), &expected_hash);
    
    // Write hash and validation data to journal
    env::commit(&computed_hash);
    env::commit(&[
        tx.from.len() as u8,
        tx.to.len() as u8,
        tx.value.len() as u8,
    ]);
} 