#![no_std]
#![no_main]

use risc0_zkvm::guest::env;
use sha2::{Sha256, Digest};
use serde_json_core::from_slice;

risc0_zkvm::guest::entry!(main);

#[derive(serde::Deserialize)]
struct BlockHeader<'a> {
    parent_hash: &'a str,
    state_root: &'a str,
    transactions_root: &'a str,
    receipts_root: &'a str,
    number: &'a str,
    timestamp: &'a str,
    gas_used: &'a str,
    gas_limit: &'a str,
    extra_data: &'a [u8],
}

fn main() {
    // Read block header from private input
    let header_bytes: Vec<u8> = env::read();
    
    // Read expected hash and block number from public input
    let mut expected_hash = [0u8; 32];
    for i in 0..8 {
        let word = env::read::<u32>();
        expected_hash[i*4..(i+1)*4].copy_from_slice(&word.to_le_bytes());
    }
    
    let expected_number = env::read::<u64>();
    
    // Parse and validate block header
    let header: BlockHeader = from_slice(&header_bytes)
        .expect("Failed to parse block header JSON").0;
    
    // Validate block header fields
    assert!(header.parent_hash.starts_with("0x") && header.parent_hash.len() == 66,
        "Invalid parent hash");
    assert!(header.state_root.starts_with("0x") && header.state_root.len() == 66,
        "Invalid state root");
    assert!(header.transactions_root.starts_with("0x") && header.transactions_root.len() == 66,
        "Invalid transactions root");
    assert!(header.receipts_root.starts_with("0x") && header.receipts_root.len() == 66,
        "Invalid receipts root");
    
    // Validate block number
    let block_number = u64::from_str_radix(&header.number[2..], 16)
        .expect("Invalid block number");
    assert_eq!(block_number, expected_number, "Block number mismatch");
    
    // Validate timestamp (must be reasonable)
    let timestamp = u64::from_str_radix(&header.timestamp[2..], 16)
        .expect("Invalid timestamp");
    assert!(timestamp > 1600000000, "Timestamp too old"); // Sept 2020
    assert!(timestamp < 2000000000, "Timestamp too far in future"); // 2033
    
    // Validate gas fields
    let gas_used = u64::from_str_radix(&header.gas_used[2..], 16)
        .expect("Invalid gas used");
    let gas_limit = u64::from_str_radix(&header.gas_limit[2..], 16)
        .expect("Invalid gas limit");
    assert!(gas_used <= gas_limit, "Gas used exceeds limit");
    
    // Compute block header hash
    let mut hasher = Sha256::new();
    hasher.update(&header_bytes);
    let computed_hash = hasher.finalize();
    
    // Verify hash matches expected
    assert_eq!(computed_hash.as_slice(), &expected_hash);
    
    // Write verification data to journal
    env::commit(&computed_hash);
    env::commit(&block_number.to_le_bytes());
    env::commit(&timestamp.to_le_bytes());
    env::commit(&[
        gas_used.to_le_bytes(),
        gas_limit.to_le_bytes(),
    ].concat());
} 