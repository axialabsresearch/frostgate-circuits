#![allow(unused_imports)]
#![allow(unused_variables)]

#![no_std]
#![no_main]

use risc0_zkvm::guest::env;
use sha2::{Sha256, Digest};
use sp1_core::{SP1Circuit, SP1Stdin};

risc0_zkvm::guest::entry!(main);

#[derive(SP1Circuit)]
pub struct MessageVerifyCircuit {
    pub message: Vec<u8>,
    pub expected_hash: [u8; 32],
}

impl MessageVerifyCircuit {
    pub fn new(message: Vec<u8>, expected_hash: [u8; 32]) -> Self {
        Self {
            message,
            expected_hash,
        }
    }
}

impl SP1Circuit for MessageVerifyCircuit {
    fn run(&self, stdin: &mut SP1Stdin) -> Result<(), String> {
        // Compute message hash
        let mut hasher = Sha256::new();
        hasher.update(&self.message);
        let computed_hash = hasher.finalize();
        
        // Verify hash matches expected
        if computed_hash.as_slice() != &self.expected_hash {
            return Err("Hash verification failed".to_string());
        }
        
        Ok(())
    }
}

fn main() {
    // Read message from private input
    let message: Vec<u8> = env::read();
    
    // Read expected hash from public input
    let mut expected_hash = [0u8; 32];
    for i in 0..8 {
        let word = env::read::<u32>();
        expected_hash[i*4..(i+1)*4].copy_from_slice(&word.to_le_bytes());
    }
    
    // Compute message hash
    let mut hasher = Sha256::new();
    hasher.update(&message);
    let computed_hash = hasher.finalize();
    
    // Verify hash matches expected
    assert_eq!(computed_hash.as_slice(), &expected_hash);
    
    // Write hash to journal for verification
    env::commit(&computed_hash);
} 