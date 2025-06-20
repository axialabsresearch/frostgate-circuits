#![allow(unused_imports)]
#![allow(unused_variables)]

//! Default circuit implementations for SP1

use sp1_sdk::{
    ProverClient, SP1Stdin, SP1ProofWithPublicValues, CpuProver,
    SP1ProvingKey, SP1VerifyingKey, Prover,
};
use serde::Deserialize;
use crate::error::ZkError;
use crate::sp1::types::Sp1Circuit;
use std::path::Path;

/// Basic message verification circuit
pub struct MessageVerifyCircuit {
    /// Message bytes to verify
    message: Vec<u8>,
    /// Expected hash
    expected_hash: [u8; 32],
}

impl MessageVerifyCircuit {
    /// Create a new message verification circuit
    pub fn new(message: Vec<u8>, expected_hash: [u8; 32]) -> Result<Self, ZkError> {
        if message.is_empty() {
            return Err(ZkError::InvalidInput("message cannot be empty".to_string()));
        }
        Ok(Self {
            message,
            expected_hash,
        })
    }

    /// Get the program bytes for this circuit
    fn get_program_bytes(&self) -> Vec<u8> {
        // Program format:
        // [0]     - Circuit type identifier (0x01 for MessageVerify)
        // [1..33] - Expected hash
        let mut program = Vec::with_capacity(33);
        program.push(0x01); // Circuit type 1
        program.extend_from_slice(&self.expected_hash);
        program
    }
}

impl Sp1Circuit for MessageVerifyCircuit {
    fn prove(&self, prover: &CpuProver) -> Vec<u8> {
        // Create stdin and write message
        let mut stdin = SP1Stdin::new();
        stdin.write_slice(&self.message);
        
        // Get program bytes
        let program = self.get_program_bytes();
        
        // Create proving key
        let (proving_key, _) = prover.setup(&program);
        
        // Generate proof
        let proof = prover.prove(&proving_key, &stdin)
            .run()
            .expect("Failed to generate proof");
        
        // Return proof bytes
        proof.bytes().to_vec()
    }
    
    fn verify(&self, verifier: &CpuProver, proof: &[u8]) -> bool {
        // Get program bytes
        let program = self.get_program_bytes();
        
        // Create proving key and verifying key
        let (proving_key, verifying_key) = verifier.setup(&program);
        
        // Parse proof
        let proof = verifier.prove(&proving_key, &SP1Stdin::new())
            .run()
            .expect("Failed to parse proof");
        
        // Verify proof
        verifier.verify(&proof, &verifying_key).is_ok()
    }
    
    fn program(&self) -> Vec<u8> {
        self.get_program_bytes()
    }
} 