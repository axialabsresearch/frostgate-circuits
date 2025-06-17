#![allow(unused_imports)]
#![allow(unused_variables)]

//! Default circuit implementations for SP1

use sp1_sdk::{ProverClient, SP1Stdin, SP1ProofWithPublicValues, CpuProver, SP1ProvingKey};
use crate::error::ZkError;
use crate::sp1::types::Sp1Circuit;

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
        
        // Get program bytes and load proving key
        let program = self.get_program_bytes();
        let proving_key = SP1ProvingKey::new(&program)
            .expect("Failed to load proving key");
        
        // Generate the proof
        let proof = prover.prove(&proving_key, &stdin)
            .expect("Failed to generate proof");
            
        // Return the proof bytes
        proof.bytes()
    }
    
    fn verify(&self, verifier: &CpuProver, proof: &[u8]) -> bool {
        // Parse the proof
        let proof = SP1ProofWithPublicValues::load(proof)
            .expect("Failed to parse proof");
            
        // Get program bytes
        let program = self.get_program_bytes();
        
        // Verify the proof
        verifier.verify(&program, &proof).is_ok()
    }
    
    fn program(&self) -> Vec<u8> {
        self.get_program_bytes()
    }
} 