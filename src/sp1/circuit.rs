//! Default circuit implementations for SP1

use sp1_core::{SP1Prover, SP1Verifier, utils::hash_bytes};
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
    pub fn new(message: Vec<u8>, expected_hash: [u8; 32]) -> Self {
        Self {
            message,
            expected_hash,
        }
    }

    /// Get the program bytes for this circuit
    fn get_program_bytes(&self) -> Vec<u8> {
        // Program format:
        // [0..32]  - Expected hash
        // [32..64] - Circuit type identifier (0x01 for MessageVerify)
        let mut program = Vec::with_capacity(64);
        program.extend_from_slice(&self.expected_hash);
        program.extend_from_slice(&[0x01; 32]); // Circuit type 1
        program
    }
}

impl Sp1Circuit for MessageVerifyCircuit {
    fn prove(&self, prover: &SP1Prover) -> Vec<u8> {
        // 1. Hash the message
        let message_hash = hash_bytes(&self.message);
        
        // 2. Create the proof that hash matches expected_hash
        let mut proof = Vec::with_capacity(96);
        
        // Proof format:
        // [0..32]  - Message hash
        // [32..64] - Random salt
        // [64..96] - SP1 proof bytes
        proof.extend_from_slice(&message_hash);
        proof.extend_from_slice(&prover.generate_salt()); // Random salt
        proof.extend_from_slice(&prover.prove_equality(message_hash, self.expected_hash));
        
        proof
    }
    
    fn verify(&self, verifier: &SP1Verifier, proof: &[u8]) -> bool {
        if proof.len() != 96 {
            return false;
        }

        // Extract proof components
        let message_hash = &proof[0..32];
        let salt = &proof[32..64];
        let sp1_proof = &proof[64..96];

        // Verify the SP1 proof
        verifier.verify_equality(
            message_hash,
            &self.expected_hash,
            salt,
            sp1_proof,
        )
    }
    
    fn program(&self) -> Vec<u8> {
        self.get_program_bytes()
    }
} 