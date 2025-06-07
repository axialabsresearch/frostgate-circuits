#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_parens)]
#![allow(unused_braces)]
#![allow(unused_macros)]
#![allow(unused_imports)]

use sp1_zkvm::{self, io, Program, Proof};
use frostgate_lib::zkplug::*;
use sha3::{Digest, Keccak256};

mod circuit;

pub struct Sp1Backend;

impl Sp1Backend {
    pub fn new() -> Self {
        Self
    }

    pub fn prove(&self, program: &[u8], input: &[u8]) -> Result<Vec<u8>, ZkError> {
        // Load the program
        let program = Program::load(program)
            .map_err(|e| ZkError::Backend(e.to_string()))?;
            
        // Create stdin for the program
        let mut stdin = io::StdinBuilder::new();
        stdin.write(input);
        
        // Execute the program and generate proof
        let proof = program.prove(stdin.build())
            .map_err(|e| ZkError::Backend(e.to_string()))?;
            
        // Serialize the proof
        bincode::serialize(&proof)
            .map_err(|e| ZkError::Backend(e.to_string()))
    }

    pub fn verify(&self, program: &[u8], proof: &[u8]) -> Result<bool, ZkError> {
        // Load the program
        let program = Program::load(program)
            .map_err(|e| ZkError::Backend(e.to_string()))?;
            
        // Deserialize the proof
        let proof: Proof = bincode::deserialize(proof)
            .map_err(|e| ZkError::Backend(e.to_string()))?;
            
        // Verify the proof
        program.verify(&proof)
            .map(|_| true)
            .map_err(|e| ZkError::VerificationFailed(e.to_string()))
    }
}

impl ZkBackend for Sp1Backend {
    type Error = ZkError;
    
    fn prove(&self, program: &[u8], input: &[u8]) -> Result<Vec<u8>, Self::Error> {
        self.prove(program, input)
    }
    
    fn verify(&self, program: &[u8], proof: &[u8]) -> Result<bool, Self::Error> {
        self.verify(program, proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_sp1_backend() {
        let backend = Sp1Backend::new();
        // Add tests here
    }
}