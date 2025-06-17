//! SP1 backend implementation for Frostgate
//! 
//! This module provides a ZkBackend implementation using the SP1 proving system.

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use sp1_sdk::{ProverClient, SP1Stdin, SP1ProofWithPublicValues};
use crate::error::ZkError;

//use crate::cache::{Cache, CacheConfig, CacheStats};
//use super::types::{Sp1Circuit, Sp1Options, Sp1VerificationResult};
//use super::backend::{Sp1Backend};

pub mod backend;
pub mod circuit;
pub mod types;
pub mod cache;

#[cfg(test)]
mod tests;

pub use backend::Sp1Backend;
pub use types::{Sp1Circuit, Sp1Options, Sp1VerificationResult};
pub use cache::{CacheConfig, CacheStats};



/* #[async_trait::async_trait]
impl ZkBackend for Sp1Backend {
    async fn prove(
        &self,
        program: &[u8],
        input: &[u8],
        options: Option<ZkOptions>,
    ) -> Result<(ZkProof, ZkProofMetadata), ZkError> {
        // Check proof cache first
        if let Some(cached_proof) = self.proof_cache.get(&(program.to_vec(), input.to_vec())) {
            return Ok((
                ZkProof {
                    data: cached_proof,
                    format: "sp1".to_string(),
                },
                ZkProofMetadata {
                    program_hash: hex::encode(program),
                    generation_time: Duration::from_millis(0),
                    proof_size: cached_proof.len(),
                },
            ));
        }

        // Create circuit
        let circuit = self.create_circuit(program)?;
        
        // Generate proof
        let start = std::time::Instant::now();
        let proof_data = circuit.prove(&self.prover);
        let generation_time = start.elapsed();
        
        // Cache proof
        self.proof_cache.insert(
            (program.to_vec(), input.to_vec()),
            proof_data.clone(),
        );
        
        Ok((
            ZkProof {
                data: proof_data,
                format: "sp1".to_string(),
            },
            ZkProofMetadata {
                program_hash: hex::encode(program),
                generation_time,
                proof_size: proof_data.len(),
            },
        ))
    }

    async fn verify(
        &self,
        program: &[u8],
        proof: &[u8],
        options: Option<ZkOptions>,
    ) -> Result<bool, ZkError> {
        // Create circuit
        let circuit = self.create_circuit(program)?;
        
        // Verify proof 
        Ok(circuit.verify(&self.prover, proof))
    }

    async fn health_check(&self) -> Result<(), ZkError> {
        // Simple health check - try to create a prover
        let _prover = ProverClient::new();
        Ok(())
    }
}

impl Sp1Backend {
    /// Create a circuit from program bytes
    fn create_circuit(&self, program: &[u8]) -> Result<Box<dyn Sp1Circuit>, ZkError> {
        // Check circuit cache first
        if let Some(cached_circuit) = self.cache.get(program) {
            return Ok(Box::new(MessageVerifyCircuit {
                program: cached_circuit,
            }));
        }

        // Create new circuit
        let circuit = Box::new(MessageVerifyCircuit {
            program: program.to_vec(),
        });

        // Cache circuit
        self.cache.insert(program.to_vec(), program.to_vec());

        Ok(circuit)
    }
}

/// Message verification circuit
struct MessageVerifyCircuit {
    program: Vec<u8>,
}

impl Sp1Circuit for MessageVerifyCircuit {
    fn prove(&self, prover: &ProverClient) -> Vec<u8> {
        let mut stdin = SP1Stdin::new();
        stdin.write(&self.program);
        
        let (pk, vk) = prover.setup(&self.program);
        let proof = prover.prove(&pk, &stdin).unwrap();
        
        proof.serialize()
    }

    fn verify(&self, verifier: &ProverClient, proof: &[u8]) -> bool {
        let proof = SP1ProofWithPublicValues::deserialize(proof).unwrap();
        let (_, vk) = verifier.setup(&self.program);
        
        verifier.verify(&vk, &proof).is_ok()
    }

    fn program(&self) -> Vec<u8> {
        self.program.clone()
    }
}  */