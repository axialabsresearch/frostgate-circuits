//! Type definitions for SP1 backend

use serde::{Serialize, Deserialize};
use sp1_core::{SP1Prover, SP1Verifier};

/// SP1 circuit trait
pub trait Sp1Circuit: Send + Sync {
    /// Generate a proof for this circuit
    fn prove(&self, prover: &SP1Prover) -> Vec<u8>;
    
    /// Verify a proof for this circuit
    fn verify(&self, verifier: &SP1Verifier, proof: &[u8]) -> bool;
    
    /// Get the circuit's program bytes
    fn program(&self) -> Vec<u8>;
}

/// SP1-specific configuration options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sp1Options {
    /// Number of parallel proving threads
    pub num_threads: Option<usize>,
    /// Memory limit per proof in bytes
    pub memory_limit: Option<usize>,
    /// Custom proving parameters
    pub custom_params: Option<Vec<u8>>,
} 