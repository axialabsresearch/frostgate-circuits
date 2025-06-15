#![allow(unused_imports)]
#![allow(unused_variables)]

//! Type definitions for SP1 backend

use serde::{Serialize, Deserialize};
use sp1_sdk::{ProverClient, SP1Stdin, SP1ProofWithPublicValues};
use crate::error::ZkError;
// use sp1_core::SP1Verifier;

/// SP1 circuit trait
pub trait Sp1Circuit: Send + Sync {
    /// Generate a proof for this circuit
    fn prove(&self, prover: &ProverClient) -> Vec<u8>;
    
    /// Verify a proof for this circuit
    fn verify(&self, verifier: &ProverClient, proof: &[u8]) -> bool;
    
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

impl Default for Sp1Options {
    fn default() -> Self {
        Self {
            num_threads: Some(4),
            memory_limit: Some(1024 * 1024 * 1024), // 1GB
            custom_params: None,
        }
    }
}

/// SP1 proof verification result
#[derive(Debug, Clone)]
pub struct Sp1VerificationResult {
    /// Whether the proof is valid
    pub is_valid: bool,
    /// Error message if verification failed
    pub error: Option<String>,
}

impl Sp1VerificationResult {
    /// Create a new successful verification result
    pub fn success() -> Self {
        Self {
            is_valid: true,
            error: None,
        }
    }

    /// Create a new failed verification result
    pub fn failure(error: String) -> Self {
        Self {
            is_valid: false,
            error: Some(error),
        }
    }
} 