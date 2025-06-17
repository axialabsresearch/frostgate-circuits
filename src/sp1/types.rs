#![allow(unused_imports)]
#![allow(unused_variables)]

//! Type definitions for SP1 backend

use serde::{Serialize, Deserialize};
use sp1_sdk::{CpuProver, SP1Stdin, SP1ProofWithPublicValues};
use crate::error::ZkError;
// use sp1_core::SP1Verifier;

/// SP1 circuit trait
pub trait Sp1Circuit: Send + Sync {
    /// Generate a proof for this circuit
    fn prove(&self, prover: &CpuProver) -> Vec<u8>;
    
    /// Verify a proof for this circuit
    fn verify(&self, verifier: &CpuProver, proof: &[u8]) -> bool;
    
    /// Get the program bytes for this circuit
    fn program(&self) -> Vec<u8>;
}

/// SP1-specific options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sp1Options {
    /// Number of threads to use for proving
    pub num_threads: Option<usize>,
    /// Memory limit in bytes
    pub memory_limit: Option<usize>,
    /// Custom parameters
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