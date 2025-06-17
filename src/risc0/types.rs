#![allow(unused_imports)]
#![allow(unused_variables)]

//! Type definitions for RISC0 backend

use serde::{Serialize, Deserialize};
use risc0_zkvm::{
    Prover, ProverOpts,
    Receipt,
    ExecutorEnv,
};

/// RISC0 circuit trait
pub trait Risc0Circuit: Send + Sync {
    /// Get the ELF binary for this circuit
    fn elf(&self) -> &[u8];
    
    /// Get the circuit's public inputs
    fn public_inputs(&self) -> Vec<u32>;
    
    /// Get the circuit's private inputs
    fn private_inputs(&self) -> Vec<u8>;
    
    /// Verify circuit-specific conditions in the receipt
    fn verify_receipt(&self, receipt: &Receipt) -> bool;
}

/// RISC0-specific configuration options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Risc0Options {
    /// Number of parallel proving threads
    pub num_threads: Option<usize>,
    /// Memory limit per proof in bytes
    pub memory_limit: Option<usize>,
    /// Custom proving parameters
    pub custom_params: Option<Vec<u8>>,
}

impl Default for Risc0Options {
    fn default() -> Self {
        Self {
            num_threads: Some(4),
            memory_limit: Some(1024 * 1024 * 1024), // 1GB
            custom_params: None,
        }
    }
} 