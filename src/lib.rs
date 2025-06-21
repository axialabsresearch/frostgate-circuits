#![allow(unused_imports)]
#![allow(unused_variables)]

//! # Frostgate Circuits
//!
//! This crate provides concrete implementations of zero-knowledge proof systems for the Frostgate ecosystem.
//! It implements the [`ZkBackend`] trait from `frostgate-zkip` for various proving systems.
//!
//! ## Available Backends
//!
//! ### SP1 Backend
//!
//! The [`Sp1Backend`] provides a high-performance implementation using the SP1 (Succinct Proofs of Interaction)
//! proving system. Features include:
//!
//! - Efficient proof generation and verification
//! - Circuit caching for improved performance
//! - Resource usage tracking
//! - Batch operations support
//!
//! ```rust,no_run
//! use frostgate_circuits::Sp1Backend;
//! use frostgate_zkip::ZkBackend;
//!
//! async fn generate_proof(message: &[u8]) {
//!     let backend = Sp1Backend::new();
//!     let program = vec![0x01]; // Example program
//!     let (proof, metadata) = backend.prove(&program, message, None).await.unwrap();
//! }
//! ```
//!
//! ### RISC0 Backend
//!
//! The [`Risc0Backend`] implements zero-knowledge proofs using the RISC0 proving system:
//!
//! - RISC-V based proving system
//! - Configurable through [`Risc0Config`]
//! - Support for complex computations
//!
//! ```rust,no_run
//! use frostgate_circuits::{Risc0Backend, Risc0Config};
//!
//! let backend = Risc0Backend::new(Risc0Config::default());
//! ```
//!
//! ## Features
//!
//! - `std`: Enables standard library features (default)
//! - `prove`: Enables proof generation capabilities
//!
//! ## Performance Considerations
//!
//! Each backend has different performance characteristics:
//!
//! - SP1: Optimized for small to medium circuits with frequent proof generation
//! - RISC0: Better for complex computations where circuit size is less critical
//!
//! ## Error Handling
//!
//! The crate uses the error types from `frostgate-zkip`:
//! - [`ZkError`] for error conditions
//! - [`ZkResult`] as a convenience type alias

// Backend implementations
pub mod sp1;
pub mod risc0;
pub mod error;

// Re-export core types from zkip
pub use frostgate_zkip::{
    ZkBackend, ZkBackendExt, ZkError, ZkResult,
    HealthStatus, ProofMetadata, ResourceUsage, ZkConfig, ZkStats,
};

// Re-export backend implementations
pub use sp1::Sp1Backend;
pub use risc0::{Risc0Backend, Risc0Config};

#[cfg(test)]
mod tests {
    use super::*;
    use frostgate_zkip::*;
    
    #[test]
    fn test_sp1_circuit() { 
        let backend = Sp1Backend::new();
        // Extra tests 
    }

    #[test]
    fn test_risc0_circuit() {
        let backend = Risc0Backend::new(Risc0Config::default());
        // Extra tests
    }
}