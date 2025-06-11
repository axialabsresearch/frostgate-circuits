//! Zero-knowledge circuit implementations for Frostgate
//!
//! This crate provides implementations of various zero-knowledge proof systems
//! using the ZkBackend trait from frostgate-zkip.

// Backend implementations
pub mod sp1;
pub mod risc0;

// Re-export core types from zkip
pub use frostgate_zkip::{
    ZkBackend, ZkBackendExt, ZkError, ZkResult,
    HealthStatus, ProofMetadata, ResourceUsage, ZkConfig, ZkStats,
};

// Re-export backend implementations
pub use sp1::Sp1Backend;
pub use risc0::Risc0Backend;

#[cfg(test)]
mod tests {
    use super::*;
    use frostgate_zkip::*;
    
    #[test]
    fn test_sp1_circuit() {
        let backend = Sp1Backend::new();
        // Add tests here
    }

    #[test]
    fn test_risc0_circuit() {
        let backend = Risc0Backend::new();
        // Add tests here
    }
}