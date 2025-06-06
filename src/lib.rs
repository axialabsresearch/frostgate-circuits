#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(unused_mut)]
#![allow(unused_must_use)]
#![allow(dead_code)]

pub mod sp1;
pub mod groth16;
pub mod halo2;
pub mod risc0;

// Re-export commonly used types and functions
pub use sp1::Sp1Plug;
pub use sp1::types::{Sp1PlugConfig, Sp1ProofType, Sp1PlugError};
pub use sp1::verifier::verify_proof;
pub use sp1::prover::{setup_program, generate_proof, execute_program};

// Common traits and types
pub mod common {
    use frostgate_zkip::zkplug::*;
    pub use super::sp1::types::ProgramInfo;
}

// Feature flags for different backends
#[cfg(feature = "sp1")]
pub use sp1::*;

#[cfg(feature = "halo2")]
pub use halo2::*;

#[cfg(feature = "groth16")]
pub use groth16::*;

#[cfg(feature = "risc0")]
pub use risc0::*;