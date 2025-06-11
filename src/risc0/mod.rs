//! RISC0 backend implementation for Frostgate
//! 
//! This module provides a ZkBackend implementation using the RISC0 proving system.

mod backend;
mod circuit;
mod types;
mod cache;

#[cfg(test)]
mod tests;

pub use backend::Risc0Backend;
pub use types::{Risc0Circuit, Risc0Options};
pub use cache::{CacheConfig, CacheStats}; 