//! SP1 backend implementation for Frostgate
//! 
//! This module provides a ZkBackend implementation using the SP1 proving system.

mod backend;
mod circuit;
mod types;
mod cache;

#[cfg(test)]
mod tests;

pub use backend::Sp1Backend;
pub use types::{Sp1Circuit, Sp1Options};
pub use cache::{CacheConfig, CacheStats}; 