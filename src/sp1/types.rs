#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_parens)]
#![allow(unused_braces)]
#![allow(unused_macros)]
#![allow(unused_imports)]


use serde::{Deserialize, Serialize};
use sp1_zkvm::{SP1ProofWithPublicValues, SP1ProvingKey, SP1VerifyingKey};
use sp1_prover::{SP1PlonkBn254Proof, SP1Groth16Bn254Proof};
use frostgate_lib::zkplug::ZkError;
use std::path::PathBuf;
use std::time::SystemTime;
use std::fmt;
use std::collections::{HashMap, BTreeMap};

/// SP1 proof types supported by this plug.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Sp1ProofType {
    Plonk(Vec<u8>),
    Groth16(Vec<u8>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    pub max_entries: Option<usize>,
    pub ttl_seconds: Option<u64>,
    pub enable_lru: bool,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_entries: Some(100), // Limit the cache size
            ttl_seconds: Some(3600), // 1 hour TTL
            enable_lru: true,
        }
    }
}

/// SP1 plug configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sp1PlugConfig {
    pub max_concurrent: Option<usize>,
    pub api_key: Option<String>,
    pub endpoint: Option<String>,
}

impl Default for Sp1PlugConfig {
    fn default() -> Self {
        Self {
            max_concurrent: Some(num_cpus::get()),
            api_key: None,
            endpoint: None,
        }
    }
}

/// Cached program information including compiled keys
#[derive(Clone)]
pub struct ProgramInfo {
    pub elf: Vec<u8>,
    pub proving_key: SP1ProvingKey,
    pub verifying_key: SP1VerifyingKey,
    pub program_hash: String,
    pub compiled_at: SystemTime,
    pub last_accessed: SystemTime,
    pub access_count: u64,
}

impl fmt::Debug for ProgramInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProgramInfo")
            .field("program_hash", &self.program_hash)
            .field("compiled_at", &self.compiled_at)
            .field("proving_key", &"<SP1ProvingKey omitted>")
            .field("verifying_key", &"<SP1VerifyingKey omitted>")
            .finish()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Sp1PlugError {
    #[error("SP1 key generation error: {0}")]
    KeyGen(String),
    
    #[error("SP1 proof error: {0}")]
    Proof(String),
    
    #[error("SP1 verification error: {0}")]
    Verification(String),
    
    #[error("SP1 execution error: {0}")]
    Execution(String),
    
    #[error("SP1 program not found: {0}")]
    ProgramNotFound(String),
    
    #[error("SP1 input error: {0}")]
    Input(String),
    
    #[error("SP1 serialization error: {0}")]
    Serialization(String),
    
    #[error("SP1 unsupported: {0}")]
    Unsupported(String),
}

impl From<Sp1PlugError> for ZkError {
    fn from(err: Sp1PlugError) -> Self {
        ZkError::Backend(err.to_string())
    }
}

/// Backend wrapper for local or network proving
pub enum Sp1Backend {
    Local(sp1_sdk::EnvProver),
    Network(sp1_sdk::NetworkProver),
}

impl fmt::Debug for Sp1Backend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Sp1Backend::Local(_) => write!(f, "Local(EnvProver)"),
            Sp1Backend::Network(_) => write!(f, "Network(NetworkProver)"),
        }
    }
}
