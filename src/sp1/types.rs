use serde::{Deserialize, Serialize};
use sp1_core_machine::io::SP1Stdin;
use sp1_sdk::{SP1ProofWithPublicValues, SP1ProvingKey, SP1VerifyingKey};
use sp1_prover::{SP1PlonkBn254Proof, SP1Groth16Bn254Proof};
use std::path::PathBuf;
use std::time::SystemTime;
use std::fmt;

/// SP1 proof types supported by this plug.
#[derive(Clone, Serialize, Deserialize)]
pub enum Sp1ProofType {
    Core(SP1ProofWithPublicValues),
    PlonkBn254(SP1PlonkBn254Proof),
    Groth16Bn254(SP1Groth16Bn254Proof),
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
    pub use_network: bool,
    pub network_api_key: Option<String>,
    pub network_endpoint: Option<String>,
    pub max_concurrent: Option<usize>,
    pub build_dir: Option<PathBuf>,
    pub max_input_size: Option<usize>,
    pub cache_config: CacheConfig,
}

impl Default for Sp1PlugConfig {
    fn default() -> Self {
        Self {
            use_network: false,
            network_api_key: std::env::var("SP1_PRIVATE_KEY").ok(),
            network_endpoint: None,
            max_concurrent: Some(num_cpus::get()),
            build_dir: Some(std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))),
            max_input_size: Some(100*1024*1024), // 100MB default
            cache_config: CacheConfig::default(),
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
    Verify(String),
    #[error("SP1 execution error: {0}")]
    Execution(String),
    #[error("SP1 program not found: {0}")]
    NotFound(String),
    #[error("SP1 input error: {0}")]
    Input(String),
    #[error("SP1 serialization error: {0}")]
    Serialization(String),
    #[error("SP1 unsupported: {0}")]
    Unsupported(String),
}

/// Backend wrapper for local or network proving
#[derive(Debug)]
pub enum Sp1Backend {
    Local(sp1_sdk::EnvProver),
    Network(sp1_sdk::NetworkProver),
}
