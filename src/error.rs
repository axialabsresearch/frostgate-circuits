use std::fmt;
use thiserror::Error;

/// Zero-knowledge proof error type
#[derive(Debug, Error)]
pub enum ZkError {
    /// Invalid input data
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Proof generation failed
    #[error("Proof generation failed: {0}")]
    ProofGeneration(String),

    /// Proof verification failed
    #[error("Proof verification failed: {0}")]
    ProofVerification(String),

    /// Circuit compilation failed
    #[error("Circuit compilation failed: {0}")]
    CircuitCompilation(String),

    /// Backend-specific error
    #[error("Backend error: {0}")]
    Backend(String),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

impl From<ZkError> for String {
    fn from(err: ZkError) -> String {
        err.to_string()
    }
} 