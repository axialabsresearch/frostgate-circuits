pub mod sp1;

pub use sp1::{
    Sp1Plug,
    Sp1PlugConfig,
    Sp1ProofType,
    Sp1PlugError,
};

// Re-export commonly used types for convenience
pub type SP1Proof = Sp1ProofType;
pub type SP1Config = Sp1PlugConfig;
pub type SP1Error = Sp1PlugError;
