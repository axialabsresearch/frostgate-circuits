use sha3::{Digest, Keccak256};
use sp1_core_machine::io::SP1Stdin;
use sp1_sdk::{SP1ProvingKey, SP1VerifyingKey};
use crate::sp1::types::{ProgramInfo, Sp1PlugError, Sp1Backend};
use crate::sp1::utils::ProgramCache;

pub async fn setup_program(
    backend: &Sp1Backend,
    cache: &mut ProgramCache,
    elf: &[u8],
) -> Result<String, Sp1PlugError> {
    let program_hash = hex::encode(Keccak256::digest(elf));
    
    // Check cache first
    if cache.len() > 0 {
        if let Some(_) = cache.get(&program_hash) {
            return Ok(program_hash);
        }
    }
    
    let (proving_key, verifying_key) = match backend {
        Sp1Backend::Local(prover) => prover.setup(elf),
        Sp1Backend::Network(prover) => prover.setup(elf),
    };
    
    let info = ProgramInfo {
        elf: elf.to_vec(),
        proving_key,
        verifying_key,
        program_hash: program_hash.clone(),
        compiled_at: std::time::SystemTime::now(),
        last_accessed: std::time::SystemTime::now(),
        access_count: 0,
    };
    
    cache.insert(program_hash.clone(), info);
    Ok(program_hash)
}

pub async fn generate_proof(
    backend: &Sp1Backend,
    proving_key: &SP1ProvingKey,
    stdin: &SP1Stdin,
) -> Result<sp1_sdk::SP1ProofWithPublicValues, Sp1PlugError> {
    match backend {
        Sp1Backend::Local(prover) => {
            prover.prove(proving_key, stdin)
                .run()
                .map_err(|e| Sp1PlugError::Proof(format!("{:?}", e)))
        }
        Sp1Backend::Network(prover) => {
            prover.prove(proving_key, stdin)
                .run()
                .map_err(|e| Sp1PlugError::Proof(format!("{:?}", e)))
        }
    }
}

pub async fn execute_program(
    backend: &Sp1Backend,
    elf: &[u8],
    stdin: &SP1Stdin,
) -> Result<(Vec<u8>, sp1_sdk::SP1Report), Sp1PlugError> {
    match backend {
        Sp1Backend::Local(prover) => {
            prover.execute(elf, stdin)
                .run()
                .map_err(|e| Sp1PlugError::Execution(format!("{:?}", e)))
        }
        Sp1Backend::Network(prover) => {
            prover.execute(elf, stdin)
                .run()
                .map_err(|e| Sp1PlugError::Execution(format!("{:?}", e)))
        }
    }
}
