#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(unused_mut)]
#![allow(unused_must_use)]
#![allow(dead_code)]

use sha3::{Digest, Keccak256};
use sp1_core_machine::io::SP1Stdin;
use sp1_sdk::{SP1ProvingKey, SP1VerifyingKey, Prover, SP1PublicValues, ExecutionReport, SP1ProofWithPublicValues};
use sp1_prover::{SP1Groth16Bn254Proof, SP1PlonkBn254Proof};
use frostgate_zkip::zkplug::{ExecutionResult, ExecutionStats, ZkProof, ProofMetadata};
use std::time::Instant;
use std::collections::HashMap;
use std::path::PathBuf;
use crate::sp1::types::{ProgramInfo, Sp1PlugError, Sp1Backend, Sp1ProofType};
use crate::sp1::utils::ProgramCache;
use bincode;
use sp1_zkvm::SP1Stdin;
use frostgate_lib::zkplug::*;

pub struct Sp1Prover {
    config: Sp1PlugConfig,
}

impl Sp1Prover {
    pub fn new(config: Sp1PlugConfig) -> Self {
        Self { config }
    }

    pub async fn prove(&self, program: &[u8], input: &[u8]) -> Result<Vec<u8>, Sp1PlugError> {
        // Generate program hash for identification
        let program_hash = hex::encode(Keccak256::digest(program));
        
        // Create stdin for the program
        let mut stdin = SP1Stdin::new();
        stdin.write(input);
        
        // Execute the program and generate proof
        let proof = sp1_zkvm::prove(program, stdin)
            .map_err(|e| Sp1PlugError::Proof(e.to_string()))?;
            
        // Serialize the proof
        bincode::serialize(&proof)
            .map_err(|e| Sp1PlugError::Serialization(e.to_string()))
    }
}

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
) -> Result<ExecutionResult<Sp1ProofType>, Sp1PlugError> {
    let start = Instant::now();
    let result = match backend {
        Sp1Backend::Local(prover) => {
            prover.execute(elf, stdin)
                .run()
                .map_err(|e| Sp1PlugError::Execution(format!("{:?}", e)))?
        }
        Sp1Backend::Network(prover) => {
            prover.execute(elf, stdin)
                .run()
                .map_err(|e| Sp1PlugError::Execution(format!("{:?}", e)))?
        }
    };

    let (public_values, report) = result;
    let execution_time = start.elapsed();
    
    // Generate a real proof using the backend
    let (proving_key, _) = match backend {
        Sp1Backend::Local(prover) => prover.setup(elf),
        Sp1Backend::Network(prover) => prover.setup(elf),
    };
    
    let real_proof = generate_proof(backend, &proving_key, stdin).await?;
    
    let proof = ZkProof {
        proof: Sp1ProofType::Core(real_proof),
        metadata: ProofMetadata {
            timestamp: std::time::SystemTime::now(),
            generation_time: execution_time,
            proof_size: 0,
            backend_id: "sp1".to_string(),
            circuit_hash: None,
            custom_fields: HashMap::new(),
        },
    };
    
    Ok(ExecutionResult {
        output: public_values.to_vec(),
        stats: ExecutionStats {
            steps: report.total_instruction_count() as u64,
            memory_usage: (report.total_instruction_count() * 32) as usize, // Convert to usize
            execution_time,
            gas_used: Some(report.total_instruction_count() as u64),
        },
        proof,
    })
}
