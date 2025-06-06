#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(unused_mut)]
#![allow(unused_must_use)]
#![allow(dead_code)]

use async_trait::async_trait;
use frostgate_zkip::zkplug::{
    ZkPlug, ZkProof, ZkResult, ZkConfig, ZkCapability, BackendInfo,
    HealthStatus, ResourceUsage, ExecutionResult, ProofMetadata,
};
use sp1_sdk::{SP1ProofWithPublicValues, SP1ProvingKey, SP1VerifyingKey, Prover};
use sp1_core_machine::io::SP1Stdin;
use tokio::sync::{Semaphore, RwLock};
use std::sync::Arc;
use std::time::Instant;
use std::collections::HashMap;
use sp1_prover::{SP1Prover, components::CpuProverComponents};
use tracing;
use crate::sp1::{
    types::{Sp1Backend, Sp1PlugConfig, Sp1PlugError, Sp1ProofType, ProgramInfo},
    utils::{ProgramCache, validate_input},
    prover::{setup_program, generate_proof, execute_program},
    verifier::verify_proof,
};

pub struct Sp1Plug {
    pub config: Sp1PlugConfig,
    pub backend: Sp1Backend,
    pub programs: Arc<RwLock<ProgramCache>>,
    pub semaphore: Arc<Semaphore>,
}

impl std::fmt::Debug for Sp1Plug {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sp1Plug")
            .field("config", &self.config)
            .field("program_count", &self.programs.blocking_read().len())
            .finish()
    }
}

impl Sp1Plug {
    pub fn new(config: Sp1PlugConfig) -> Self {
        let backend = if config.use_network {
            match (&config.network_api_key, &config.network_endpoint) {
                (Some(api_key), Some(endpoint)) => {
                    Sp1Backend::Network(sp1_sdk::NetworkProver::new(api_key, endpoint))
                }
                (Some(api_key), None) => {
                    // Use default endpoint with API key
                    tracing::warn!("Network proving requested but API key/endpoint missing. Falling back to local prover.");
                    Sp1Backend::Network(sp1_sdk::NetworkProver::new(api_key, "https://sp1.proof.network"))
                }
                _ => {
                    // Fallback to local if network config is incomplete
                    tracing::warn!("Network proving requested but API key/endpoint missing. Falling back to local prover.");
                    Sp1Backend::Local(sp1_sdk::EnvProver::new())
                }
            }
        } else {
            Sp1Backend::Local(sp1_sdk::EnvProver::new())
        };

        let max_concurrent = config.max_concurrent.unwrap_or_else(num_cpus::get);
        let cache_config = config.cache_config.clone();
        
        Self {
            config,
            backend,
            programs: Arc::new(RwLock::new(ProgramCache::new(cache_config))),
            semaphore: Arc::new(Semaphore::new(max_concurrent)),
        }
    }

    async fn get_program_info(&self, hash: &str) -> Result<ProgramInfo, Sp1PlugError> {
        self.programs
            .write()
            .await
            .get(hash)
            .ok_or_else(|| Sp1PlugError::NotFound("Program not found".to_string()))
    }

    fn get_build_dir(&self) -> &std::path::Path {
        self.config.build_dir
            .as_deref()
            .unwrap_or_else(|| std::path::Path::new("."))
    }
}

#[async_trait]
impl ZkPlug for Sp1Plug {
    type Proof = Sp1ProofType;
    type Error = Sp1PlugError;

    async fn prove(
        &self,
        input: &[u8],
        aux_input: Option<&[u8]>,
        config: Option<&ZkConfig>,
    ) -> ZkResult<ZkProof<Self::Proof>, Self::Error> {
        validate_input(input, self.config.max_input_size)
            .map_err(|e| Sp1PlugError::Input(e.to_string()))?;

        // First get the program hash
        let program_hash = {
            let mut programs = self.programs.write().await;
            let hash = setup_program(&self.backend, &mut programs, input).await?;
            hash
        };

        // Then get program info with a read lock
        let program_info = {
            let programs = self.programs.read().await;
            programs.entries()
                .get(&program_hash)
                .ok_or_else(|| Sp1PlugError::NotFound(format!("Program {} not found", program_hash)))?
                .clone()
        };

        let _permit = self.semaphore.acquire().await.unwrap();
        let mut stdin = SP1Stdin::new();
        stdin.write_slice(input);
        if let Some(aux) = aux_input {
            stdin.write_slice(aux);
        }
        
        let proof = generate_proof(&self.backend, &program_info.proving_key, &stdin).await?;
        let start_time = Instant::now();
        let proof_size = bincode::serialize(&proof).map(|v| v.len()).unwrap_or(0);

        Ok(ZkProof {
            proof: Sp1ProofType::Core(proof),
            metadata: ProofMetadata {
                timestamp: std::time::SystemTime::now(),
                generation_time: start_time.elapsed(),
                proof_size,
                backend_id: self.id().to_string(),
                circuit_hash: Some(program_info.program_hash),
                custom_fields: HashMap::new(),
            },
        })
    }

    async fn verify(
        &self,
        proof: &ZkProof<Self::Proof>,
        input: Option<&[u8]>,
        config: Option<&ZkConfig>,
    ) -> ZkResult<bool, Self::Error> {
        if let Some(input) = input {
            validate_input(input, self.config.max_input_size)
                .map_err(|e| Sp1PlugError::Input(e.to_string()))?;
        }

        // First get the program hash
        let program_hash = if let Some(input) = input {
            let mut programs = self.programs.write().await;
            let hash = setup_program(&self.backend, &mut programs, input).await?;
            hash
        } else {
            // If no input provided, use the first available program hash
            let programs = self.programs.read().await;
            programs.entries()
                .keys()
                .next()
                .ok_or_else(|| Sp1PlugError::NotFound("No programs available".to_string()))?
                .clone()
        };

        // Then get program info with a read lock
        let program_info = {
            let programs = self.programs.read().await;
            programs.entries()
                .get(&program_hash)
                .ok_or_else(|| Sp1PlugError::NotFound(format!("Program {} not found", program_hash)))?
                .clone()
        };

        let _permit = self.semaphore.acquire().await.unwrap();
        verify_proof(&self.backend, &proof.proof, &program_info.verifying_key).await
    }

    async fn execute(
        &self,
        input: &[u8],
        program: &[u8],
        aux_input: Option<&[u8]>,
        config: Option<&ZkConfig>,
    ) -> ZkResult<ExecutionResult<Self::Proof>, Self::Error> {
        let _permit = self.semaphore.acquire().await.unwrap();
        
        validate_input(input, self.config.max_input_size)
            .map_err(|e| Sp1PlugError::Input(e.to_string()))?;

        let mut stdin = SP1Stdin::new();
        stdin.write_slice(input);
        if let Some(aux) = aux_input {
            stdin.write_slice(aux);
        }

        let result = execute_program(&self.backend, program, &stdin).await?;
        
        Ok(result)
    }

    async fn get_backend_info(&self) -> BackendInfo {
        BackendInfo {
            id: self.id().to_string(),
            name: "SP1 zkVM".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            capabilities: self.capabilities(),
            health: self.health_check().await,
            resource_usage: self.get_resource_usage().await,
            custom_info: HashMap::new(),
        }
    }

    fn id(&self) -> &'static str {
        "sp1"
    }

    fn capabilities(&self) -> Vec<ZkCapability> {
        vec![
            ZkCapability::VirtualMachine,
            ZkCapability::BatchProving,
            ZkCapability::SuccinctVerification,
            ZkCapability::ZeroKnowledge,
            ZkCapability::Custom("plonk_bn254".to_string()),
            ZkCapability::Custom("groth16_bn254".to_string()),
        ]
    }

    async fn health_check(&self) -> HealthStatus {
        match &self.backend {
            Sp1Backend::Local(_) => {
                match std::panic::catch_unwind(|| SP1Prover::<CpuProverComponents>::new()) {
                    Ok(_) => HealthStatus::Healthy,
                    Err(_) => HealthStatus::Degraded("degraded".to_string()),
                }
            }
            Sp1Backend::Network(_) => {
                if self.config.network_api_key.is_some() {
                    HealthStatus::Healthy
                } else {
                    HealthStatus::Unhealthy("faulty! Unhealthy".to_string())
                }
            }
        }
    }

    async fn get_resource_usage(&self) -> ResourceUsage {
        let cache_len = self.programs.read().await.len();
        let available_permits = self.semaphore.available_permits();
        let max_concurrent = self.config.max_concurrent.unwrap_or_else(num_cpus::get);
        
        ResourceUsage {
            cpu_usage: 0.0,
            memory_usage: cache_len * 1024 * 1024,
            available_memory: 8 * 1024 * 1024 * 1024,
            active_tasks: max_concurrent - available_permits,
            queue_depth: 0,
        }
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn initialize(&mut self, _config: Option<&ZkConfig>) -> ZkResult<(), Self::Error> {
        Ok(())
    }

    async fn shutdown(&mut self) -> ZkResult<(), Self::Error> {
        self.programs.write().await.clear();
        Ok(())
    }
}