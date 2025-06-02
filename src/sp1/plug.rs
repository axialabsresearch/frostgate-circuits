use async_trait::async_trait;
use frostgate_zkip::zkplug::*;
use std::sync::{Arc, RwLock};
use std::time::Instant;
use std::collections::HashMap;
use tokio::sync::Semaphore;
use sp1_core_machine::io::SP1Stdin;
use sp1_prover::{SP1Prover, components::CpuProverComponents};
use crate::sp1::{
    types::*,
    utils::{ProgramCache, validate_input},
    prover::{setup_program, generate_proof, execute_program},
    verifier::verify_proof_unified,
};

pub struct Sp1Plug {
    backend: Sp1Backend,
    config: Sp1PlugConfig,
    programs: RwLock<ProgramCache>,
    semaphore: Arc<Semaphore>,
}

impl std::fmt::Debug for Sp1Plug {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sp1Plug")
            .field("config", &self.config)
            .field("program_count", &self.programs.read().unwrap().len())
            .finish()
    }
}

impl Sp1Plug {
    pub fn new(config: Option<Sp1PlugConfig>) -> Self {
        let config = config.unwrap_or_default();
        let backend = if config.use_network {
            let api_key = config
                .network_api_key
                .as_deref()
                .unwrap_or_else(|| panic!("SP1 network API key required"));
            let endpoint = config
                .network_endpoint
                .as_deref()
                .unwrap_or("https://api.sp1.giza.io");
            Sp1Backend::Network(sp1_sdk::NetworkProver::new(api_key, endpoint))
        } else {
            Sp1Backend::Local(sp1_sdk::EnvProver::new())
        };
        let max_concurrent = config.max_concurrent.unwrap_or_else(num_cpus::get);
        let cache_config = config.cache_config.clone();
        Self {
            backend,
            config,
            programs: RwLock::new(ProgramCache::new(cache_config)),
            semaphore: Arc::new(Semaphore::new(max_concurrent)),
        }
    }

    fn get_program_info(&self, hash: &str) -> Result<ProgramInfo, Sp1PlugError> {
        self.programs
            .write()
            .unwrap()
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
        public_inputs: Option<&[u8]>,
        _config: Option<&ZkConfig>,
    ) -> ZkResult<ZkProof<Self::Proof>, Self::Error> {
        validate_input(input, Some(100 * 1024 * 1024))
            .map_err(|e| Sp1PlugError::Input(e.to_string()))?;
        let program_hash = setup_program(&self.backend, &mut self.programs.write().unwrap(), input).await?;
        let info = self.get_program_info(&program_hash)?;

        let mut stdin = SP1Stdin::new();
        if let Some(pub_inputs) = public_inputs {
            stdin.write_slice(pub_inputs);
        }

        let _permit = self.semaphore.acquire().await.unwrap();
        let start = Instant::now();

        let proof = generate_proof(&self.backend, &info.proving_key, &stdin).await?;
        let duration = start.elapsed();

        let proof_type = Sp1ProofType::Core(proof);

        let metadata = ProofMetadata {
            timestamp: std::time::SystemTime::now(),
            generation_time: duration,
            proof_size: bincode::serialize(&proof_type).map(|v| v.len()).unwrap_or(0),
            backend_id: self.id().to_string(),
            circuit_hash: Some(program_hash),
            custom_fields: HashMap::new(),
        };

        Ok(ZkProof {
            proof: proof_type,
            metadata,
        })
    }

    async fn verify(
        &self,
        proof: &ZkProof<Self::Proof>,
        _public_inputs: Option<&[u8]>,
        _config: Option<&ZkConfig>,
    ) -> ZkResult<bool, Self::Error> {
        let program_hash = proof
            .metadata
            .circuit_hash
            .as_ref()
            .ok_or_else(|| Sp1PlugError::Input("Missing program hash".to_string()))?;
        let info = self.get_program_info(program_hash)?;

        verify_proof_unified(&self.backend, &proof.proof, &info.verifying_key, self.get_build_dir()).await
    }

    async fn execute(
        &self,
        program: &[u8],
        input: &[u8],
        public_inputs: Option<&[u8]>,
        _config: Option<&ZkConfig>,
    ) -> ZkResult<ExecutionResult<Self::Proof>, Self::Error> {
        let program_hash = setup_program(&self.backend, &mut self.programs.write().unwrap(), program).await?;
        let info = self.get_program_info(&program_hash)?;

        let mut stdin = SP1Stdin::new();
        stdin.write_slice(input);
        if let Some(pub_inputs) = public_inputs {
            stdin.write_slice(pub_inputs);
        }

        let start = Instant::now();

        let (output, report) = execute_program(&self.backend, &info.elf, &stdin).await?;
        let exec_time = start.elapsed();

        let stats = ExecutionStats {
            steps: report.total_instruction_count() as u64,
            memory_usage: 0,
            execution_time: exec_time,
            gas_used: Some(report.total_instruction_count() as u64),
        };

        let proof = self.prove(program, public_inputs, None).await?;

        let output_bytes = bincode::serialize(&output)
            .map_err(|e| Sp1PlugError::Execution(format!("Serialization error: {:?}", e)))?;

        Ok(ExecutionResult {
            output: output_bytes,
            proof,
            stats,
        })
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
        let cache_len = self.programs.read().unwrap().len();
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
        self.programs.write().unwrap().clear();
        Ok(())
    }
}