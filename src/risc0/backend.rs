//! RISC0 backend implementation

use std::sync::Arc;
use std::time::{Duration, SystemTime};
use async_trait::async_trait;
use risc0_zkvm::{
    Prover, ProverOpts, Receipt,
    ExecutorEnv, ExecutorEnvBuilder,
};
use tokio::sync::RwLock;
use rayon::prelude::*;
use frostgate_zkip::{
    ZkBackend, ZkBackendExt, ZkError, ZkResult,
    HealthStatus, ProofMetadata, ResourceUsage, ZkConfig, ZkStats,
};

use super::types::{Risc0Circuit, Risc0Options};
use super::circuit::{MessageVerifyCircuit, TxVerifyCircuit, BlockVerifyCircuit};
use super::cache::{CircuitCache, CacheConfig, CacheStats};

/// RISC0 backend implementation
pub struct Risc0Backend {
    /// Backend statistics
    stats: Arc<RwLock<ZkStats>>,
    /// Current resource usage
    resources: Arc<RwLock<ResourceUsage>>,
    /// RISC0-specific options
    options: Risc0Options,
    /// Circuit and proof cache
    cache: Arc<CircuitCache>,
}

impl Risc0Backend {
    /// Create a new RISC0 backend with default configuration
    pub fn new() -> Self {
        Self {
            stats: Arc::new(RwLock::new(ZkStats::default())),
            resources: Arc::new(RwLock::new(ResourceUsage {
                cpu_usage: 0.0,
                memory_usage: 0,
                active_tasks: 0,
                max_concurrent: 4,
                queue_depth: 0,
            })),
            options: Risc0Options {
                num_threads: Some(4),
                memory_limit: Some(1024 * 1024 * 1024), // 1GB
                prover_opts: None,
            },
            cache: Arc::new(CircuitCache::new(CacheConfig::default())),
        }
    }

    /// Create a new RISC0 backend with custom configuration
    pub fn with_config(options: Risc0Options, cache_config: CacheConfig) -> Self {
        Self {
            stats: Arc::new(RwLock::new(ZkStats::default())),
            resources: Arc::new(RwLock::new(ResourceUsage {
                cpu_usage: 0.0,
                memory_usage: 0,
                active_tasks: 0,
                max_concurrent: options.num_threads.unwrap_or(4),
                queue_depth: 0,
            })),
            options,
            cache: Arc::new(CircuitCache::new(cache_config)),
        }
    }

    /// Update statistics after a proving operation
    async fn update_proving_stats(&self, duration: Duration, success: bool) {
        let mut stats = self.stats.write().await;
        stats.total_proofs += 1;
        if !success {
            stats.total_failures += 1;
        }
        
        // Update average proving time
        let total_proofs = stats.total_proofs as u32;
        stats.avg_proving_time = Duration::from_nanos(
            ((stats.avg_proving_time.as_nanos() * (total_proofs - 1) as u128 +
              duration.as_nanos()) / total_proofs as u128) as u64
        );
    }

    /// Update statistics after a verification operation
    async fn update_verification_stats(&self, duration: Duration, success: bool) {
        let mut stats = self.stats.write().await;
        stats.total_verifications += 1;
        if !success {
            stats.total_failures += 1;
        }
        
        // Update average verification time
        let total_verifications = stats.total_verifications as u32;
        stats.avg_verification_time = Duration::from_nanos(
            ((stats.avg_verification_time.as_nanos() * (total_verifications - 1) as u128 +
              duration.as_nanos()) / total_verifications as u128) as u64
        );
    }

    /// Create a circuit from program bytes and input
    fn create_circuit(&self, program: &[u8], input: &[u8]) -> ZkResult<Box<dyn Risc0Circuit>> {
        // Check cache first
        if let Some(entry) = self.cache.get_circuit(program) {
            let circuit = match program[0] {
                0x01 => {
                    let mut expected_hash = [0u8; 32];
                    expected_hash.copy_from_slice(&program[1..33]);
                    Box::new(MessageVerifyCircuit::new(
                        input.to_vec(),
                        expected_hash,
                        entry.elf_bytes,
                    ))
                }
                0x02 => {
                    let mut expected_hash = [0u8; 32];
                    expected_hash.copy_from_slice(&program[1..33]);
                    Box::new(TxVerifyCircuit::new(
                        input.to_vec(),
                        expected_hash,
                        entry.elf_bytes,
                    ))
                }
                0x03 => {
                    let mut expected_hash = [0u8; 32];
                    let mut expected_number = [0u8; 8];
                    expected_hash.copy_from_slice(&program[1..33]);
                    expected_number.copy_from_slice(&program[33..41]);
                    Box::new(BlockVerifyCircuit::new(
                        input.to_vec(),
                        expected_hash,
                        u64::from_le_bytes(expected_number),
                        entry.elf_bytes,
                    ))
                }
                _ => return Err(ZkError::InvalidInput("Unknown circuit type".into())),
            };
            return Ok(circuit);
        }

        // Not in cache, create new circuit
        let start = SystemTime::now();
        let circuit = match program[0] {
            0x01 => {
                let mut expected_hash = [0u8; 32];
                if program.len() < 33 {
                    return Err(ZkError::InvalidInput("Program too short for message verification".into()));
                }
                expected_hash.copy_from_slice(&program[1..33]);
                Box::new(MessageVerifyCircuit::new(
                    input.to_vec(),
                    expected_hash,
                    program[33..].to_vec(),
                ))
            }
            0x02 => {
                let mut expected_hash = [0u8; 32];
                if program.len() < 33 {
                    return Err(ZkError::InvalidInput("Program too short for transaction verification".into()));
                }
                expected_hash.copy_from_slice(&program[1..33]);
                Box::new(TxVerifyCircuit::new(
                    input.to_vec(),
                    expected_hash,
                    program[33..].to_vec(),
                ))
            }
            0x03 => {
                let mut expected_hash = [0u8; 32];
                let mut expected_number = [0u8; 8];
                if program.len() < 41 {
                    return Err(ZkError::InvalidInput("Program too short for block verification".into()));
                }
                expected_hash.copy_from_slice(&program[1..33]);
                expected_number.copy_from_slice(&program[33..41]);
                Box::new(BlockVerifyCircuit::new(
                    input.to_vec(),
                    expected_hash,
                    u64::from_le_bytes(expected_number),
                    program[41..].to_vec(),
                ))
            }
            _ => return Err(ZkError::InvalidInput("Unknown circuit type".into())),
        };

        // Store in cache
        let compile_time = start.elapsed().unwrap();
        self.cache.store_circuit(program, circuit.elf().to_vec(), compile_time);

        Ok(circuit)
    }

    /// Create executor environment for a circuit
    fn create_env(&self, circuit: &dyn Risc0Circuit) -> ExecutorEnv {
        let mut builder = ExecutorEnvBuilder::default();
        
        // Add public inputs
        for input in circuit.public_inputs() {
            builder.add_input(input);
        }
        
        // Add private inputs
        builder.write_slice(&circuit.private_inputs());
        
        builder.build().unwrap()
    }
}

#[async_trait]
impl ZkBackend for Risc0Backend {
    async fn prove(
        &self,
        program: &[u8],
        input: &[u8],
        config: Option<&ZkConfig>,
    ) -> ZkResult<(Vec<u8>, ProofMetadata)> {
        let start = SystemTime::now();
        
        // Check proof cache first
        if let Some(entry) = self.cache.get_proof(program, input) {
            return Ok((entry.proof, ProofMetadata {
                generation_time: entry.generation_time,
                proof_size: entry.proof.len(),
                program_hash: hex::encode(&entry.program_hash),
                timestamp: start,
            }));
        }
        
        // Update resource tracking
        {
            let mut resources = self.resources.write().await;
            resources.active_tasks += 1;
        }

        // Create circuit
        let circuit = self.create_circuit(program, input)?;
        
        // Create prover
        let prover = Prover::new(circuit.elf(), self.options.prover_opts.clone().unwrap_or_default())
            .map_err(|e| ZkError::ProverError(format!("Failed to create prover: {}", e)))?;
        
        // Create environment
        let env = self.create_env(circuit.as_ref());
        
        // Generate proof
        let receipt = prover.prove(env)
            .map_err(|e| ZkError::ProverError(format!("Proof generation failed: {}", e)))?;
        
        // Verify circuit-specific conditions
        if !circuit.verify_receipt(&receipt) {
            return Err(ZkError::VerificationError("Circuit verification failed".into()));
        }
        
        // Serialize receipt
        let proof = bincode::serialize(&receipt)
            .map_err(|e| ZkError::SerializationError(format!("Failed to serialize receipt: {}", e)))?;
        
        // Create metadata
        let duration = start.elapsed().unwrap_or_default();
        let metadata = ProofMetadata {
            generation_time: duration,
            proof_size: proof.len(),
            program_hash: hex::encode(circuit.elf()),
            timestamp: start,
        };

        // Store in cache
        self.cache.store_proof(program, input, proof.clone(), duration);

        // Update stats
        self.update_proving_stats(duration, true).await;
        
        // Update resource tracking
        {
            let mut resources = self.resources.write().await;
            resources.active_tasks -= 1;
        }

        Ok((proof, metadata))
    }

    async fn verify(
        &self,
        program: &[u8],
        proof: &[u8],
        config: Option<&ZkConfig>,
    ) -> ZkResult<bool> {
        let start = SystemTime::now();
        
        // Update resource tracking
        {
            let mut resources = self.resources.write().await;
            resources.active_tasks += 1;
        }

        // Create circuit
        let circuit = self.create_circuit(program, &[])?;
        
        // Deserialize receipt
        let receipt: Receipt = bincode::deserialize(proof)
            .map_err(|e| ZkError::SerializationError(format!("Failed to deserialize receipt: {}", e)))?;
        
        // Verify receipt
        let result = receipt.verify(circuit.elf())
            .map_err(|e| ZkError::VerificationError(format!("Receipt verification failed: {}", e)))?;
        
        // Verify circuit-specific conditions
        let result = result && circuit.verify_receipt(&receipt);
        
        // Update stats
        self.update_verification_stats(start.elapsed().unwrap_or_default(), result).await;
        
        // Update resource tracking
        {
            let mut resources = self.resources.write().await;
            resources.active_tasks -= 1;
        }

        Ok(result)
    }

    fn resource_usage(&self) -> ResourceUsage {
        futures::executor::block_on(async {
            self.resources.read().await.clone()
        })
    }

    async fn health_check(&self) -> HealthStatus {
        let resources = self.resources.read().await;
        if resources.cpu_usage > 90.0 {
            HealthStatus::Degraded("High CPU usage".into())
        } else if resources.memory_usage > self.options.memory_limit.unwrap_or(usize::MAX) {
            HealthStatus::Degraded("High memory usage".into())
        } else {
            HealthStatus::Healthy
        }
    }

    fn stats(&self) -> ZkStats {
        futures::executor::block_on(async {
            self.stats.read().await.clone()
        })
    }

    async fn clear_cache(&mut self) -> ZkResult<()> {
        self.cache.clear_all();
        Ok(())
    }

    fn capabilities(&self) -> Vec<String> {
        vec![
            "parallel_proving".into(),
            "batch_verification".into(),
            "custom_programs".into(),
            "deterministic_proofs".into(),
            "circuit_caching".into(),
            "proof_caching".into(),
        ]
    }
}

#[async_trait]
impl ZkBackendExt for Risc0Backend {
    async fn batch_prove(
        &self,
        programs: &[(&[u8], &[u8])],
        config: Option<&ZkConfig>,
    ) -> ZkResult<Vec<(Vec<u8>, ProofMetadata)>> {
        let start = SystemTime::now();
        let thread_pool = rayon::ThreadPoolBuilder::new()
            .num_threads(self.options.num_threads.unwrap_or(4))
            .build()?;

        // Update resource tracking
        {
            let mut resources = self.resources.write().await;
            resources.active_tasks += programs.len();
            resources.queue_depth = programs.len();
        }

        // Generate proofs in parallel
        let results: Vec<ZkResult<(Vec<u8>, ProofMetadata)>> = thread_pool.install(|| {
            programs.par_iter().map(|(program, input)| {
                let circuit = self.create_circuit(program, input)?;
                let proof_start = SystemTime::now();
                
                // Create prover
                let prover = Prover::new(circuit.elf(), self.options.prover_opts.clone().unwrap_or_default())
                    .map_err(|e| ZkError::ProverError(format!("Failed to create prover: {}", e)))?;
                
                // Create environment
                let env = self.create_env(circuit.as_ref());
                
                // Generate proof
                let receipt = prover.prove(env)
                    .map_err(|e| ZkError::ProverError(format!("Proof generation failed: {}", e)))?;
                
                // Verify circuit-specific conditions
                if !circuit.verify_receipt(&receipt) {
                    return Err(ZkError::VerificationError("Circuit verification failed".into()));
                }
                
                // Serialize receipt
                let proof = bincode::serialize(&receipt)
                    .map_err(|e| ZkError::SerializationError(format!("Failed to serialize receipt: {}", e)))?;
                
                let duration = proof_start.elapsed().unwrap_or_default();
                Ok((proof, ProofMetadata {
                    generation_time: duration,
                    proof_size: proof.len(),
                    program_hash: hex::encode(circuit.elf()),
                    timestamp: proof_start,
                }))
            }).collect()
        });

        // Update stats
        self.update_proving_stats(
            start.elapsed().unwrap_or_default(),
            results.iter().all(|r| r.is_ok()),
        ).await;

        // Update resource tracking
        {
            let mut resources = self.resources.write().await;
            resources.active_tasks -= programs.len();
            resources.queue_depth = 0;
        }

        // Collect results
        results.into_iter().collect()
    }

    async fn batch_verify(
        &self,
        verifications: &[(&[u8], &[u8])],
        config: Option<&ZkConfig>,
    ) -> ZkResult<Vec<bool>> {
        let start = SystemTime::now();
        let thread_pool = rayon::ThreadPoolBuilder::new()
            .num_threads(self.options.num_threads.unwrap_or(4))
            .build()?;

        // Update resource tracking
        {
            let mut resources = self.resources.write().await;
            resources.active_tasks += verifications.len();
            resources.queue_depth = verifications.len();
        }

        // Verify proofs in parallel
        let results: Vec<ZkResult<bool>> = thread_pool.install(|| {
            verifications.par_iter().map(|(program, proof)| {
                let circuit = self.create_circuit(program, &[])?;
                
                // Deserialize receipt
                let receipt: Receipt = bincode::deserialize(proof)
                    .map_err(|e| ZkError::SerializationError(format!("Failed to deserialize receipt: {}", e)))?;
                
                // Verify receipt
                let result = receipt.verify(circuit.elf())
                    .map_err(|e| ZkError::VerificationError(format!("Receipt verification failed: {}", e)))?;
                
                // Verify circuit-specific conditions
                Ok(result && circuit.verify_receipt(&receipt))
            }).collect()
        });

        // Update stats
        self.update_verification_stats(
            start.elapsed().unwrap_or_default(),
            results.iter().all(|r| r.is_ok()),
        ).await;

        // Update resource tracking
        {
            let mut resources = self.resources.write().await;
            resources.active_tasks -= verifications.len();
            resources.queue_depth = 0;
        }

        // Collect results
        results.into_iter().collect()
    }
} 