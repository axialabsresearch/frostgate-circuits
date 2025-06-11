//! SP1 backend implementation

use std::sync::Arc;
use std::time::{Duration, SystemTime};
use async_trait::async_trait;
use sp1_core::{SP1Prover, SP1ProverOpts};
use tokio::sync::RwLock;
use rayon::prelude::*;
use frostgate_zkip::{
    ZkBackend, ZkBackendExt, ZkError, ZkResult,
    HealthStatus, ProofMetadata, ResourceUsage, ZkConfig, ZkStats,
};

use super::types::{Sp1Circuit, Sp1Options};
use super::circuit::{MessageVerifyCircuit, TxVerifyCircuit, BlockVerifyCircuit};
use super::cache::{CircuitCache, CacheConfig, CacheStats};

/// SP1 backend implementation
pub struct Sp1Backend {
    /// Backend statistics
    stats: Arc<RwLock<ZkStats>>,
    /// Current resource usage
    resources: Arc<RwLock<ResourceUsage>>,
    /// SP1-specific options
    options: Sp1Options,
    /// Circuit and proof cache
    cache: Arc<CircuitCache>,
}

impl Sp1Backend {
    /// Create a new SP1 backend with default configuration
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
            options: Sp1Options {
                num_threads: Some(4),
                memory_limit: Some(1024 * 1024 * 1024), // 1GB
                prover_opts: None,
            },
            cache: Arc::new(CircuitCache::new(CacheConfig::default())),
        }
    }

    /// Create a new SP1 backend with custom configuration
    pub fn with_config(options: Sp1Options, cache_config: CacheConfig) -> Self {
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
    fn create_circuit(&self, program: &[u8], input: &[u8]) -> ZkResult<Box<dyn Sp1Circuit>> {
        // Check cache first
        if let Some(entry) = self.cache.get_circuit(program) {
            let circuit = match program[0] {
                0x01 => {
                    let mut expected_hash = [0u8; 32];
                    expected_hash.copy_from_slice(&program[1..33]);
                    Box::new(MessageVerifyCircuit::new(
                        input.to_vec(),
                        expected_hash,
                        entry.circuit_bytes,
                    ))
                }
                0x02 => {
                    let mut expected_hash = [0u8; 32];
                    expected_hash.copy_from_slice(&program[1..33]);
                    Box::new(TxVerifyCircuit::new(
                        input.to_vec(),
                        expected_hash,
                        entry.circuit_bytes,
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
                        entry.circuit_bytes,
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
        self.cache.store_circuit(program, circuit.program().to_vec(), compile_time);

        Ok(circuit)
    }
}

#[async_trait]
impl ZkBackend for Sp1Backend {
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
        let prover = SP1Prover::new(circuit.program(), self.options.prover_opts.clone().unwrap_or_default())
            .map_err(|e| ZkError::ProverError(format!("Failed to create prover: {}", e)))?;
        
        // Generate proof
        let proof = prover.prove(circuit.as_ref())
            .map_err(|e| ZkError::ProverError(format!("Proof generation failed: {}", e)))?;
        
        // Verify circuit-specific conditions
        if !circuit.verify_proof(&proof) {
            return Err(ZkError::VerificationError("Circuit verification failed".into()));
        }
        
        // Serialize proof
        let proof_bytes = bincode::serialize(&proof)
            .map_err(|e| ZkError::SerializationError(format!("Failed to serialize proof: {}", e)))?;
        
        // Create metadata
        let duration = start.elapsed().unwrap_or_default();
        let metadata = ProofMetadata {
            generation_time: duration,
            proof_size: proof_bytes.len(),
            program_hash: hex::encode(circuit.program()),
            timestamp: start,
        };

        // Store in cache
        self.cache.store_proof(program, input, proof_bytes.clone(), duration);

        // Update stats
        self.update_proving_stats(duration, true).await;
        
        // Update resource tracking
        {
            let mut resources = self.resources.write().await;
            resources.active_tasks -= 1;
        }

        Ok((proof_bytes, metadata))
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
        
        // Verify proof
        let result = circuit.verify(&self.verifier, proof);
        
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
impl ZkBackendExt for Sp1Backend {
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
                let proof = circuit.prove(&self.prover);
                let duration = proof_start.elapsed().unwrap_or_default();
                
                Ok((proof, ProofMetadata {
                    generation_time: duration,
                    proof_size: proof.len(),
                    program_hash: hex::encode(circuit.program()),
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
                Ok(circuit.verify(&self.verifier, proof))
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

    async fn clear_cache(&mut self) -> ZkResult<()> {
        self.cache.clear_all();
        Ok(())
    }

    fn capabilities(&self) -> Vec<String> {
        vec![
            "parallel_proving".into(),
            "batch_verification".into(),
            "custom_programs".into(),
        ]
    }
} 