#![allow(unused_imports)]
#![allow(unused_variables)]

//! SP1 backend implementation

use std::sync::Arc;
use std::time::{Duration, SystemTime};
use async_trait::async_trait;
use sp1_sdk::{ProverClient, SP1Stdin, SP1ProofWithPublicValues, CpuProver};
use tokio::sync::RwLock;
use rayon::prelude::*;
use frostgate_zkip::{
    ZkBackend, ZkBackendExt, ZkError, ZkResult,
    HealthStatus, ProofMetadata, ResourceUsage, ZkConfig, ZkStats,
};

use super::types::{Sp1Circuit, Sp1Options};
use super::circuit::MessageVerifyCircuit;
use super::cache::{CircuitCache, CacheConfig, CacheStats};

/// SP1 backend implementation
#[derive(Debug, Clone)]
pub struct Sp1Backend {
    /// Backend statistics
    pub stats: Arc<RwLock<ZkStats>>,
    /// Current resource usage
    pub resources: Arc<RwLock<ResourceUsage>>,
    /// SP1-specific options
    pub options: Sp1Options,
    /// Circuit and proof cache
    pub cache: Arc<CircuitCache>,
    /// SP1 prover client
    #[allow(dead_code)]
    client: CpuProver,
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
                custom_params: None,
            },
            cache: Arc::new(CircuitCache::new(CacheConfig::default())),
            client: CpuProver::new(),
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
            client: CpuProver::new(),
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

    /// Create a circuit from program and input
    fn create_circuit(&self, program: &[u8], input: &[u8]) -> Result<MessageVerifyCircuit, frostgate_zkip::ZkError> {
        // For now, we only support message verification circuits
        if program.is_empty() || program[0] != 0x01 {
            return Err(frostgate_zkip::ZkError::Program("Unsupported circuit type".into()));
        }
        
        // Extract expected hash from program
        if program.len() < 33 {
            return Err(frostgate_zkip::ZkError::Program("Invalid program format".into()));
        }
        let expected_hash: [u8; 32] = program[1..33].try_into()
            .map_err(|_| frostgate_zkip::ZkError::Program("Invalid hash format".into()))?;
        
        // Create circuit
        MessageVerifyCircuit::new(input.to_vec(), expected_hash)
            .map_err(|e| frostgate_zkip::ZkError::Program(e.to_string()))
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
        
        // Create stdin and write input
        let mut stdin = SP1Stdin::new();
        stdin.write_slice(input);
        
        // Generate proof
        let proof = self.client.prove(program, &stdin)
            .map_err(|e| ZkError::ProofGeneration(format!("Proof generation failed: {}", e)))?;
        
        // Serialize proof
        let proof_bytes = proof.bytes();
        
        // Create metadata
        let duration = start.elapsed().unwrap_or_default();
        let metadata = ProofMetadata {
            generation_time: duration,
            proof_size: proof_bytes.len(),
            program_hash: hex::encode(program),
            timestamp: start,
        };

        // Store in cache
        self.cache.store_proof(program, input, &proof_bytes, duration);
        
        // Update resource tracking
        {
            let mut resources = self.resources.write().await;
            resources.active_tasks -= 1;
        }
        
        // Update stats
        self.update_proving_stats(duration, true).await;
        
        Ok((proof_bytes, metadata))
    }

    async fn verify(
        &self,
        program: &[u8],
        proof: &[u8],
        config: Option<&ZkConfig>,
    ) -> ZkResult<bool> {
        let start = SystemTime::now();
        
        // Create circuit
        let circuit = self.create_circuit(program, &[])?;
        
        // Parse proof
        let proof = SP1ProofWithPublicValues::load(proof)
            .map_err(|e| ZkError::VerificationFailed(format!("Failed to parse proof: {}", e)))?;
        
        // Verify the proof
        let result = self.client.verify(program, &proof)
            .map_err(|e| ZkError::VerificationFailed(format!("Proof verification failed: {}", e)))?;
        
        // Update stats
        self.update_verification_stats(start.elapsed().unwrap_or_default(), result).await;
        
        Ok(result)
    }

    fn resource_usage(&self) -> ResourceUsage {
        futures::executor::block_on(async {
            self.resources.read().await.clone()
        })
    }

    async fn health_check(&self) -> HealthStatus {
        let resources = self.resources.read().await;
        let stats = self.stats.read().await;
        
        if resources.active_tasks < resources.max_concurrent {
            HealthStatus::Healthy
        } else {
            HealthStatus::Degraded("High resource usage".into())
        }
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
            .build()
            .map_err(|e| ZkError::Prover(format!("Failed to create thread pool: {}", e)))?;

        // Update resource tracking
        {
            let mut resources = self.resources.write().await;
            resources.active_tasks += programs.len();
            resources.queue_depth = programs.len();
        }

        // Generate proofs in parallel
        let results: Vec<ZkResult<(Vec<u8>, ProofMetadata)>> =
            programs.par_iter().map(|(program, input)| {
                let circuit = self.create_circuit(program, input)?;
                let proof_start = SystemTime::now();
                
                // Create stdin and write input
                let mut stdin = SP1Stdin::new();
                stdin.write(input);
                
                // Generate proof
                let proof = self.client.prove(program, &stdin)
                    .map_err(|e| ZkError::Prover(format!("Proof generation failed: {}", e)))?;
                
                // Serialize proof
                let proof_bytes = proof.bytes();
                
                let duration = proof_start.elapsed().unwrap_or_default();
                Ok((proof_bytes, ProofMetadata {
                    generation_time: duration,
                    proof_size: proof_bytes.len(),
                    program_hash: hex::encode(program),
                    timestamp: proof_start,
                }))
            }).collect();

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
            .build()
            .map_err(|e| ZkError::Prover(format!("Failed to create thread pool: {}", e)))?;

        // Update resource tracking
        {
            let mut resources = self.resources.write().await;
            resources.active_tasks += verifications.len();
            resources.queue_depth = verifications.len();
        }

        // Verify proofs in parallel
        let results: Vec<ZkResult<bool>> = thread_pool.install(|| {
            verifications.par_iter().map(|(program, proof)| {
                // Verify the proof
                self.client.verify(program, proof)
                    .map_err(|e| ZkError::Verification(format!("Proof verification failed: {}", e)))
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

    async fn clear_cache(&mut self) -> Result<(), ZkError> {
        self.cache.clear_all();
        Ok(())
    }

    fn capabilities(&self) -> Vec<String> {
        vec![
            "sp1".to_string(),
            "message_verify".to_string(),
            "tx_verify".to_string(),
            "block_verify".to_string(),
        ]
    }
} 