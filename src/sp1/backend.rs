#![allow(unused_imports)]
#![allow(unused_variables)]

//! SP1 backend implementation

use std::sync::Arc;
use std::time::{Duration, SystemTime};
use async_trait::async_trait;
use sp1_sdk::{
    ProverClient, SP1Stdin, SP1ProofWithPublicValues, CpuProver, SP1ProvingKey,
    SP1VerifyingKey, Prover,
};
use tokio::sync::RwLock;
use rayon::prelude::*;
use frostgate_zkip::{
    ZkBackend, ZkBackendExt, ZkError, ZkResult,
    HealthStatus, ProofMetadata, ResourceUsage, ZkConfig, ZkStats,
};
use std::fmt;
use std::path::Path;
use futures::TryFutureExt;

use super::types::{Sp1Circuit, Sp1Options};
use super::circuit::MessageVerifyCircuit;
use super::cache::{CircuitCache, CacheConfig, CacheStats};

// Create a newtype wrapper for CpuProver to implement Debug
pub struct DebugCpuProver(CpuProver);

impl DebugCpuProver {
    pub fn new() -> Self {
        Self(CpuProver::new())
    }

    pub fn inner(&self) -> &CpuProver {
        &self.0
    }
}

impl fmt::Debug for DebugCpuProver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DebugCpuProver").finish()
    }
}

/// SP1 backend implementation
#[derive(Debug)]
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
    pub client: DebugCpuProver,
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
            client: DebugCpuProver::new(),
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
            client: DebugCpuProver::new(),
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

    async fn prove_internal(&self, program: &[u8], input: &[u8]) -> ZkResult<Vec<u8>> {
        // Create stdin and write input
        let mut stdin = SP1Stdin::new();
        stdin.write_slice(input);
        
        // Create proving key and verifying key
        let (proving_key, verifying_key) = self.client.inner().setup(program);
        
        // Generate proof
        let proof = self.client.inner().prove(&proving_key, &stdin)
            .run()
            .map_err(|e| ZkError::Backend(format!("Proof generation failed: {}", e)))?;
        
        Ok(proof.bytes().to_vec())
    }

    async fn verify_internal(&self, program: &[u8], proof: &[u8]) -> ZkResult<bool> {
        // Create proving key and verifying key
        let (proving_key, verifying_key) = self.client.inner().setup(program);
        
        // Parse proof - create a temporary file since load requires a path
        let temp_dir = std::env::temp_dir();
        let temp_path = temp_dir.join("proof.tmp");
        std::fs::write(&temp_path, proof)
            .map_err(|e| ZkError::Backend(format!("Failed to write proof to temp file: {}", e)))?;
        
        let proof = SP1ProofWithPublicValues::load(&temp_path)
            .map_err(|e| ZkError::Backend(format!("Failed to parse proof: {}", e)))?;
        
        // Clean up temp file
        let _ = std::fs::remove_file(temp_path);
        
        // Verify proof
        match self.client.inner().verify(&proof, &verifying_key) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false)
        }
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
            let proof = entry.proof.clone();
            return Ok((proof.clone(), ProofMetadata {
                generation_time: entry.generation_time,
                proof_size: proof.len(),
                program_hash: hex::encode(&entry.program_hash),
                timestamp: start,
            }));
        }
        
        // Update resource tracking
        {
            let mut resources = self.resources.write().await;
            resources.active_tasks += 1;
        }

        // Generate proof
        let proof_bytes = self.prove_internal(program, input).await?;
        
        // Create metadata
        let duration = start.elapsed().unwrap_or_default();
        let metadata = ProofMetadata {
            generation_time: duration,
            proof_size: proof_bytes.len(),
            program_hash: hex::encode(program),
            timestamp: start,
        };

        // Store in cache
        self.cache.store_proof(program, input, proof_bytes.clone(), duration);
        
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
        
        // Verify proof
        let result = self.verify_internal(program, proof).await?;
        
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
            .map_err(|e| ZkError::Backend(format!("Failed to create thread pool: {}", e)))?;

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
                
                // Create proving key and verifying key
                let (proving_key, verifying_key) = self.client.inner().setup(program);

                let proof = self.client.inner().prove(&proving_key, &stdin)
                    .run()
                    .map_err(|e| ZkError::Backend(format!("Proof generation failed: {}", e)))?;
                
                // Get proof bytes and their size
                let proof_bytes = proof.bytes().to_vec();
                let proof_size = proof_bytes.len();
                
                let duration = proof_start.elapsed().unwrap_or_default();
                Ok((proof_bytes, ProofMetadata {
                    generation_time: duration,
                    proof_size,
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
        let thread_pool = rayon::ThreadPoolBuilder::new()
            .num_threads(self.options.num_threads.unwrap_or(4))
            .build()
            .map_err(|e| ZkError::Backend(format!("Failed to create thread pool: {}", e)))?;

        // Verify proofs in parallel
        let results: Vec<ZkResult<bool>> = thread_pool.install(|| {
            verifications.par_iter().map(|(program, proof)| {
                let (proving_key, verifying_key) = self.client.inner().setup(program);
                
                // Parse proof - create a temporary file since load requires a path
                let temp_dir = std::env::temp_dir();
                let temp_path = temp_dir.join("proof.tmp");
                std::fs::write(&temp_path, proof)
                    .map_err(|e| ZkError::Backend(format!("Failed to write proof to temp file: {}", e)))?;
                
                let proof = SP1ProofWithPublicValues::load(&temp_path)
                    .map_err(|e| ZkError::Backend(format!("Failed to parse proof: {}", e)))?;
                
                // Clean up temp file
                let _ = std::fs::remove_file(temp_path);
                
                // Verify proof
                match self.client.inner().verify(&proof, &verifying_key) {
                    Ok(_) => Ok(true),
                    Err(_) => Ok(false)
                }
            }).collect()
        });

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