#![allow(unused_imports)]
#![allow(unused_variables)]

//! Tests for SP1 backend implementation

use super::*;
use super::backend::DebugCpuProver;
use frostgate_zkip::{ZkBackend, ZkBackendExt};
use sha2::{Sha256, Digest};
use serde_json::json;
use std::time::Duration;

// Add Clone implementation for Sp1Backend
impl Clone for Sp1Backend {
    fn clone(&self) -> Self {
        Self {
            stats: self.stats.clone(),
            resources: self.resources.clone(),
            options: self.options.clone(),
            cache: self.cache.clone(),
            client: DebugCpuProver::new(),
        }
    }
}

#[tokio::test]
async fn test_message_verification() {
    // Create backend
    let backend = Sp1Backend::new();
    
    // Create test message and hash
    let message = b"Hello, World!".to_vec();
    let mut hasher = Sha256::new();
    hasher.update(&message);
    let expected_hash: [u8; 32] = hasher.finalize().as_slice().try_into().unwrap();
    
    // Create program (contains expected hash)
    let mut program = Vec::with_capacity(33);
    program.push(0x01); // Circuit type 1
    program.extend_from_slice(&expected_hash);
    
    // Generate proof
    let (proof, metadata) = backend.prove(&program, &message, None)
        .await
        .expect("Proof generation failed");
    
    // Verify proof
    let result = backend.verify(&program, &proof, None)
        .await
        .expect("Verification failed");
    
    assert!(result, "Proof verification should succeed");
    assert_eq!(metadata.program_hash, hex::encode(program));
}

#[tokio::test]
async fn test_invalid_message() {
    let backend = Sp1Backend::new();
    
    // Create test message and wrong hash
    let message = b"Hello, World!".to_vec();
    let wrong_hash = [0u8; 32];
    
    // Create program with wrong hash
    let mut program = Vec::with_capacity(33);
    program.push(0x01); // Circuit type 1
    program.extend_from_slice(&wrong_hash);
    
    // Generate proof
    let (proof, _) = backend.prove(&program, &message, None)
        .await
        .expect("Proof generation failed");
    
    // Verify proof (should fail)
    let result = backend.verify(&program, &proof, None)
        .await
        .expect("Verification failed");
    
    assert!(!result, "Proof verification should fail with wrong hash");
}

#[tokio::test]
async fn test_batch_operations() {
    let backend = Sp1Backend::new();
    
    // Create multiple test cases
    let messages = vec![
        b"Message 1".to_vec(),
        b"Message 2".to_vec(),
        b"Message 3".to_vec(),
    ];
    
    let mut programs = Vec::new();
    let mut inputs = Vec::new();
    
    for message in &messages {
        let mut hasher = Sha256::new();
        hasher.update(message);
        let hash: [u8; 32] = hasher.finalize().as_slice().try_into().unwrap();
        
        let mut program = Vec::with_capacity(64);
        program.extend_from_slice(&hash);
        program.extend_from_slice(&[0x01; 32]);
        
        programs.push(program);
        inputs.push(message.clone());
    }
    
    // Generate proofs in batch
    let program_inputs: Vec<_> = programs.iter()
        .zip(inputs.iter())
        .map(|(p, i)| (p.as_slice(), i.as_slice()))
        .collect();
    
    let proofs = backend.batch_prove(&program_inputs, None)
        .await
        .expect("Batch proving failed");
    
    assert_eq!(proofs.len(), messages.len());
    
    // Verify proofs in batch
    let verifications: Vec<_> = programs.iter()
        .zip(proofs.iter())
        .map(|(p, (proof, _))| (p.as_slice(), proof.as_slice()))
        .collect();
    
    let results = backend.batch_verify(&verifications, None)
        .await
        .expect("Batch verification failed");
    
    assert_eq!(results.len(), messages.len());
    assert!(results.iter().all(|&r| r), "All proofs should verify");
}

#[tokio::test]
async fn test_resource_tracking() {
    let backend = Sp1Backend::new();
    
    // Initial state
    let initial_usage = backend.resource_usage();
    assert_eq!(initial_usage.active_tasks, 0);
    assert_eq!(initial_usage.queue_depth, 0);
    
    // Generate proof
    let message = b"Test message".to_vec();
    let mut hasher = Sha256::new();
    hasher.update(&message);
    let hash: [u8; 32] = hasher.finalize().as_slice().try_into().unwrap();
    
    let mut program = Vec::with_capacity(64);
    program.extend_from_slice(&hash);
    program.extend_from_slice(&[0x01; 32]);
    
    let prove_handle = tokio::spawn({
        let backend = backend.clone();
        let program = program.clone();
        let message = message.clone();
        async move {
            backend.prove(&program, &message, None).await
        }
    });
    
    // Check resource usage during operation
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    let usage = backend.resource_usage();
    assert!(usage.active_tasks > 0);
    
    let (proof, _) = prove_handle.await.unwrap().unwrap();
    
    // Check final state
    let final_usage = backend.resource_usage();
    assert_eq!(final_usage.active_tasks, 0);
    assert_eq!(final_usage.queue_depth, 0);
}

#[tokio::test]
async fn test_circuit_caching() {
    let backend = Sp1Backend::with_config(
        Sp1Options::default(),
        CacheConfig {
            max_circuits: 10,
            max_proofs: 10,
            max_age: Duration::from_secs(60),
            enable_proof_cache: true,
        },
    );
    
    // Create test message
    let message = b"Hello, World!";
    let mut hasher = Sha256::new();
    hasher.update(message);
    let expected_hash: [u8; 32] = hasher.finalize().as_slice().try_into().unwrap();
    
    // Create program bytes
    let mut program = Vec::with_capacity(33);
    program.push(0x01); // Circuit type 1
    program.extend_from_slice(&expected_hash);
    
    // First proof generation (should compile and cache circuit)
    let (proof1, metadata1) = backend.prove(&program, message, None).await.unwrap();
    
    // Second proof generation (should use cached circuit)
    let (proof2, metadata2) = backend.prove(&program, message, None).await.unwrap();
    
    // Verify proofs are identical (deterministic)
    assert_eq!(proof1, proof2);
    
    // Second generation should be faster due to caching
    assert!(metadata2.generation_time <= metadata1.generation_time);
    
    // Check cache stats
    let stats = backend.cache.stats();
    assert_eq!(stats.circuit_entries, 1);
    assert!(stats.circuit_hits >= 1);
}

#[tokio::test]
async fn test_proof_caching() {
    let backend = Sp1Backend::with_config(
        Sp1Options::default(),
        CacheConfig {
            max_circuits: 10,
            max_proofs: 10,
            max_age: Duration::from_secs(60),
            enable_proof_cache: true,
        },
    );
    
    // Create test message
    let message = b"Hello, World!";
    let mut hasher = Sha256::new();
    hasher.update(message);
    let expected_hash: [u8; 32] = hasher.finalize().as_slice().try_into().unwrap();
    
    // Create program bytes
    let mut program = Vec::with_capacity(33);
    program.push(0x01); // Circuit type 1
    program.extend_from_slice(&expected_hash);
    
    // First proof generation
    let (proof1, metadata1) = backend.prove(&program, message, None).await.unwrap();
    
    // Second proof generation (should use cached proof)
    let (proof2, metadata2) = backend.prove(&program, message, None).await.unwrap();
    
    // Verify proofs are identical
    assert_eq!(proof1, proof2);
    
    // Second generation should be much faster (near instant)
    assert!(metadata2.generation_time < Duration::from_millis(1));
    
    // Check cache stats
    let stats = backend.cache.stats();
    assert_eq!(stats.proof_entries, 1);
    assert!(stats.proof_hits >= 1);
}

#[tokio::test]
async fn test_cache_expiration() {
    let backend = Sp1Backend::with_config(
        Sp1Options::default(),
        CacheConfig {
            max_circuits: 10,
            max_proofs: 10,
            max_age: Duration::from_millis(100), // Very short expiration
            enable_proof_cache: true,
        },
    );
    
    // Create test message
    let message = b"Hello, World!";
    let mut hasher = Sha256::new();
    hasher.update(message);
    let expected_hash: [u8; 32] = hasher.finalize().as_slice().try_into().unwrap();
    
    // Create program bytes
    let mut program = Vec::with_capacity(33);
    program.push(0x01); // Circuit type 1
    program.extend_from_slice(&expected_hash);
    
    // First proof generation
    let (proof1, metadata1) = backend.prove(&program, message, None).await.unwrap();
    
    // Wait for cache to expire
    tokio::time::sleep(Duration::from_millis(200)).await;
    
    // Second proof generation (should regenerate due to expiration)
    let (proof2, metadata2) = backend.prove(&program, message, None).await.unwrap();
    
    // Proofs should still be identical (deterministic)
    assert_eq!(proof1, proof2);
    
    // Second generation should not be instant (cache expired)
    assert!(metadata2.generation_time > Duration::from_millis(1));
    
    // Check cache stats
    let stats = backend.cache.stats();
    assert_eq!(stats.proof_entries, 1); // Old entry was replaced
    assert_eq!(stats.proof_hits, 0); // No cache hits
}

#[tokio::test]
async fn test_cache_limits() {
    let backend = Sp1Backend::with_config(
        Sp1Options::default(),
        CacheConfig {
            max_circuits: 2,
            max_proofs: 2,
            max_age: Duration::from_secs(60),
            enable_proof_cache: true,
        },
    );
    
    // Create three different messages
    let messages = [
        b"Message 1".to_vec(),
        b"Message 2".to_vec(),
        b"Message 3".to_vec(),
    ];
    
    // Generate proofs for all messages
    for message in &messages {
        let mut hasher = Sha256::new();
        hasher.update(message);
        let hash: [u8; 32] = hasher.finalize().as_slice().try_into().unwrap();
        
        let mut program = vec![0x01];
        program.extend_from_slice(&hash);
        program.extend_from_slice(&[0x02; 32]); // Use dummy circuit data
        
        backend.prove(&program, message, None).await.unwrap();
    }
    
    // Check cache stats
    let stats = backend.cache.stats();
    assert_eq!(stats.circuit_entries, 1); // Same circuit type for all
    assert_eq!(stats.proof_entries, 2); // Limited by max_proofs
}

#[tokio::test]
async fn test_cache_clear() {
    let mut backend = Sp1Backend::with_config(
        Sp1Options::default(),
        CacheConfig {
            max_circuits: 10,
            max_proofs: 10,
            max_age: Duration::from_secs(60),
            enable_proof_cache: true,
        },
    );
    
    // Create test message
    let message = b"Hello, World!";
    let mut hasher = Sha256::new();
    hasher.update(message);
    let expected_hash: [u8; 32] = hasher.finalize().as_slice().try_into().unwrap();
    
    // Create program bytes
    let mut program = Vec::with_capacity(33);
    program.push(0x01); // Circuit type 1
    program.extend_from_slice(&expected_hash);
    
    // Generate first proof
    let (proof1, metadata1) = backend.prove(&program, message, None).await.unwrap();
    
    // Clear cache
    backend.clear_cache().await.unwrap();
    
    // Generate second proof
    let (proof2, metadata2) = backend.prove(&program, message, None).await.unwrap();
    
    // Proofs should still be identical
    assert_eq!(proof1, proof2);
    
    // Second generation should not be instant (cache was cleared)
    assert!(metadata2.generation_time > Duration::from_millis(1));
    
    // Check cache stats
    let stats = backend.cache.stats();
    assert_eq!(stats.circuit_entries, 1); // New entry after clear
    assert_eq!(stats.proof_entries, 1); // New entry after clear
    assert_eq!(stats.circuit_hits, 0); // No hits after clear
    assert_eq!(stats.proof_hits, 0); // No hits after clear
} 