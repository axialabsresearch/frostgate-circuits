//! Tests for RISC0 backend

use super::*;
use frostgate_zkip::*;
use sha2::{Sha256, Digest};
use serde_json::json;
use std::time::Duration;
use std::default::Default;
use super::circuit::MessageVerifyCircuit;

#[tokio::test]
async fn test_message_verification() {
    let backend = Risc0Backend::new(Risc0Config::default());
    
    // Create test message
    let message = b"Hello, World!";
    let mut hasher = Sha256::new();
    hasher.update(message);
    let expected_hash = hasher.finalize();
    
    // Create circuit
    let mut program = vec![0x01]; // Circuit type 1
    program.extend_from_slice(&expected_hash);
    let circuit = MessageVerifyCircuit::new(&program).unwrap();
    
    // Generate proof
    let proof = backend.prove(&circuit).await.unwrap();
    
    // Verify proof
    let result = backend.verify(&circuit, &proof).await.unwrap();
    assert!(result);
}

#[tokio::test]
async fn test_transaction_verification() {
    let backend = Risc0Backend::new(Risc0Config::default());
    
    // Create test transaction
    let tx = b"{\"from\":\"0x123\",\"to\":\"0x456\",\"value\":\"100\"}";
    let mut hasher = Sha256::new();
    hasher.update(tx);
    let expected_hash = hasher.finalize();
    
    // Create circuit
    let mut program = vec![0x01]; // Circuit type 1
    program.extend_from_slice(&expected_hash);
    let circuit = MessageVerifyCircuit::new(&program).unwrap();
    
    // Generate proof
    let proof = backend.prove(&circuit).await.unwrap();
    
    // Verify proof
    let result = backend.verify(&circuit, &proof).await.unwrap();
    assert!(result);
}

#[tokio::test]
async fn test_batch_operations() {
    let backend = Risc0Backend::new(Risc0Config::default());
    
    // Create test messages
    let messages = vec![
        b"Message 1".to_vec(),
        b"Message 2".to_vec(),
        b"Message 3".to_vec(),
    ];
    
    // Create programs
    let mut programs = Vec::new();
    for message in &messages {
        let mut hasher = Sha256::new();
        hasher.update(message);
        let hash = hasher.finalize();
        
        let mut program = vec![0x01];
        program.extend_from_slice(&hash);
        program.extend_from_slice(include_bytes!("../../../target/riscv/message_verify.elf"));
        
        programs.push((program, message.clone()));
    }
    
    // Generate proofs in batch
    let program_refs: Vec<_> = programs.iter()
        .map(|(p, m)| (p.as_slice(), m.as_slice()))
        .collect();
    
    let results = backend.batch_prove(&program_refs, None).await.unwrap();
    assert_eq!(results.len(), messages.len());
    
    // Verify proofs in batch
    let verify_refs: Vec<_> = programs.iter().zip(&results)
        .map(|((p, _), (proof, _))| (p.as_slice(), proof.as_slice()))
        .collect();
    
    let verify_results = backend.batch_verify(&verify_refs, None).await.unwrap();
    assert_eq!(verify_results.len(), messages.len());
    assert!(verify_results.iter().all(|&r| r));
}

#[tokio::test]
async fn test_invalid_program() {
    let backend = Risc0Backend::new(Risc0Config::default());
    
    // Empty program
    let result = backend.prove(&[], b"test", None).await;
    assert!(result.is_err());
    
    // Invalid circuit type
    let result = backend.prove(&[0xFF], b"test", None).await;
    assert!(result.is_err());
    
    // Program too short
    let result = backend.prove(&[0x01], b"test", None).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_resource_tracking() {
    let backend = Risc0Backend::new(Risc0Config::default());
    
    // Check initial state
    let usage = backend.resource_usage();
    assert_eq!(usage.active_tasks, 0);
    assert_eq!(usage.queue_depth, 0);
    
    // Create test message
    let message = b"Hello, World!";
    let mut hasher = Sha256::new();
    hasher.update(message);
    let expected_hash = hasher.finalize();
    
    let mut program = vec![0x01];
    program.extend_from_slice(&expected_hash);
    program.extend_from_slice(include_bytes!("../../../target/riscv/message_verify.elf"));
    
    // Start proving
    let prove_handle = tokio::spawn({
        let backend = backend.clone();
        let program = program.clone();
        async move {
            backend.prove(&program, message, None).await
        }
    });
    
    // Check resource usage during proving
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let usage = backend.resource_usage();
    assert!(usage.active_tasks > 0);
    
    // Wait for proving to complete
    let (proof, _) = prove_handle.await.unwrap().unwrap();
    
    // Check final state
    let usage = backend.resource_usage();
    assert_eq!(usage.active_tasks, 0);
    assert_eq!(usage.queue_depth, 0);
    
    // Verify the proof
    let result = backend.verify(&program, &proof, None).await.unwrap();
    assert!(result);
}

#[tokio::test]
async fn test_stats_tracking() {
    let backend = Risc0Backend::new(Risc0Config::default());
    
    // Check initial stats
    let stats = backend.stats();
    assert_eq!(stats.total_proofs, 0);
    assert_eq!(stats.total_verifications, 0);
    assert_eq!(stats.total_failures, 0);
    
    // Create test message
    let message = b"Hello, World!";
    let mut hasher = Sha256::new();
    hasher.update(message);
    let expected_hash = hasher.finalize();
    
    let mut program = vec![0x01];
    program.extend_from_slice(&expected_hash);
    program.extend_from_slice(include_bytes!("../../../target/riscv/message_verify.elf"));
    
    // Generate and verify proof
    let (proof, _) = backend.prove(&program, message, None).await.unwrap();
    let result = backend.verify(&program, &proof, None).await.unwrap();
    assert!(result);
    
    // Check updated stats
    let stats = backend.stats();
    assert_eq!(stats.total_proofs, 1);
    assert_eq!(stats.total_verifications, 1);
    assert_eq!(stats.total_failures, 0);
    assert!(stats.avg_proving_time > std::time::Duration::from_nanos(0));
    assert!(stats.avg_verification_time > std::time::Duration::from_nanos(0));
}

#[tokio::test]
async fn test_block_verification() {
    let backend = Risc0Backend::new(Risc0Config::default());
    
    // Create test block header
    let block_header = json!({
        "parent_hash": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        "state_root": "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        "transactions_root": "0x9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba",
        "receipts_root": "0xfedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
        "number": "0x1234",
        "timestamp": "0x61c8d240",  // Dec 2021
        "gas_used": "0x1234567",
        "gas_limit": "0x2345678",
        "extra_data": []
    });
    
    let header_bytes = serde_json::to_vec(&block_header).unwrap();
    
    // Compute expected hash
    let mut hasher = Sha256::new();
    hasher.update(&header_bytes);
    let expected_hash = hasher.finalize();
    
    // Create program bytes (0x03 for block verification)
    let mut program = vec![0x03];
    program.extend_from_slice(&expected_hash);
    program.extend_from_slice(&0x1234u64.to_le_bytes()); // Expected block number
    program.extend_from_slice(include_bytes!("../../../target/riscv/block_verify.elf"));
    
    // Generate proof
    let (proof, metadata) = backend.prove(&program, &header_bytes, None).await.unwrap();
    
    // Verify proof
    let result = backend.verify(&program, &proof, None).await.unwrap();
    assert!(result);
}

#[tokio::test]
async fn test_invalid_block() {
    let backend = Risc0Backend::new(Risc0Config::default());
    
    // Test cases with invalid block headers
    let test_cases = vec![
        // Invalid parent hash
        json!({
            "parent_hash": "0x123", // Too short
            "state_root": "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            "transactions_root": "0x9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba",
            "receipts_root": "0xfedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
            "number": "0x1234",
            "timestamp": "0x61c8d240",
            "gas_used": "0x1234567",
            "gas_limit": "0x2345678",
            "extra_data": []
        }),
        // Invalid timestamp (too old)
        json!({
            "parent_hash": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            "state_root": "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            "transactions_root": "0x9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba",
            "receipts_root": "0xfedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
            "number": "0x1234",
            "timestamp": "0x4d3c2b1a", // 2010
            "gas_used": "0x1234567",
            "gas_limit": "0x2345678",
            "extra_data": []
        }),
        // Invalid gas (used > limit)
        json!({
            "parent_hash": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            "state_root": "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            "transactions_root": "0x9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba",
            "receipts_root": "0xfedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
            "number": "0x1234",
            "timestamp": "0x61c8d240",
            "gas_used": "0x2345679", // Greater than limit
            "gas_limit": "0x2345678",
            "extra_data": []
        }),
    ];
    
    for test_case in test_cases {
        let header_bytes = serde_json::to_vec(&test_case).unwrap();
        
        // Compute hash
        let mut hasher = Sha256::new();
        hasher.update(&header_bytes);
        let expected_hash = hasher.finalize();
        
        // Create program
        let mut program = vec![0x03];
        program.extend_from_slice(&expected_hash);
        program.extend_from_slice(&0x1234u64.to_le_bytes());
        program.extend_from_slice(include_bytes!("../../../target/riscv/block_verify.elf"));
        
        // Attempt to generate proof
        let result = backend.prove(&program, &header_bytes, None).await;
        assert!(result.is_err());
    }
}

#[tokio::test]
async fn test_block_number_mismatch() {
    let backend = Risc0Backend::new(Risc0Config::default());
    
    // Create valid block header
    let block_header = json!({
        "parent_hash": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        "state_root": "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        "transactions_root": "0x9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba",
        "receipts_root": "0xfedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
        "number": "0x1234",
        "timestamp": "0x61c8d240",
        "gas_used": "0x1234567",
        "gas_limit": "0x2345678",
        "extra_data": []
    });
    
    let header_bytes = serde_json::to_vec(&block_header).unwrap();
    
    // Compute hash
    let mut hasher = Sha256::new();
    hasher.update(&header_bytes);
    let expected_hash = hasher.finalize();
    
    // Create program with mismatched block number
    let mut program = vec![0x03];
    program.extend_from_slice(&expected_hash);
    program.extend_from_slice(&0x5678u64.to_le_bytes()); // Different block number
    program.extend_from_slice(include_bytes!("../../../target/riscv/block_verify.elf"));
    
    // Attempt to generate proof
    let result = backend.prove(&program, &header_bytes, None).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_circuit_caching() {
    let backend = Risc0Backend::with_config(
        Risc0Config::default(),
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
    let expected_hash = hasher.finalize();
    
    // Create program bytes
    let mut program = vec![0x01];
    program.extend_from_slice(&expected_hash);
    program.extend_from_slice(include_bytes!("../../../target/riscv/message_verify.elf"));
    
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
    let backend = Risc0Backend::with_config(
        Risc0Config::default(),
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
    let expected_hash = hasher.finalize();
    
    // Create program bytes
    let mut program = vec![0x01];
    program.extend_from_slice(&expected_hash);
    program.extend_from_slice(include_bytes!("../../../target/riscv/message_verify.elf"));
    
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
    let backend = Risc0Backend::with_config(
        Risc0Config::default(),
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
    let expected_hash = hasher.finalize();
    
    // Create program bytes
    let mut program = vec![0x01];
    program.extend_from_slice(&expected_hash);
    program.extend_from_slice(include_bytes!("../../../target/riscv/message_verify.elf"));
    
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
    let backend = Risc0Backend::with_config(
        Risc0Config::default(),
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
        let hash = hasher.finalize();
        
        let mut program = vec![0x01];
        program.extend_from_slice(&hash);
        program.extend_from_slice(include_bytes!("../../../target/riscv/message_verify.elf"));
        
        backend.prove(&program, message, None).await.unwrap();
    }
    
    // Check cache stats
    let stats = backend.cache.stats();
    assert_eq!(stats.circuit_entries, 1); // Same circuit type for all
    assert_eq!(stats.proof_entries, 2); // Limited by max_proofs
}

#[tokio::test]
async fn test_cache_clear() {
    let backend = Risc0Backend::with_config(
        Risc0Config::default(),
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
    let expected_hash = hasher.finalize();
    
    // Create program bytes
    let mut program = vec![0x01];
    program.extend_from_slice(&expected_hash);
    program.extend_from_slice(include_bytes!("../../../target/riscv/message_verify.elf"));
    
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