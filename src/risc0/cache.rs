#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_must_use)]
#![allow(unused_braces)]
#![allow(unused_parens)]
#![allow(unused_macros)]

//! Cache implementation for RISC0 circuits and proofs

use std::sync::Arc;
use std::time::{Duration, SystemTime};
use parking_lot::RwLock;
use lru::LruCache;
use std::num::NonZeroUsize;
use sha2::{Sha256, Digest};
use risc0_zkvm::{Receipt, ProverOpts};

use super::types::Risc0Circuit;

/// Cache entry for a compiled circuit
#[derive(Clone)]
pub struct CircuitCacheEntry {
    /// Circuit ELF bytes
    pub elf_bytes: Vec<u8>,
    /// Circuit hash
    pub hash: [u8; 32],
    /// Last access time
    pub last_access: SystemTime,
    /// Number of times accessed
    pub access_count: u64,
    /// Compilation time
    pub compile_time: Duration,
}

/// Cache entry for a proof
#[derive(Clone)]
pub struct ProofCacheEntry {
    /// Proof bytes
    pub proof: Vec<u8>,
    /// Program hash
    pub program_hash: [u8; 32],
    /// Input hash
    pub input_hash: [u8; 32],
    /// Generation time
    pub generation_time: Duration,
    /// Last access time
    pub last_access: SystemTime,
    /// Number of times accessed
    pub access_count: u64,
}

/// Cache configuration
#[derive(Clone, Debug)]
pub struct CacheConfig {
    /// Maximum number of circuits to cache
    pub max_circuits: usize,
    /// Maximum number of proofs to cache
    pub max_proofs: usize,
    /// Maximum age of cached items
    pub max_age: Duration,
    /// Whether to enable proof caching
    pub enable_proof_cache: bool,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_circuits: 100,
            max_proofs: 1000,
            max_age: Duration::from_secs(3600), // 1 hour
            enable_proof_cache: true,
        }
    }
}

/// Circuit and proof cache
#[derive(Debug)]
pub struct CircuitCache {
    /// Cached compiled circuits
    circuits: RwLock<LruCache<[u8; 32], CircuitCacheEntry>>,
    /// Cached proofs
    proofs: RwLock<LruCache<[u8; 32], ProofCacheEntry>>,
    /// Cache configuration
    config: CacheConfig,
}

impl CircuitCache {
    /// Create a new circuit cache with the given configuration
    pub fn new(config: CacheConfig) -> Self {
        Self {
            circuits: RwLock::new(LruCache::new(NonZeroUsize::new(config.max_circuits).unwrap())),
            proofs: RwLock::new(LruCache::new(NonZeroUsize::new(config.max_proofs).unwrap())),
            config,
        }
    }

    /// Get circuit ELF bytes from cache
    pub fn get_circuit(&self, program: &[u8]) -> Option<CircuitCacheEntry> {
        let hash = self.hash_program(program);
        let mut circuits = self.circuits.write();
        
        if let Some(entry) = circuits.get(&hash) {
            if let Ok(age) = SystemTime::now().duration_since(entry.last_access) {
                if age < self.config.max_age {
                    return Some(entry.clone());
                }
            }
            circuits.pop(&hash);
        }
        None
    }

    /// Store circuit ELF bytes in cache
    pub fn store_circuit(&self, program: &[u8], elf_bytes: Vec<u8>, compile_time: Duration) {
        let hash = self.hash_program(program);
        let entry = CircuitCacheEntry {
            elf_bytes,
            hash,
            last_access: SystemTime::now(),
            access_count: 1,
            compile_time,
        };
        self.circuits.write().put(hash, entry);
    }

    /// Get proof from cache
    pub fn get_proof(&self, program: &[u8], input: &[u8]) -> Option<ProofCacheEntry> {
        if !self.config.enable_proof_cache {
            return None;
        }

        let hash = self.hash_program(program);
        let mut proofs = self.proofs.write();
        
        if let Some(entry) = proofs.get(&hash) {
            if let Ok(age) = SystemTime::now().duration_since(entry.last_access) {
                if age < self.config.max_age {
                    return Some(entry.clone());
                }
            }
            proofs.pop(&hash);
        }
        None
    }

    /// Store proof in cache
    pub fn store_proof(
        &self,
        program: &[u8],
        input: &[u8],
        proof: Vec<u8>,
        generation_time: Duration,
    ) {
        if !self.config.enable_proof_cache {
            return;
        }

        let hash = self.hash_program(program);
        let entry = ProofCacheEntry {
            proof,
            program_hash: hash,
            input_hash: self.hash_program(input),
            generation_time,
            last_access: SystemTime::now(),
            access_count: 1,
        };
        self.proofs.write().put(hash, entry);
    }

    /// Clear expired cache entries
    pub fn clear_expired(&self) {
        let now = SystemTime::now();
        
        // Clear expired circuits
        let mut circuits = self.circuits.write();
        let expired: Vec<_> = circuits.iter()
            .filter(|(_, entry)| entry.last_access.elapsed().unwrap() >= self.config.max_age)
            .map(|(k, _)| *k)
            .collect();
        for k in expired {
            circuits.pop(&k);
        }

        // Clear expired proofs
        let mut proofs = self.proofs.write();
        let expired: Vec<_> = proofs.iter()
            .filter(|(_, entry)| entry.last_access.elapsed().unwrap() >= self.config.max_age)
            .map(|(k, _)| *k)
            .collect();
        for k in expired {
            proofs.pop(&k);
        }
    }

    /// Clear all cache entries
    pub fn clear_all(&self) {
        self.circuits.write().clear();
        self.proofs.write().clear();
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        let circuits = self.circuits.read();
        let proofs = self.proofs.read();

        CacheStats {
            circuit_entries: circuits.len(),
            proof_entries: proofs.len(),
            max_circuits: self.config.max_circuits,
            max_proofs: self.config.max_proofs,
            circuit_hits: circuits.iter().map(|e| e.1.access_count).sum(),
            proof_hits: proofs.iter().map(|e| e.1.access_count).sum(),
        }
    }

    fn hash_program(&self, program: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(program);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hasher.finalize());
        hash
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    /// Number of cached circuits
    pub circuit_entries: usize,
    /// Number of cached proofs
    pub proof_entries: usize,
    /// Maximum number of circuits
    pub max_circuits: usize,
    /// Maximum number of proofs
    pub max_proofs: usize,
    /// Total number of circuit cache hits
    pub circuit_hits: u64,
    /// Total number of proof cache hits
    pub proof_hits: u64,
} 