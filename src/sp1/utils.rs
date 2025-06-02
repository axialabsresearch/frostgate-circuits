#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(unused_mut)]
#![allow(unused_must_use)]
#![allow(dead_code)]

use std::collections::{HashMap, BTreeMap};
use std::time::{SystemTime, Duration};
use crate::sp1::types::{ProgramInfo, CacheConfig};

pub struct ProgramCache {
    entries: HashMap<String, ProgramInfo>,
    access_order: BTreeMap<SystemTime, String>,
    config: CacheConfig,
}

impl ProgramCache {
    pub fn new(config: CacheConfig) -> Self {
        Self {
            entries: HashMap::new(),
            access_order: BTreeMap::new(),
            config,
        }
    }

    pub fn get(&mut self, hash: &str) -> Option<ProgramInfo> {
        if let Some(mut info) = self.entries.get(hash).cloned() {
            // Check TTL
            if let Some(ttl) = self.config.ttl_seconds {
                let age = SystemTime::now()
                    .duration_since(info.compiled_at)
                    .unwrap_or(Duration::from_secs(0))
                    .as_secs();
                
                if age > ttl {
                    self.remove(hash);
                    return None;
                }
            }

            // Update access tracking
            if self.config.enable_lru {
                self.access_order.remove(&info.last_accessed);
                info.last_accessed = SystemTime::now();
                info.access_count += 1;
                self.access_order.insert(info.last_accessed, hash.to_string());
                self.entries.insert(hash.to_string(), info.clone());
            }

            Some(info)
        } else {
            None
        }
    }

    pub fn insert(&mut self, hash: String, mut info: ProgramInfo) {
        // Evict if necessary
        if let Some(max_entries) = self.config.max_entries {
            while self.entries.len() >= max_entries {
                self.evict_oldest();
            }
        }

        info.last_accessed = SystemTime::now();
        if self.config.enable_lru {
            self.access_order.insert(info.last_accessed, hash.clone());
        }
        self.entries.insert(hash, info);
    }

    pub fn remove(&mut self, hash: &str) {
        if let Some(info) = self.entries.remove(hash) {
            if self.config.enable_lru {
                self.access_order.remove(&info.last_accessed);
            }
        }
    }

    pub fn evict_oldest(&mut self) {
        if self.config.enable_lru && !self.access_order.is_empty() {
            if let Some((_, oldest_hash)) = self.access_order.iter().next() {
                let oldest_hash = oldest_hash.clone();
                self.remove(&oldest_hash);
            }
        } else if let Some(hash) = self.entries.keys().next().cloned() {
            self.remove(&hash);
        }
    }

    pub fn clear(&mut self) {
        self.entries.clear();
        self.access_order.clear();
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn entries(&self) -> &HashMap<String, ProgramInfo> {
        &self.entries
    }
}

pub fn validate_input(input: &[u8], max_size: Option<usize>) -> Result<(), String> {
    if input.is_empty() {
        return Err("Input cannot be empty".to_string());
    }

    if let Some(max) = max_size {
        if input.len() > max {
            return Err(format!("Input size {} exceeds maximum {}", input.len(), max));
        }
    }

    Ok(())
}
