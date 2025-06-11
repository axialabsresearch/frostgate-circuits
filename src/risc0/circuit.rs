//! Default circuit implementations for RISC0

use risc0_zkvm::{Receipt, sha::Digest};
use crate::risc0::types::Risc0Circuit;

/// Basic message verification circuit
pub struct MessageVerifyCircuit {
    /// Message bytes to verify
    message: Vec<u8>,
    /// Expected hash
    expected_hash: [u8; 32],
    /// Circuit ELF bytes
    elf_bytes: Vec<u8>,
}

impl MessageVerifyCircuit {
    /// Create a new message verification circuit
    pub fn new(message: Vec<u8>, expected_hash: [u8; 32], elf_bytes: Vec<u8>) -> Self {
        Self {
            message,
            expected_hash,
            elf_bytes,
        }
    }
}

impl Risc0Circuit for MessageVerifyCircuit {
    fn elf(&self) -> &[u8] {
        &self.elf_bytes
    }
    
    fn public_inputs(&self) -> Vec<u32> {
        // Convert expected hash to u32 words
        self.expected_hash.chunks(4)
            .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
            .collect()
    }
    
    fn private_inputs(&self) -> Vec<u8> {
        // Message bytes are private input
        self.message.clone()
    }
    
    fn verify_receipt(&self, receipt: &Receipt) -> bool {
        // Check that the journal contains our expected hash
        if receipt.journal.bytes().len() != 32 {
            return false;
        }
        
        let mut computed_hash = [0u8; 32];
        computed_hash.copy_from_slice(&receipt.journal.bytes()[0..32]);
        
        computed_hash == self.expected_hash
    }
}

/// Transaction verification circuit
pub struct TxVerifyCircuit {
    /// Transaction bytes
    tx_bytes: Vec<u8>,
    /// Expected transaction hash
    expected_hash: [u8; 32],
    /// Circuit ELF bytes
    elf_bytes: Vec<u8>,
}

impl TxVerifyCircuit {
    /// Create a new transaction verification circuit
    pub fn new(tx_bytes: Vec<u8>, expected_hash: [u8; 32], elf_bytes: Vec<u8>) -> Self {
        Self {
            tx_bytes,
            expected_hash,
            elf_bytes,
        }
    }
}

impl Risc0Circuit for TxVerifyCircuit {
    fn elf(&self) -> &[u8] {
        &self.elf_bytes
    }
    
    fn public_inputs(&self) -> Vec<u32> {
        // Convert expected hash to u32 words
        self.expected_hash.chunks(4)
            .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
            .collect()
    }
    
    fn private_inputs(&self) -> Vec<u8> {
        // Transaction bytes are private input
        self.tx_bytes.clone()
    }
    
    fn verify_receipt(&self, receipt: &Receipt) -> bool {
        // Check that the journal contains our expected hash
        // and any additional transaction verification data
        if receipt.journal.bytes().len() < 64 {
            return false;
        }
        
        let mut computed_hash = [0u8; 32];
        computed_hash.copy_from_slice(&receipt.journal.bytes()[0..32]);
        
        // Additional transaction verification could be done here
        // using the rest of the journal data
        
        computed_hash == self.expected_hash
    }
}

/// Block verification circuit
pub struct BlockVerifyCircuit {
    /// Block header bytes
    header_bytes: Vec<u8>,
    /// Expected block hash
    expected_hash: [u8; 32],
    /// Expected block number
    expected_number: u64,
    /// Circuit ELF bytes
    elf_bytes: Vec<u8>,
}

impl BlockVerifyCircuit {
    /// Create a new block verification circuit
    pub fn new(header_bytes: Vec<u8>, expected_hash: [u8; 32], expected_number: u64, elf_bytes: Vec<u8>) -> Self {
        Self {
            header_bytes,
            expected_hash,
            expected_number,
            elf_bytes,
        }
    }
}

impl Risc0Circuit for BlockVerifyCircuit {
    fn elf(&self) -> &[u8] {
        &self.elf_bytes
    }
    
    fn public_inputs(&self) -> Vec<u32> {
        // Convert expected hash to u32 words and add block number
        let mut inputs = self.expected_hash.chunks(4)
            .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
            .collect::<Vec<_>>();
        
        // Add block number as two u32s
        inputs.extend_from_slice(&[
            (self.expected_number & 0xFFFFFFFF) as u32,
            (self.expected_number >> 32) as u32,
        ]);
        
        inputs
    }
    
    fn private_inputs(&self) -> Vec<u8> {
        // Block header bytes are private input
        self.header_bytes.clone()
    }
    
    fn verify_receipt(&self, receipt: &Receipt) -> bool {
        // Check that the journal contains our expected hash and block data
        if receipt.journal.bytes().len() < 56 { // 32 + 8 + 8 + 8
            return false;
        }
        
        // Verify hash
        let mut computed_hash = [0u8; 32];
        computed_hash.copy_from_slice(&receipt.journal.bytes()[0..32]);
        if computed_hash != self.expected_hash {
            return false;
        }
        
        // Verify block number
        let mut block_number_bytes = [0u8; 8];
        block_number_bytes.copy_from_slice(&receipt.journal.bytes()[32..40]);
        let block_number = u64::from_le_bytes(block_number_bytes);
        if block_number != self.expected_number {
            return false;
        }
        
        // Verify timestamp is reasonable
        let mut timestamp_bytes = [0u8; 8];
        timestamp_bytes.copy_from_slice(&receipt.journal.bytes()[40..48]);
        let timestamp = u64::from_le_bytes(timestamp_bytes);
        if timestamp < 1600000000 || timestamp > 2000000000 {
            return false;
        }
        
        // Verify gas used <= gas limit
        let mut gas_bytes = [0u8; 16];
        gas_bytes.copy_from_slice(&receipt.journal.bytes()[48..64]);
        let gas_used = u64::from_le_bytes(gas_bytes[0..8].try_into().unwrap());
        let gas_limit = u64::from_le_bytes(gas_bytes[8..16].try_into().unwrap());
        if gas_used > gas_limit {
            return false;
        }
        
        true
    }
} 