use sp1_zkvm::{self, io, entrypoint};
use sha3::{Digest, Keccak256};

#[entrypoint]
fn main() {
    // Read input from stdin
    let input = io::read::<Vec<u8>>();
    
    // Hash the input using Keccak256
    let mut hasher = Keccak256::new();
    hasher.update(&input);
    let hash = hasher.finalize();
    
    // Write the hash to stdout
    io::write(0, &hash);
} 