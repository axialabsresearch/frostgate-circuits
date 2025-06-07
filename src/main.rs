//! A simple program that takes a number `n` as input, and writes the `n-1`th and `n`th fibonacci
//! number as an output.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.

#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_parens)]
#![allow(unused_braces)]
#![allow(unused_macros)]
#![allow(unused_imports)]


#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_sol_types::SolType;
use frostgate_lib::zkplug::{hash_bytes, MessageEvent};

pub fn main() {
    // Read input from the prover
    let input = sp1_zkvm::io::read::<Vec<u8>>();
    
    // Hash the input
    let hash = hash_bytes(&input);
    
    // Write output
    sp1_zkvm::io::commit_slice(&hash);
}
