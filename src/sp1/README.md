# SP1 Zero-Knowledge Proof Implementation

This directory contains the SP1 zero-knowledge proof system implementation for Frostgate. SP1 is a RISC-V zkVM that enables efficient zero-knowledge proof generation for arbitrary computation.

## Components

- `plug.rs` - Main ZkPlug trait implementation for SP1 integration
- `prover.rs` - Proof generation and program execution logic
- `types.rs` - Core types and data structures
- `utils.rs` - Utility functions and program caching
- `verifier.rs` - Proof verification logic

## Features

- Local and network-based proving backends
- Program caching for improved performance
- Async proof generation and verification
- Support for both Plonk and Groth16 proof systems
- TEE (Trusted Execution Environment) integration
- Memory-efficient execution tracking

## Usage

The SP1 implementation is used through the ZkPlug trait interface:

```rust
let config = Sp1PlugConfig::default();
let mut plug = Sp1Plug::new(config);

// Execute a program and generate proof
let result = plug.execute(program, input, None, None).await?;

// Verify a proof
let is_valid = plug.verify(&result.proof, Some(input), None).await?;
```

## Configuration

The system can be configured through `Sp1PlugConfig`:

- Network/Local proving mode
- Concurrent proof generation limits
- Program cache settings
- Memory usage limits
- Build directory location

## Error Handling

Errors are handled through the `Sp1PlugError` type which covers:

- Proof generation failures
- Verification errors
- Input validation issues
- Network communication errors
- Resource allocation failures

## Dependencies

- sp1-sdk: Core SP1 functionality
- sp1-core-machine: RISC-V machine implementation
- sp1-prover: Proof generation components 