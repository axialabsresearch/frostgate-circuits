# Frostgate Circuits

Zero-knowledge proof circuit implementations for the Frostgate blockchain adapter system. This crate provides the core zero-knowledge proof functionality used to validate and verify blockchain state transitions.

Frostgate's ZKIP allows implementation of new ZK backends using the ZkBackend trait abstraction.

## Overview

Frostgate Circuits implements various zero-knowledge proof systems to enable secure and private blockchain state verification. The current implementation focuses on SP1, a RISC-V based zkVM that allows proving arbitrary computation.

## Features

- SP1 zkVM integration for general-purpose zero-knowledge proofs
- Efficient program caching and proof generation
- Support for both local and network-based proving
- Async-first architecture for improved performance
- Memory-efficient execution tracking
- Comprehensive error handling

## Architecture

The crate is organized into several modules:

```
src/
├── lib.rs           # Library entry point and exports
├── sp1/             # SP1 zkVM implementation
│   ├── backend.rs   # ZkBackend trait implementation
│   ├── circuit.rs   # Circuit definitions
│   ├── types.rs     # Core types and structures
│   └── mod.rs       # Module exports
└── tests/           # Integration tests
```

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
frostgate-circuits = { git = "https://github.com/frostgate/frostgate-circuits.git" }
```

Basic usage example:

```rust
use frostgate_circuits::sp1::{Sp1Backend, Sp1Config};

#[tokio::main]
async fn main() {
    // Initialize the SP1 backend
    let config = Sp1Config::default();
    let backend = Sp1Backend::with_config(config);

    // Execute a program and generate proof
    let (proof, metadata) = backend.prove(program, input, None).await?;

    // Verify the proof
    let is_valid = backend.verify(program, &proof, None).await?;
}
```

## Configuration

The system can be configured through various options:

- Maximum concurrent operations
- Program cache size
- GPU acceleration (if available)
- Memory usage limits
- Build directory location

See the SP1 module documentation for detailed configuration options.

## Development

### Prerequisites

- Rust 1.70 or later
- SP1 SDK 4.2.1 or later
- CMake (for native dependencies)

### Building

```bash
cargo build --release
```

### Testing

```bash
cargo test
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under either of

- Apache License, Version 2.0 (LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license (LICENSE-MIT or http://opensource.org/licenses/MIT)

at your option.

## Acknowledgments

- SP1 Team for their excellent zkVM implementation
- Frostgate contributors and maintainers
