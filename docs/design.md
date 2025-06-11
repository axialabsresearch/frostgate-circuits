# Frostgate Circuits Design

This document describes the current design of Frostgate's zero-knowledge circuit system.

## Architecture Overview

```mermaid
graph TB
    subgraph "Application Layer"
        APP[Applications]
        SDK[Circuit SDK]
    end

    subgraph "Circuit Layer"
        MSG[Message Circuits]
        TX[Transaction Circuits]
        BLK[Block Circuits]
    end

    subgraph "Backend Layer"
        RISC0[RISC0 Backend]
        SP1[SP1 Backend]
        CACHE[Circuit Cache]
    end

    subgraph "Proof Layer"
        PROVE[Prover]
        VERIFY[Verifier]
        BATCH[Batch Ops]
    end

    APP --> SDK
    SDK --> MSG
    SDK --> TX
    SDK --> BLK
    MSG --> RISC0
    MSG --> SP1
    TX --> RISC0
    TX --> SP1
    BLK --> RISC0
    BLK --> SP1
    RISC0 --> CACHE
    SP1 --> CACHE
    RISC0 --> PROVE
    SP1 --> PROVE
    PROVE --> VERIFY
    PROVE --> BATCH
```

## Core Components

### 1. Circuit Types

```mermaid
classDiagram
    class Circuit {
        +program() bytes
        +verify_proof(proof) bool
        +prove(input) Result
        +verify(proof) bool
    }

    class MessageCircuit {
        +message: Vec<u8>
        +expected_hash: [u8; 32]
        +prove() Result
        +verify() bool
    }

    class TransactionCircuit {
        +tx_data: TxData
        +state: State
        +prove() Result
        +verify() bool
    }

    class BlockCircuit {
        +block_data: BlockData
        +state: State
        +prove() Result
        +verify() bool
    }

    Circuit <|-- MessageCircuit
    Circuit <|-- TransactionCircuit
    Circuit <|-- BlockCircuit
```

### 2. Backend Integration

```mermaid
graph TB
    subgraph "Backend Interface"
        TRAIT[Circuit Trait]
        PROVE[Prove Method]
        VERIFY[Verify Method]
    end

    subgraph "RISC0 Implementation"
        R0_CIRC[RISC0 Circuit]
        R0_PROVE[RISC0 Prover]
        R0_VERIFY[RISC0 Verifier]
        R0_CACHE[Circuit Cache]
    end

    subgraph "SP1 Implementation"
        SP1_CIRC[SP1 Circuit]
        SP1_PROVE[SP1 Prover]
        SP1_VERIFY[SP1 Verifier]
        SP1_CACHE[Circuit Cache]
    end

    TRAIT --> R0_CIRC
    TRAIT --> SP1_CIRC
    PROVE --> R0_PROVE
    PROVE --> SP1_PROVE
    VERIFY --> R0_VERIFY
    VERIFY --> SP1_VERIFY
    R0_CIRC --> R0_CACHE
    SP1_CIRC --> SP1_CACHE
```

## Circuit Implementations

### 1. Message Verification Circuit

```rust
pub struct MessageVerifyCircuit {
    message: Vec<u8>,
    expected_hash: [u8; 32],
    circuit_bytes: Vec<u8>,
}

impl Circuit for MessageVerifyCircuit {
    fn program(&self) -> &[u8] {
        &self.circuit_bytes
    }

    fn verify_proof(&self, proof: &[u8]) -> bool {
        // Verify hash matches
        let actual_hash = hash_message(&self.message);
        actual_hash == self.expected_hash && 
        self.verify_proof_internal(proof)
    }
}
```

### 2. Transaction Verification Circuit

```rust
pub struct TxVerifyCircuit {
    tx_data: TxData,
    state: State,
    circuit_bytes: Vec<u8>,
}

impl Circuit for TxVerifyCircuit {
    fn program(&self) -> &[u8] {
        &self.circuit_bytes
    }

    fn verify_proof(&self, proof: &[u8]) -> bool {
        // Verify transaction validity
        self.verify_tx_validity() &&
        // Verify state transition
        self.verify_state_transition() &&
        // Verify proof
        self.verify_proof_internal(proof)
    }
}
```

## Caching System

```mermaid
graph TB
    subgraph "Circuit Cache"
        COMP[Compiled Circuits]
        HASH[Circuit Hashes]
        META[Circuit Metadata]
    end

    subgraph "Proof Cache"
        PROOFS[Generated Proofs]
        INPUTS[Input Hashes]
        STATS[Cache Stats]
    end

    subgraph "Management"
        LRU[LRU Eviction]
        CLEAN[Cleanup]
        CONFIG[Cache Config]
    end

    COMP --> HASH
    COMP --> META
    PROOFS --> INPUTS
    PROOFS --> STATS
    LRU --> COMP
    LRU --> PROOFS
    CLEAN --> COMP
    CLEAN --> PROOFS
    CONFIG --> LRU
    CONFIG --> CLEAN
```

## Performance Optimizations

### 1. Circuit Compilation

```mermaid
graph LR
    subgraph "Compilation"
        SRC[Source]
        OPT[Optimizer]
        COMP[Compiler]
        CACHE[Cache]
    end

    subgraph "Optimizations"
        CONST[Constant Folding]
        ELIM[Dead Code Elimination]
        MERGE[Circuit Merging]
    end

    SRC --> OPT
    OPT --> COMP
    COMP --> CACHE
    OPT --> CONST
    OPT --> ELIM
    OPT --> MERGE
```

### 2. Proof Generation

```mermaid
sequenceDiagram
    participant App
    participant Cache
    participant Compiler
    participant Prover
    
    App->>Cache: Request Circuit
    alt Circuit in Cache
        Cache-->>App: Return Cached Circuit
    else Circuit not in Cache
        Cache->>Compiler: Compile Circuit
        Compiler-->>Cache: Store Compiled Circuit
        Cache-->>App: Return New Circuit
    end
    App->>Prover: Generate Proof
    Prover-->>App: Return Proof
```

## Error Handling

```mermaid
graph TB
    subgraph "Error Types"
        CIRC[Circuit Errors]
        COMP[Compilation Errors]
        PROVE[Proving Errors]
        VERIFY[Verification Errors]
    end

    subgraph "Recovery"
        RETRY[Retry Logic]
        FALLBACK[Fallback Circuit]
        REPORT[Error Reporting]
    end

    CIRC --> RETRY
    COMP --> FALLBACK
    PROVE --> RETRY
    VERIFY --> REPORT
```

## Testing Framework

```mermaid
graph TB
    subgraph "Test Types"
        UNIT[Unit Tests]
        INT[Integration Tests]
        PROP[Property Tests]
        FUZZ[Fuzzing]
    end

    subgraph "Test Components"
        CIRC[Circuit Tests]
        PROVE[Prover Tests]
        VERIFY[Verifier Tests]
        PERF[Performance Tests]
    end

    UNIT --> CIRC
    UNIT --> PROVE
    INT --> VERIFY
    INT --> PERF
    PROP --> CIRC
    PROP --> VERIFY
    FUZZ --> CIRC
    FUZZ --> PROVE
```

## Future Extensions

1. Circuit Optimizations
   - Advanced circuit merging
   - Automated optimization
   - Custom constraint systems

2. Backend Support
   - Additional ZK backends
   - Custom proving systems
   - Hybrid approaches

3. Performance Features
   - Parallel proof generation
   - Circuit preprocessing
   - Hardware acceleration

4. Testing Features
   - Automated circuit testing
   - Property-based testing
   - Benchmark framework 