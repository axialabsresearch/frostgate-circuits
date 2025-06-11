# Frostgate Circuits Migration Guide

This document outlines the migration path from the previous circuit architecture to the current design, highlighting key changes and improvements.

## Architecture Evolution

```mermaid
graph TB
    subgraph "Previous Architecture"
        direction TB
        P_APP[Application]
        P_CIRC[Single Circuit Type]
        P_SP1[SP1 Only]
        
        P_APP --> P_CIRC
        P_CIRC --> P_SP1
    end

    subgraph "Current Architecture"
        direction TB
        C_APP[Application]
        C_SDK[Circuit SDK]
        C_TYPES[Multiple Circuits]
        C_BACK[Multiple Backends]
        C_CACHE[Caching Layer]
        
        C_APP --> C_SDK
        C_SDK --> C_TYPES
        C_TYPES --> C_BACK
        C_BACK --> C_CACHE
    end
```

## Previous Architecture Limitations

1. Limited Circuit Types
   - Only message verification
   - No transaction support
   - No block verification

2. Single Backend
   - SP1-only implementation
   - No backend abstraction
   - Limited proving options

3. Performance Issues
   - No circuit caching
   - Sequential proof generation
   - Limited optimization

4. Development Constraints
   - No testing framework
   - Limited debugging tools
   - Poor error handling

## Migration Steps

### 1. Circuit Trait Redesign

```mermaid
graph LR
    subgraph "Before"
        OLD_CIRC[Basic Circuit]
        OLD_PROVE[Simple Prove]
    end

    subgraph "After"
        NEW_CIRC[Circuit Trait]
        NEW_MSG[Message Circuit]
        NEW_TX[Transaction Circuit]
        NEW_BLK[Block Circuit]
    end

    OLD_CIRC --> NEW_CIRC
    NEW_CIRC --> NEW_MSG
    NEW_CIRC --> NEW_TX
    NEW_CIRC --> NEW_BLK
```

#### Before:
```rust
struct Circuit {
    message: Vec<u8>,
    hash: [u8; 32],
}

impl Circuit {
    fn prove(&self) -> Vec<u8> {
        // Basic proving logic
    }
}
```

#### After:
```rust
trait Circuit {
    fn program(&self) -> &[u8];
    fn verify_proof(&self, proof: &[u8]) -> bool;
    fn prove(&self, input: &[u8]) -> Result<Vec<u8>>;
    fn verify(&self, proof: &[u8]) -> bool;
}

struct MessageCircuit { /* ... */ }
struct TransactionCircuit { /* ... */ }
struct BlockCircuit { /* ... */ }
```

### 2. Backend Integration

```mermaid
graph TB
    subgraph "Backend Evolution"
        OLD[SP1 Only]
        NEW[Multiple Backends]
        TRAIT[Backend Trait]
    end

    subgraph "Features"
        RISC0[RISC0 Support]
        SP1[SP1 Support]
        CACHE[Caching]
        BATCH[Batching]
    end

    OLD --> NEW
    NEW --> TRAIT
    TRAIT --> RISC0
    TRAIT --> SP1
    RISC0 --> CACHE
    SP1 --> CACHE
    CACHE --> BATCH
```

### 3. Caching Implementation

```mermaid
graph TB
    subgraph "Cache Evolution"
        OLD[No Cache]
        NEW[Circuit Cache]
        PROOF[Proof Cache]
    end

    subgraph "Features"
        LRU[LRU Policy]
        STATS[Statistics]
        CLEAN[Cleanup]
    end

    OLD --> NEW
    NEW --> PROOF
    NEW --> LRU
    PROOF --> STATS
    LRU --> CLEAN
```

### 4. Testing Framework

```mermaid
graph TB
    subgraph "Test Evolution"
        OLD[Basic Tests]
        NEW[Test Framework]
        PROP[Property Tests]
    end

    subgraph "Components"
        UNIT[Unit Tests]
        INT[Integration]
        FUZZ[Fuzzing]
        BENCH[Benchmarks]
    end

    OLD --> NEW
    NEW --> PROP
    NEW --> UNIT
    NEW --> INT
    PROP --> FUZZ
    INT --> BENCH
```

## Breaking Changes

```mermaid
graph TB
    subgraph "Interface Changes"
        TRAIT[Circuit Trait]
        PROVE[Proving API]
        VERIFY[Verification API]
    end

    subgraph "Data Changes"
        FORMAT[Circuit Format]
        PROOF[Proof Format]
        META[Metadata]
    end

    subgraph "Backend Changes"
        BACK[Backend API]
        CACHE[Cache API]
        CONFIG[Configuration]
    end

    TRAIT --> FORMAT
    PROVE --> PROOF
    VERIFY --> META
    FORMAT --> BACK
    PROOF --> CACHE
    META --> CONFIG
```

## Migration Benefits

1. Enhanced Functionality
   - Multiple circuit types
   - Rich proving options
   - Advanced verification

2. Improved Performance
   - Circuit caching
   - Proof caching
   - Parallel execution

3. Better Development
   - Comprehensive testing
   - Better error handling
   - Debugging tools

4. Future-Proofing
   - Backend abstraction
   - Extensible design
   - Upgrade path

## Migration Timeline

```mermaid
gantt
    title Migration Timeline
    dateFormat YYYY-MM
    
    section Core
    Circuit Trait    :2023-10, 1M
    Backend Trait    :2023-11, 1M
    Caching System   :2023-12, 1M

    section Features
    RISC0 Backend    :2024-01, 2M
    SP1 Migration    :2024-02, 1M
    Testing Framework :2024-03, 1M

    section Integration
    Circuit Types    :2024-04, 2M
    Performance Opt  :2024-05, 1M
    Documentation    :2024-06, 1M
```

## Migration Steps

1. Preparation
   - Audit existing circuits
   - Plan backend support
   - Update dependencies

2. Core Updates
   - Implement circuit trait
   - Add backend abstraction
   - Setup caching

3. Feature Migration
   - Add circuit types
   - Implement backends
   - Add testing

4. Integration
   - Update applications
   - Migrate circuits
   - Update documentation

## Backward Compatibility

1. Compatibility Layer
   - Legacy circuit support
   - Format conversion
   - API compatibility

2. Migration Tools
   - Circuit converter
   - Proof converter
   - Verification tools

## Testing Strategy

1. Unit Tests
   - Circuit implementations
   - Backend integration
   - Cache operations

2. Integration Tests
   - End-to-end proving
   - Cross-backend verification
   - Performance testing

3. Migration Tests
   - Format conversion
   - API compatibility
   - Performance comparison 