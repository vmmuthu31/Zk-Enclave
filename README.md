# zkenclave

A privacy-preserving withdrawal mechanism for EVM vaults using Trusted Execution Environments (TEE) and native ZK circuits.

## Overview

zkenclave enables private withdrawals from an EVM vault while maintaining regulatory compliance through:

- **Phala TEE** - Confidential computing for sensitive withdrawal processing
- **Native ZK Circuits (Halo2)** - Fast proof generation without trusted setup
- **Privacy Pools** - Association Set Providers for compliance without revealing transaction details

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         User Layer                               │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐          │
│  │  Web/SDK    │    │   Wallet    │    │  Note Mgmt  │          │
│  └─────────────┘    └─────────────┘    └─────────────┘          │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                        EVM Layer                                 │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐          │
│  │PrivacyVault │    │ ZKVerifier  │    │ ASPRegistry │          │
│  └─────────────┘    └─────────────┘    └─────────────┘          │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Phala TEE Layer                             │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                    TEE Enclave                             │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │  │
│  │  │  Processor  │  │  ZK Prover  │  │    State    │        │  │
│  │  └─────────────┘  └─────────────┘  └─────────────┘        │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Compliance Layer                             │
│  ┌─────────────────────────┐    ┌─────────────────────────┐     │
│  │   Association Set       │    │   Encrypted Audit       │     │
│  │       Provider          │    │       Trail             │     │
│  └─────────────────────────┘    └─────────────────────────┘     │
└─────────────────────────────────────────────────────────────────┘
```

## Project Structure

```
zkenclave/
├── contracts/           # Solidity smart contracts
│   ├── PrivacyVault.sol     # Main vault contract
│   ├── ZKVerifier.sol       # ZK proof verifier
│   ├── ASPRegistry.sol      # Compliance provider registry
│   └── libraries/
│       ├── MerkleTree.sol   # Merkle tree operations
│       └── PoseidonT3.sol   # ZK-friendly hash
│
├── phat-contract/       # Phala TEE contract (Rust/ink!)
│   └── src/
│       ├── lib.rs           # Contract entry point
│       ├── processor.rs     # Withdrawal processing
│       └── state.rs         # Encrypted state mgmt
│
├── zk-circuits/         # Native Halo2 ZK circuits
│   └── src/
│       ├── lib.rs               # Main exports
│       ├── poseidon.rs          # Poseidon hash chip
│       ├── merkle.rs            # Merkle tree gadget
│       ├── withdrawal_circuit.rs    # Withdrawal proof
│       └── association_circuit.rs   # Compliance proof
│
├── compliance/          # Compliance infrastructure
│   └── src/
│       ├── asp_provider.rs  # Association Set Provider
│       └── audit_trail.rs   # Encrypted audit logs
│
├── sdk/                 # TypeScript SDK
│   └── src/
│       ├── vault.ts         # Main SDK class
│       ├── crypto.ts        # Crypto utilities
│       ├── phat-client.ts   # Phat contract client
│       └── types.ts         # Type definitions
│
└── docs/                # Documentation
```

## Quick Start

### Prerequisites

- Rust 1.75+
- Node.js 18+
- Foundry (for Solidity)

### Installation

```bash
# Clone the repository
git clone <repo-url>
cd zkenclave

# Install SDK dependencies
cd sdk && npm install

# Build ZK circuits
cd ../zk-circuits && cargo build --release

# Build Phat contract
cd ../phat-contract && cargo contract build --release
```

### Usage

```typescript
import {
  PrivacyVaultSDK,
  generateDepositNote,
  serializeNote,
} from "@zkenclave/sdk";

// Initialize SDK
const sdk = new PrivacyVaultSDK({
  vaultAddress: "0x...",
  zkVerifierAddress: "0x...",
  aspRegistryAddress: "0x...",
  phatContractAddress: "...",
  chainId: 1,
  rpcUrl: "https://eth.llamarpc.com",
});

// Connect wallet
await sdk.connect(signer);

// Deposit funds
const depositResult = await sdk.deposit(parseEther("1"));
const noteBackup = serializeNote(depositResult.note);

// Withdraw privately
const withdrawResult = await sdk.withdraw(depositResult.note, recipientAddress);

// Withdraw with compliance proof
const complianceResult = await sdk.withdrawWithCompliance(
  depositResult.note,
  recipientAddress,
  aspProviderAddress
);
```

## Key Features

### 1. Privacy Preservation

- Deposits create cryptographic commitments
- Withdrawals break the on-chain link between deposit and withdrawal
- Zero-knowledge proofs prove validity without revealing details

### 2. TEE Security

- Withdrawal processing inside Phala's secure enclave
- Hardware-level isolation protects sensitive data
- TEE attestation proves correct execution

### 3. Native ZK Performance

- Halo2-based circuits for ~50% faster proofs
- No trusted setup required
- Parallelizable proof generation

### 4. Regulatory Compliance

- Association Set Providers maintain approved deposit lists
- Users can prove funds aren't from sanctioned sources
- Encrypted audit trail for selective disclosure to regulators

## Security Considerations

- **Nullifier uniqueness**: Each deposit can only be withdrawn once
- **Merkle tree depth**: 20 levels supports ~1M deposits
- **TEE attestation**: Verify enclave reports before trusting responses
- **Note backup**: Lost notes = lost funds

## License

MIT License - see [LICENSE](./LICENSE) for details.
