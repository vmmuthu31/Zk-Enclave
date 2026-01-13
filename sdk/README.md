# zkenclave-sdk

Privacy-preserving vault SDK for Zero-Knowledge withdrawals on EVM chains.

## Installation

```bash
npm install zkenclave-sdk
```

## Quick Start

```typescript
import { PrivacyVaultSDK, ZKProofClient } from "zkenclave-sdk";

const sdk = new PrivacyVaultSDK(
  {
    vaultAddress: "0x68F19280d3030eaE36B8Da42621B66e92a8AEA32",
    zkVerifierAddress: "0x68491614a84C0410E9Fc0CB59Fc60A4F9188687c",
    aspRegistryAddress: "0xB041Cff58FB866c7f4326e0767c97B93434aBa9E",
    chainId: 845320009,
    rpcUrl: "https://horizen-rpc-testnet.appchain.base.org",
  },
  signer
);

// Deposit
const { note, txHash, leafIndex } = await sdk.deposit(parseEther("0.1"));

// Withdraw
const result = await sdk.withdraw(note, recipientAddress);
```

## Features

- **Privacy-preserving deposits** - Commitment-nullifier scheme
- **ZK proof generation** - Client-side via `ZKProofClient`
- **Multi-chain support** - Configurable RPC/chain
- **TypeScript** - Full type definitions

## API

### `PrivacyVaultSDK`

| Method                       | Description               |
| ---------------------------- | ------------------------- |
| `deposit(amount)`            | Deposit ETH, returns note |
| `withdraw(note, recipient)`  | Withdraw using note       |
| `getLatestRoot()`            | Get current Merkle root   |
| `getNextLeafIndex()`         | Get next deposit index    |
| `isNullifierUsed(nullifier)` | Check if nullifier spent  |

### `ZKProofClient`

| Method                                      | Description               |
| ------------------------------------------- | ------------------------- |
| `generateWithdrawalProof(request)`          | Generate ZK proof         |
| `generateComplianceProof(commitment, root)` | Generate compliance proof |

## Types

```typescript
interface VaultConfig {
  vaultAddress: string;
  zkVerifierAddress: string;
  aspRegistryAddress: string;
  chainId: number;
  rpcUrl: string;
}

interface DepositNote {
  commitment: Uint8Array;
  secret: Uint8Array;
  nullifierSeed: Uint8Array;
  amount: bigint;
  leafIndex: number;
  timestamp: number;
}
```

## Deployed Contracts (Horizen Sepolia)

| Contract     | Address                                      |
| ------------ | -------------------------------------------- |
| PrivacyVault | `0x68F19280d3030eaE36B8Da42621B66e92a8AEA32` |
| ZKVerifier   | `0x68491614a84C0410E9Fc0CB59Fc60A4F9188687c` |
| ASPRegistry  | `0xB041Cff58FB866c7f4326e0767c97B93434aBa9E` |

## License

MIT
