export interface DepositNote {
  commitment: Uint8Array;
  secret: Uint8Array;
  nullifierSeed: Uint8Array;
  amount: bigint;
  leafIndex: number;
  timestamp: number;
}

export interface WithdrawalRequest {
  commitment: Uint8Array;
  nullifier: Uint8Array;
  recipient: string;
  amount: bigint;
  merklePath: Uint8Array[];
  pathIndices: boolean[];
}

export interface WithdrawalResult {
  success: boolean;
  txHash?: string;
  zkProof: Uint8Array;
  teeAttestation: Uint8Array;
  error?: string;
}

export interface DepositResult {
  success: boolean;
  txHash: string;
  commitment: Uint8Array;
  leafIndex: number;
  note: DepositNote;
}

export interface ComplianceProof {
  depositCommitment: Uint8Array;
  associationRoot: Uint8Array;
  zkProof: Uint8Array;
  aspSignature: Uint8Array;
  timestamp: number;
}

export interface MerkleProof {
  path: Uint8Array[];
  indices: boolean[];
  root: Uint8Array;
}

export interface TEEAttestation {
  dataHash: Uint8Array;
  timestamp: number;
  enclaveId: Uint8Array;
  signature: Uint8Array;
}

export interface VaultConfig {
  vaultAddress: string;
  zkVerifierAddress: string;
  aspRegistryAddress: string;
  phatContractAddress: string;
  chainId: number;
  rpcUrl: string;
}

export interface ASPProvider {
  address: string;
  name: string;
  currentRoot: Uint8Array;
  reputationScore: number;
  active: boolean;
}

export interface VaultStats {
  totalDeposits: bigint;
  totalWithdrawals: bigint;
  nextLeafIndex: number;
  latestRoot: Uint8Array;
}

export type ProofStatus = "pending" | "verified" | "rejected" | "expired";

export interface BatchWithdrawal {
  requests: WithdrawalRequest[];
  aggregatedProof?: Uint8Array;
  status: ProofStatus;
}
