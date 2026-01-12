import { keccak256, getBytes } from "ethers";

export const MERKLE_TREE_DEPTH = 20;

export const FIELD_SIZE = BigInt(
  "21888242871839275222246405745257275088548364400416034343698204186575808495617"
);

export const DEFAULT_GAS_LIMIT = 500000n;
export const DEFAULT_BATCH_SIZE = 10;
export const PROOF_EXPIRY_MS = 300000;

export const CONTRACT_ADDRESSES = {
  ethereum: {
    mainnet: {
      vault: "0x0000000000000000000000000000000000000000",
      zkVerifier: "0x0000000000000000000000000000000000000000",
      aspRegistry: "0x0000000000000000000000000000000000000000",
    },
    celoSepolia: {
      vault: "0x68F19280d3030eaE36B8Da42621B66e92a8AEA32",
      zkVerifier: "0x68491614a84C0410E9Fc0CB59Fc60A4F9188687c",
      aspRegistry: "0xB041Cff58FB866c7f4326e0767c97B93434aBa9E",
    },
  },
  phala: {
    mainnet: {
      phatContract: "",
    },
    testnet: {
      phatContract: "",
    },
  },
} as const;

export const CHAIN_CONFIG = {
  1: {
    name: "Ethereum Mainnet",
    rpcUrl: "https://eth.llamarpc.com",
    explorer: "https://etherscan.io",
  },
  11142220: {
    name: "Celo Sepolia",
    rpcUrl: "https://forno.celo-sepolia.celo-testnet.org",
    explorer: "https://sepolia.celoscan.io",
  },
  2035: {
    name: "Phala L2",
    rpcUrl: "https://rpc.phala.network",
    explorer: "https://explorer.phala.network",
  },
} as const;

export const POSEIDON_CONSTANTS = {
  T: 3,
  ROUNDS_F: 8,
  ROUNDS_P: 57,
} as const;

export const PRIVACY_VAULT_ABI = [
  "function deposit(bytes32 commitment) external payable",
  "function withdraw(bytes32 nullifierHash, bytes32 root, address recipient, uint256 amount, bytes calldata zkProof, bytes calldata teeAttestation) external",
  "function withdrawWithCompliance(bytes32 nullifierHash, bytes32 root, address recipient, uint256 amount, bytes calldata zkProof, bytes calldata associationProof, address aspProvider) external",
  "function isKnownRoot(bytes32 root) external view returns (bool)",
  "function getLatestRoot() external view returns (bytes32)",
  "function getNextLeafIndex() external view returns (uint256)",
  "function isNullifierUsed(bytes32 nullifier) external view returns (bool)",
  "function getUserDeposits(address user) external view returns (bytes32[])",
  "event Deposit(bytes32 indexed commitment, uint256 leafIndex, uint256 amount, uint256 timestamp)",
  "event Withdrawal(bytes32 indexed nullifierHash, address indexed recipient, uint256 amount, bytes32 merkleRoot)",
] as const;

export const ZK_VERIFIER_ABI = [
  "function verifyProof(bytes calldata proof, bytes32[] calldata publicInputs) external returns (bool)",
  "function verifyProofView(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool)",
  "function isProofVerified(bytes32 proofHash) external view returns (bool)",
] as const;

export const ASP_REGISTRY_ABI = [
  "function isRegistered(address provider) external view returns (bool)",
  "function getProviderRoot(address provider) external view returns (bytes32)",
  "function getActiveProviders() external view returns (address[])",
  "function getHighReputationProviders(uint256 minScore) external view returns (address[])",
] as const;

export const ZERO_BYTES32 = new Uint8Array(32);

export function getZeroNode(level: number): Uint8Array {
  const zeros: Uint8Array[] = [ZERO_BYTES32];

  for (let i = 1; i <= level; i++) {
    const prev = zeros[i - 1];
    const combined = new Uint8Array(64);
    combined.set(prev, 0);
    combined.set(prev, 32);
    zeros.push(hashKeccak256(combined));
  }

  return zeros[level];
}

function hashKeccak256(data: Uint8Array): Uint8Array {
  return getBytes(keccak256(data));
}
