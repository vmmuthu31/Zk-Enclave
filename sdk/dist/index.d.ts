import { ethers } from 'ethers';

interface DepositNote {
    commitment: Uint8Array;
    secret: Uint8Array;
    nullifierSeed: Uint8Array;
    amount: bigint;
    leafIndex: number;
    timestamp: number;
}
interface WithdrawalRequest {
    commitment: Uint8Array;
    nullifier: Uint8Array;
    recipient: string;
    amount: bigint;
    leafIndex: number;
    merkleRoot?: Uint8Array;
    merklePath: Uint8Array[];
    pathIndices: boolean[];
    secret?: Uint8Array;
}
interface WithdrawalResult {
    success: boolean;
    txHash?: string;
    zkProof: Uint8Array;
    nullifierHash: Uint8Array;
    merkleRoot: Uint8Array;
    timestamp: number;
    error?: string;
}
interface DepositResult {
    success: boolean;
    txHash: string;
    commitment: Uint8Array;
    leafIndex: number;
    note: DepositNote;
}
interface ComplianceProof {
    id: string;
    depositCommitment?: Uint8Array;
    associationRoot: Uint8Array;
    zkProof?: Uint8Array;
    proof: Uint8Array;
    valid: boolean;
    timestamp: number;
}
interface MerkleProof {
    path: Uint8Array[];
    indices: boolean[];
    root: Uint8Array;
}
interface TEEAttestation {
    dataHash: Uint8Array;
    timestamp: number;
    enclaveId: Uint8Array;
    signature: Uint8Array;
}
interface VaultConfig {
    vaultAddress: string;
    zkVerifierAddress: string;
    aspRegistryAddress: string;
    chainId: number;
    rpcUrl: string;
}
interface ASPProvider {
    address: string;
    name: string;
    currentRoot: Uint8Array;
    reputationScore: number;
    active: boolean;
}
interface VaultStats {
    totalDeposits: bigint;
    totalWithdrawals: bigint;
    nextLeafIndex: number;
    latestRoot: Uint8Array;
}
type ProofStatus = "pending" | "verified" | "rejected" | "expired";
interface BatchWithdrawal {
    requests: WithdrawalRequest[];
    aggregatedProof?: Uint8Array;
    status: ProofStatus;
}

interface ZKProofClientConfig {
    wasmPath?: string;
    useRealProofs?: boolean;
}
declare class ZKProofClient {
    private config;
    private wasmReady;
    constructor(config?: ZKProofClientConfig);
    private loadWasm;
    generateWithdrawalProof(request: WithdrawalRequest): Promise<WithdrawalResult>;
    private generateRealProof;
    private generateFallbackProof;
    generateComplianceProof(commitment: Uint8Array, associationRoot: Uint8Array): Promise<ComplianceProof>;
    verifyProof(proofResult: WithdrawalResult): Promise<boolean>;
    isWasmReady(): boolean;
    private computeNullifierHash;
    private addressToBytes;
    private hexToBytes;
}

declare class PrivacyVaultSDK {
    private provider;
    private signer;
    private vault;
    private readVault;
    private _aspRegistry;
    private zkClient;
    private config;
    private _merkleTree;
    constructor(config: VaultConfig, signer?: ethers.Signer, zkClient?: ZKProofClient);
    connect(signer: ethers.Signer): Promise<void>;
    deposit(amount: bigint): Promise<DepositResult>;
    withdraw(note: DepositNote, recipient: string): Promise<WithdrawalResult>;
    getLatestRoot(): Promise<Uint8Array>;
    getNextLeafIndex(): Promise<number>;
    isNullifierUsed(nullifier: Uint8Array): Promise<boolean>;
    isKnownRoot(root: Uint8Array): Promise<boolean>;
    getVaultStats(): Promise<VaultStats>;
    getConfig(): VaultConfig;
}

declare function generateRandomBytes(length: number): Uint8Array;
declare function bytesToHex(bytes: Uint8Array): string;
declare function hexToBytes(hex: string): Uint8Array;
declare function bigIntToBytes32(value: bigint): Uint8Array;
declare function bytes32ToBigInt(bytes: Uint8Array): bigint;
declare function poseidonHash(inputs: bigint[]): bigint;
declare function computeCommitment(secret: bigint, nullifierSeed: bigint, amount: bigint): bigint;
declare function computeNullifier(nullifierSeed: bigint, leafIndex: number): bigint;
declare function generateDepositNote(amount: bigint): DepositNote;
declare function serializeNote(note: DepositNote): string;
declare function deserializeNote(serialized: string): DepositNote;
declare function encryptNote(note: DepositNote, password: string): string;
declare function decryptNote(encrypted: string, password: string): DepositNote;
declare class MerkleTree {
    private leaves;
    private layers;
    private readonly depth;
    private readonly zeroValues;
    constructor(depth?: number);
    private computeZeroValues;
    insert(leaf: bigint): number;
    private rebuild;
    getRoot(): bigint;
    generateProof(index: number): MerkleProof;
    verifyProof(leaf: bigint, proof: MerkleProof): boolean;
}

declare const MERKLE_TREE_DEPTH = 20;
declare const FIELD_SIZE: bigint;
declare const DEFAULT_GAS_LIMIT = 500000n;
declare const DEFAULT_BATCH_SIZE = 10;
declare const PROOF_EXPIRY_MS = 300000;
declare const CONTRACT_ADDRESSES: {
    readonly ethereum: {
        readonly mainnet: {
            readonly vault: "0x0000000000000000000000000000000000000000";
            readonly zkVerifier: "0x0000000000000000000000000000000000000000";
            readonly aspRegistry: "0x0000000000000000000000000000000000000000";
        };
        readonly celoSepolia: {
            readonly vault: "0x68F19280d3030eaE36B8Da42621B66e92a8AEA32";
            readonly zkVerifier: "0x68491614a84C0410E9Fc0CB59Fc60A4F9188687c";
            readonly aspRegistry: "0xB041Cff58FB866c7f4326e0767c97B93434aBa9E";
        };
        readonly horizenSepolia: {
            readonly vault: "0x68F19280d3030eaE36B8Da42621B66e92a8AEA32";
            readonly zkVerifier: "0x68491614a84C0410E9Fc0CB59Fc60A4F9188687c";
            readonly aspRegistry: "0xB041Cff58FB866c7f4326e0767c97B93434aBa9E";
        };
    };
    readonly phala: {
        readonly mainnet: {
            readonly phatContract: "";
        };
        readonly testnet: {
            readonly phatContract: "";
        };
    };
};
declare const CHAIN_CONFIG: {
    readonly 1: {
        readonly name: "Ethereum Mainnet";
        readonly rpcUrl: "https://eth.llamarpc.com";
        readonly explorer: "https://etherscan.io";
    };
    readonly 11142220: {
        readonly name: "Celo Sepolia";
        readonly rpcUrl: "https://forno.celo-sepolia.celo-testnet.org";
        readonly explorer: "https://sepolia.celoscan.io";
    };
    readonly 2035: {
        readonly name: "Phala L2";
        readonly rpcUrl: "https://rpc.phala.network";
        readonly explorer: "https://explorer.phala.network";
    };
    readonly 845320009: {
        readonly name: "Horizen Sepolia Testnet";
        readonly rpcUrl: "https://horizen-rpc-testnet.appchain.base.org";
        readonly explorer: "https://explorer-horizen-testnet.appchain.base.org";
    };
};
declare const POSEIDON_CONSTANTS: {
    readonly T: 3;
    readonly ROUNDS_F: 8;
    readonly ROUNDS_P: 57;
};
declare const PRIVACY_VAULT_ABI: readonly ["function deposit(bytes32 commitment) external payable", "function withdraw(bytes32 nullifierHash, bytes32 root, address recipient, uint256 amount, bytes calldata zkProof, bytes calldata teeAttestation) external", "function withdrawWithCompliance(bytes32 nullifierHash, bytes32 root, address recipient, uint256 amount, bytes calldata zkProof, bytes calldata associationProof, address aspProvider) external", "function isKnownRoot(bytes32 root) external view returns (bool)", "function getLatestRoot() external view returns (bytes32)", "function getNextLeafIndex() external view returns (uint256)", "function isNullifierUsed(bytes32 nullifier) external view returns (bool)", "function getUserDeposits(address user) external view returns (bytes32[])", "event Deposit(bytes32 indexed commitment, uint256 leafIndex, uint256 amount, uint256 timestamp)", "event Withdrawal(bytes32 indexed nullifierHash, address indexed recipient, uint256 amount, bytes32 merkleRoot)"];
declare const ZK_VERIFIER_ABI: readonly ["function verifyProof(bytes calldata proof, bytes32[] calldata publicInputs) external returns (bool)", "function verifyProofView(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool)", "function isProofVerified(bytes32 proofHash) external view returns (bool)"];
declare const ASP_REGISTRY_ABI: readonly ["function isRegistered(address provider) external view returns (bool)", "function getProviderRoot(address provider) external view returns (bytes32)", "function getActiveProviders() external view returns (address[])", "function getHighReputationProviders(uint256 minScore) external view returns (address[])"];
declare const ZERO_BYTES32: Uint8Array<ArrayBuffer>;
declare function getZeroNode(level: number): Uint8Array;

export { type ASPProvider, ASP_REGISTRY_ABI, type BatchWithdrawal, CHAIN_CONFIG, CONTRACT_ADDRESSES, type ComplianceProof, DEFAULT_BATCH_SIZE, DEFAULT_GAS_LIMIT, type DepositNote, type DepositResult, FIELD_SIZE, MERKLE_TREE_DEPTH, type MerkleProof, MerkleTree, POSEIDON_CONSTANTS, PRIVACY_VAULT_ABI, PROOF_EXPIRY_MS, PrivacyVaultSDK, type ProofStatus, type TEEAttestation, type VaultConfig, type VaultStats, type WithdrawalRequest, type WithdrawalResult, ZERO_BYTES32, ZKProofClient, ZK_VERIFIER_ABI, bigIntToBytes32, bytes32ToBigInt, bytesToHex, computeCommitment, computeNullifier, decryptNote, deserializeNote, encryptNote, generateDepositNote, generateRandomBytes, getZeroNode, hexToBytes, poseidonHash, serializeNote };
