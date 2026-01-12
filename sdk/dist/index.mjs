// src/vault.ts
import { ethers } from "ethers";

// src/constants.ts
var MERKLE_TREE_DEPTH = 20;
var FIELD_SIZE = BigInt(
  "21888242871839275222246405745257275088548364400416034343698204186575808495617"
);
var DEFAULT_GAS_LIMIT = 500000n;
var DEFAULT_BATCH_SIZE = 10;
var PROOF_EXPIRY_MS = 3e5;
var CONTRACT_ADDRESSES = {
  ethereum: {
    mainnet: {
      vault: "0x0000000000000000000000000000000000000000",
      zkVerifier: "0x0000000000000000000000000000000000000000",
      aspRegistry: "0x0000000000000000000000000000000000000000"
    },
    sepolia: {
      vault: "0x0000000000000000000000000000000000000000",
      zkVerifier: "0x0000000000000000000000000000000000000000",
      aspRegistry: "0x0000000000000000000000000000000000000000"
    }
  },
  phala: {
    mainnet: {
      phatContract: ""
    },
    testnet: {
      phatContract: ""
    }
  }
};
var CHAIN_CONFIG = {
  1: {
    name: "Ethereum Mainnet",
    rpcUrl: "https://eth.llamarpc.com",
    explorer: "https://etherscan.io"
  },
  11155111: {
    name: "Sepolia Testnet",
    rpcUrl: "https://rpc.sepolia.org",
    explorer: "https://sepolia.etherscan.io"
  },
  2035: {
    name: "Phala L2",
    rpcUrl: "https://rpc.phala.network",
    explorer: "https://explorer.phala.network"
  }
};
var POSEIDON_CONSTANTS = {
  T: 3,
  ROUNDS_F: 8,
  ROUNDS_P: 57
};
var PRIVACY_VAULT_ABI = [
  "function deposit(bytes32 commitment) external payable",
  "function withdraw(bytes32 nullifierHash, bytes32 root, address recipient, uint256 amount, bytes calldata zkProof, bytes calldata teeAttestation) external",
  "function withdrawWithCompliance(bytes32 nullifierHash, bytes32 root, address recipient, uint256 amount, bytes calldata zkProof, bytes calldata associationProof, address aspProvider) external",
  "function isKnownRoot(bytes32 root) external view returns (bool)",
  "function getLatestRoot() external view returns (bytes32)",
  "function getNextLeafIndex() external view returns (uint256)",
  "function isNullifierUsed(bytes32 nullifier) external view returns (bool)",
  "function getUserDeposits(address user) external view returns (bytes32[])",
  "event Deposit(bytes32 indexed commitment, uint256 leafIndex, uint256 amount, uint256 timestamp)",
  "event Withdrawal(bytes32 indexed nullifierHash, address indexed recipient, uint256 amount, bytes32 merkleRoot)"
];
var ZK_VERIFIER_ABI = [
  "function verifyProof(bytes calldata proof, bytes32[] calldata publicInputs) external returns (bool)",
  "function verifyProofView(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool)",
  "function isProofVerified(bytes32 proofHash) external view returns (bool)"
];
var ASP_REGISTRY_ABI = [
  "function isRegistered(address provider) external view returns (bool)",
  "function getProviderRoot(address provider) external view returns (bytes32)",
  "function getActiveProviders() external view returns (address[])",
  "function getHighReputationProviders(uint256 minScore) external view returns (address[])"
];
var ZERO_BYTES32 = new Uint8Array(32);
function getZeroNode(level) {
  const zeros = [ZERO_BYTES32];
  for (let i = 1; i <= level; i++) {
    const prev = zeros[i - 1];
    const combined = new Uint8Array(64);
    combined.set(prev, 0);
    combined.set(prev, 32);
    zeros.push(hashKeccak256(combined));
  }
  return zeros[level];
}
function hashKeccak256(data) {
  return new Uint8Array(32);
}

// src/crypto.ts
function generateRandomBytes(length) {
  const buffer = new Uint8Array(length);
  if (typeof crypto !== "undefined" && crypto.getRandomValues) {
    crypto.getRandomValues(buffer);
  } else {
    for (let i = 0; i < length; i++) {
      buffer[i] = Math.floor(Math.random() * 256);
    }
  }
  return buffer;
}
function bytesToHex(bytes) {
  return "0x" + Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}
function hexToBytes(hex) {
  const cleanHex = hex.startsWith("0x") ? hex.slice(2) : hex;
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(cleanHex.substr(i * 2, 2), 16);
  }
  return bytes;
}
function bigIntToBytes32(value) {
  const hex = value.toString(16).padStart(64, "0");
  return hexToBytes(hex);
}
function bytes32ToBigInt(bytes) {
  if (bytes.length !== 32) {
    throw new Error("Invalid bytes32 length");
  }
  return BigInt(bytesToHex(bytes));
}
function poseidonHash(inputs) {
  if (inputs.length > 2) {
    throw new Error("Poseidon T3 supports max 2 inputs");
  }
  let state = inputs.map((i) => i % FIELD_SIZE);
  while (state.length < 3) {
    state.push(0n);
  }
  const C = [
    0x0ee9a592ba9a9518d05986d656f40c2114c4993c11bb29938d21d47304cd8e6en,
    0x00f1445235f2148c5986587169fc1bcd887b08d4d00868df5696fff40956e864n,
    0x08dff3487e8ac99e1f29a058d0fa80b930c728730b7ab36ce879f3890ecf73f5n
  ];
  const M = [
    [
      0x109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118bn,
      0x16ed41e13bb9c0c66ae119424fddbcbc9314dc9fdbdeea55d6c64543dc4903e0n,
      0x2b90bba00f05d28c6d4c9d2f1d4d3c2e7f5d8e4a3b2c1d0e9f8a7b6c5d4e3f2an
    ],
    [
      0x2969f27eed31a480b9c36c764379dbca2cc8fdd1415c3dded62940bcde0bd771n,
      0x143021ec686a3f330d5f9e654638065ce6cd79e28c5b3753326244ee65a1b1a7n,
      0x1e3f7a4c5d6b8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3fn
    ],
    [
      0x176cc029695ad02582a70eff08a6fd99d057e12e58e7d7b6b16cdfabc8ee2911n,
      0x19a3fc0a56702bf417ba7fee3802593fa644470307043f7773c5e6f71c7c5e3an,
      0x2b4129c2e5a87d9c3e1f5b7d9a2c4e6f8a0b2d4c6e8f0a2b4c6d8e0f2a4b6c8dn
    ]
  ];
  const sbox = (x) => {
    const x2 = x * x % FIELD_SIZE;
    const x4 = x2 * x2 % FIELD_SIZE;
    return x4 * x % FIELD_SIZE;
  };
  const mix = (s) => {
    const result = [];
    for (let i = 0; i < 3; i++) {
      let sum = 0n;
      for (let j = 0; j < 3; j++) {
        sum = (sum + M[i][j] * s[j]) % FIELD_SIZE;
      }
      result.push(sum);
    }
    return result;
  };
  const halfF = POSEIDON_CONSTANTS.ROUNDS_F / 2;
  for (let r = 0; r < halfF; r++) {
    for (let i = 0; i < 3; i++) {
      state[i] = (state[i] + C[i]) % FIELD_SIZE;
      state[i] = sbox(state[i]);
    }
    state = mix(state);
  }
  for (let r = 0; r < POSEIDON_CONSTANTS.ROUNDS_P; r++) {
    for (let i = 0; i < 3; i++) {
      state[i] = (state[i] + C[i]) % FIELD_SIZE;
    }
    state[0] = sbox(state[0]);
    state = mix(state);
  }
  for (let r = 0; r < halfF; r++) {
    for (let i = 0; i < 3; i++) {
      state[i] = (state[i] + C[i]) % FIELD_SIZE;
      state[i] = sbox(state[i]);
    }
    state = mix(state);
  }
  return state[0];
}
function computeCommitment(secret, nullifierSeed, amount) {
  const intermediate = poseidonHash([secret, nullifierSeed]);
  return poseidonHash([intermediate, amount]);
}
function computeNullifier(nullifierSeed, leafIndex) {
  return poseidonHash([nullifierSeed, BigInt(leafIndex)]);
}
function generateDepositNote(amount) {
  const secret = generateRandomBytes(32);
  const nullifierSeed = generateRandomBytes(32);
  const secretBigInt = bytes32ToBigInt(secret);
  const nullifierBigInt = bytes32ToBigInt(nullifierSeed);
  const commitmentBigInt = computeCommitment(
    secretBigInt,
    nullifierBigInt,
    amount
  );
  const commitment = bigIntToBytes32(commitmentBigInt);
  return {
    commitment,
    secret,
    nullifierSeed,
    amount,
    leafIndex: -1,
    timestamp: Date.now()
  };
}
function serializeNote(note) {
  const data = {
    commitment: bytesToHex(note.commitment),
    secret: bytesToHex(note.secret),
    nullifierSeed: bytesToHex(note.nullifierSeed),
    amount: note.amount.toString(),
    leafIndex: note.leafIndex,
    timestamp: note.timestamp
  };
  return btoa(JSON.stringify(data));
}
function deserializeNote(serialized) {
  const data = JSON.parse(atob(serialized));
  return {
    commitment: hexToBytes(data.commitment),
    secret: hexToBytes(data.secret),
    nullifierSeed: hexToBytes(data.nullifierSeed),
    amount: BigInt(data.amount),
    leafIndex: data.leafIndex,
    timestamp: data.timestamp
  };
}
function encryptNote(note, password) {
  const serialized = serializeNote(note);
  const encrypted = xorEncrypt(serialized, password);
  return bytesToHex(encrypted);
}
function decryptNote(encrypted, password) {
  const bytes = hexToBytes(encrypted);
  const decrypted = xorDecrypt(bytes, password);
  return deserializeNote(decrypted);
}
function xorEncrypt(data, key) {
  const dataBytes = new TextEncoder().encode(data);
  const keyBytes = new TextEncoder().encode(key);
  const result = new Uint8Array(dataBytes.length);
  for (let i = 0; i < dataBytes.length; i++) {
    result[i] = dataBytes[i] ^ keyBytes[i % keyBytes.length];
  }
  return result;
}
function xorDecrypt(data, key) {
  const keyBytes = new TextEncoder().encode(key);
  const result = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i++) {
    result[i] = data[i] ^ keyBytes[i % keyBytes.length];
  }
  return new TextDecoder().decode(result);
}
var MerkleTree = class {
  leaves;
  layers;
  depth;
  zeroValues;
  constructor(depth = MERKLE_TREE_DEPTH) {
    this.depth = depth;
    this.leaves = [];
    this.layers = [];
    this.zeroValues = this.computeZeroValues();
  }
  computeZeroValues() {
    const zeros = [0n];
    for (let i = 1; i <= this.depth; i++) {
      zeros.push(poseidonHash([zeros[i - 1], zeros[i - 1]]));
    }
    return zeros;
  }
  insert(leaf) {
    const index = this.leaves.length;
    this.leaves.push(leaf);
    this.rebuild();
    return index;
  }
  rebuild() {
    this.layers = [this.leaves.slice()];
    const targetSize = 1 << this.depth;
    while (this.layers[0].length < targetSize) {
      this.layers[0].push(this.zeroValues[0]);
    }
    for (let level = 0; level < this.depth; level++) {
      const currentLayer = this.layers[level];
      const nextLayer = [];
      for (let i = 0; i < currentLayer.length; i += 2) {
        const left = currentLayer[i];
        const right = currentLayer[i + 1] ?? this.zeroValues[level];
        nextLayer.push(poseidonHash([left, right]));
      }
      this.layers.push(nextLayer);
    }
  }
  getRoot() {
    if (this.layers.length === 0) {
      return this.zeroValues[this.depth];
    }
    return this.layers[this.layers.length - 1][0];
  }
  generateProof(index) {
    if (index >= this.leaves.length) {
      throw new Error("Index out of bounds");
    }
    const path = [];
    const indices = [];
    let currentIndex = index;
    for (let level = 0; level < this.depth; level++) {
      const isRight = currentIndex % 2 === 1;
      const siblingIndex = isRight ? currentIndex - 1 : currentIndex + 1;
      const sibling = this.layers[level][siblingIndex] ?? this.zeroValues[level];
      path.push(bigIntToBytes32(sibling));
      indices.push(isRight);
      currentIndex = Math.floor(currentIndex / 2);
    }
    return {
      path,
      indices,
      root: bigIntToBytes32(this.getRoot())
    };
  }
  verifyProof(leaf, proof) {
    let current = leaf;
    for (let i = 0; i < proof.path.length; i++) {
      const sibling = bytes32ToBigInt(proof.path[i]);
      if (proof.indices[i]) {
        current = poseidonHash([sibling, current]);
      } else {
        current = poseidonHash([current, sibling]);
      }
    }
    return current === bytes32ToBigInt(proof.root);
  }
};

// src/phat-client.ts
var PhatClient = class {
  contractAddress;
  endpoint;
  timeout;
  constructor(contractAddress, config) {
    this.contractAddress = contractAddress;
    this.endpoint = config?.endpoint ?? "https://poc5.phala.network/tee-api/v1";
    this.timeout = config?.timeout ?? 3e4;
  }
  async processWithdrawal(request) {
    try {
      const encodedRequest = this.encodeWithdrawalRequest(request);
      const response = await this.callPhatContract(
        "process_withdrawal",
        encodedRequest
      );
      return this.decodeWithdrawalResponse(response);
    } catch (error) {
      return {
        success: false,
        zkProof: new Uint8Array(),
        teeAttestation: new Uint8Array(),
        error: error instanceof Error ? error.message : "Unknown error"
      };
    }
  }
  async generateComplianceProof(commitment, aspProvider) {
    const params = {
      commitment: bytesToHex(commitment),
      asp_provider: aspProvider
    };
    const response = await this.callPhatContract(
      "generate_compliance_proof",
      params
    );
    return this.decodeComplianceProof(response);
  }
  async getAttestationReport() {
    const response = await this.callPhatContract(
      "get_tee_attestation_report",
      {}
    );
    return hexToBytes(response.attestation);
  }
  async isNullifierUsed(nullifier) {
    const params = {
      nullifier: bytesToHex(nullifier)
    };
    const response = await this.callPhatContract("is_nullifier_used", params);
    return response.used === true;
  }
  async getCommitmentRoot() {
    const response = await this.callPhatContract("get_commitment_root", {});
    return hexToBytes(response.root);
  }
  async callPhatContract(method, params) {
    if (this.contractAddress === "" || this.contractAddress === "0x") {
      return this.simulateLocalResponse(method, params);
    }
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);
    try {
      const response = await fetch(`${this.endpoint}/call`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          contract: this.contractAddress,
          method,
          params
        }),
        signal: controller.signal
      });
      if (!response.ok) {
        throw new Error(`Phat contract call failed: ${response.statusText}`);
      }
      return await response.json();
    } finally {
      clearTimeout(timeoutId);
    }
  }
  simulateLocalResponse(method, params) {
    switch (method) {
      case "process_withdrawal": {
        const request = params;
        const mockProof = new Uint8Array(256);
        mockProof[0] = 1;
        const commitmentBytes = hexToBytes(request.commitment);
        const nullifierBytes = hexToBytes(request.nullifier);
        mockProof.set(this.simpleHash(commitmentBytes), 1);
        mockProof.set(commitmentBytes, 33);
        mockProof.set(nullifierBytes, 65);
        const mockAttestation = new Uint8Array(128);
        mockAttestation.set(this.simpleHash(mockProof.slice(0, 97)), 0);
        const timestamp = BigInt(Date.now());
        for (let i = 0; i < 8; i++) {
          mockAttestation[32 + i] = Number(
            timestamp >> BigInt(i * 8) & 0xffn
          );
        }
        return {
          success: true,
          tx_hash: null,
          zk_proof: bytesToHex(mockProof),
          tee_attestation: bytesToHex(mockAttestation),
          error: null
        };
      }
      case "generate_compliance_proof": {
        const request = params;
        const commitmentBytes = hexToBytes(request.commitment);
        const mockRoot = this.simpleHash(commitmentBytes);
        const mockProof = new Uint8Array(64);
        mockProof.set(mockRoot, 0);
        return {
          deposit_commitment: request.commitment,
          association_root: bytesToHex(mockRoot),
          zk_proof: bytesToHex(mockProof),
          asp_signature: bytesToHex(new Uint8Array(64)),
          timestamp: Date.now()
        };
      }
      case "get_tee_attestation_report": {
        const mockReport = new Uint8Array(96);
        return {
          attestation: bytesToHex(mockReport)
        };
      }
      case "is_nullifier_used":
        return { used: false };
      case "get_commitment_root":
        return { root: bytesToHex(new Uint8Array(32)) };
      default:
        throw new Error(`Unknown method: ${method}`);
    }
  }
  simpleHash(data) {
    const result = new Uint8Array(32);
    let hash = 2166136261;
    for (let i = 0; i < data.length; i++) {
      hash ^= data[i];
      hash = Math.imul(hash, 16777619);
    }
    for (let i = 0; i < 32; i++) {
      result[i] = hash >> i % 4 * 8 & 255;
      hash = Math.imul(hash, 16777619) ^ i;
    }
    return result;
  }
  encodeWithdrawalRequest(request) {
    return {
      commitment: bytesToHex(request.commitment),
      nullifier: bytesToHex(request.nullifier),
      recipient: request.recipient,
      amount: request.amount.toString(),
      merkle_proof: request.merklePath.map((p) => bytesToHex(p)),
      proof_indices: request.pathIndices
    };
  }
  decodeWithdrawalResponse(response) {
    return {
      success: response.success,
      txHash: response.tx_hash,
      zkProof: hexToBytes(response.zk_proof),
      teeAttestation: hexToBytes(response.tee_attestation),
      error: response.error
    };
  }
  decodeComplianceProof(response) {
    return {
      depositCommitment: hexToBytes(response.deposit_commitment),
      associationRoot: hexToBytes(response.association_root),
      zkProof: hexToBytes(response.zk_proof),
      aspSignature: hexToBytes(response.asp_signature),
      timestamp: response.timestamp
    };
  }
};

// src/vault.ts
var PrivacyVaultSDK = class {
  provider;
  signer = null;
  vault;
  _zkVerifier;
  aspRegistry;
  phatClient;
  config;
  merkleTree;
  constructor(config, signer) {
    this.config = config;
    this.provider = new ethers.JsonRpcProvider(config.rpcUrl);
    if (signer) {
      this.signer = signer;
    }
    this.vault = new ethers.Contract(
      config.vaultAddress,
      PRIVACY_VAULT_ABI,
      this.signer ?? this.provider
    );
    this._zkVerifier = new ethers.Contract(
      config.zkVerifierAddress,
      ZK_VERIFIER_ABI,
      this.provider
    );
    this.aspRegistry = new ethers.Contract(
      config.aspRegistryAddress,
      ASP_REGISTRY_ABI,
      this.provider
    );
    this.phatClient = new PhatClient(config.phatContractAddress);
    this.merkleTree = new MerkleTree();
  }
  async connect(signer) {
    this.signer = signer;
    this.vault = this.vault.connect(signer);
  }
  async deposit(amount) {
    if (!this.signer) {
      throw new Error("Signer required for deposits");
    }
    const note = generateDepositNote(amount);
    const commitmentHex = bytesToHex(note.commitment);
    const tx = await this.vault.deposit(commitmentHex, {
      value: amount,
      gasLimit: DEFAULT_GAS_LIMIT
    });
    const receipt = await tx.wait();
    const depositEvent = receipt.logs.find((log) => {
      try {
        const parsed = this.vault.interface.parseLog({
          topics: log.topics,
          data: log.data
        });
        return parsed?.name === "Deposit";
      } catch {
        return false;
      }
    });
    let leafIndex = -1;
    if (depositEvent) {
      const parsed = this.vault.interface.parseLog({
        topics: depositEvent.topics,
        data: depositEvent.data
      });
      leafIndex = Number(parsed?.args?.leafIndex ?? -1);
    }
    note.leafIndex = leafIndex;
    this.merkleTree.insert(bytes32ToBigInt(note.commitment));
    return {
      success: true,
      txHash: receipt.hash,
      commitment: note.commitment,
      leafIndex,
      note
    };
  }
  async withdraw(note, recipient) {
    if (!this.signer) {
      throw new Error("Signer required for withdrawals");
    }
    const nullifierSeedBigInt = bytes32ToBigInt(note.nullifierSeed);
    const nullifier = computeNullifier(nullifierSeedBigInt, note.leafIndex);
    const nullifierBytes = bigIntToBytes32(nullifier);
    const isUsed = await this.vault.isNullifierUsed(bytesToHex(nullifierBytes));
    if (isUsed) {
      return {
        success: false,
        zkProof: new Uint8Array(),
        teeAttestation: new Uint8Array(),
        error: "Nullifier already used"
      };
    }
    const merkleProof = this.merkleTree.generateProof(note.leafIndex);
    const root = await this.vault.getLatestRoot();
    const teeResult = await this.phatClient.processWithdrawal({
      commitment: note.commitment,
      nullifier: nullifierBytes,
      recipient,
      amount: note.amount,
      merklePath: merkleProof.path,
      pathIndices: merkleProof.indices
    });
    if (!teeResult.success) {
      return {
        success: false,
        zkProof: new Uint8Array(),
        teeAttestation: new Uint8Array(),
        error: teeResult.error
      };
    }
    const tx = await this.vault.withdraw(
      bytesToHex(nullifierBytes),
      root,
      recipient,
      note.amount,
      bytesToHex(teeResult.zkProof),
      bytesToHex(teeResult.teeAttestation),
      { gasLimit: DEFAULT_GAS_LIMIT * 2n }
    );
    const receipt = await tx.wait();
    return {
      success: true,
      txHash: receipt.hash,
      zkProof: teeResult.zkProof,
      teeAttestation: teeResult.teeAttestation
    };
  }
  async withdrawWithCompliance(note, recipient, aspProvider) {
    if (!this.signer) {
      throw new Error("Signer required for withdrawals");
    }
    const isRegistered = await this.aspRegistry.isRegistered(aspProvider);
    if (!isRegistered) {
      return {
        success: false,
        zkProof: new Uint8Array(),
        teeAttestation: new Uint8Array(),
        error: "ASP provider not registered"
      };
    }
    const nullifierSeedBigInt = bytes32ToBigInt(note.nullifierSeed);
    const nullifier = computeNullifier(nullifierSeedBigInt, note.leafIndex);
    const nullifierBytes = bigIntToBytes32(nullifier);
    const merkleProof = this.merkleTree.generateProof(note.leafIndex);
    const root = await this.vault.getLatestRoot();
    const complianceProof = await this.phatClient.generateComplianceProof(
      note.commitment,
      aspProvider
    );
    const teeResult = await this.phatClient.processWithdrawal({
      commitment: note.commitment,
      nullifier: nullifierBytes,
      recipient,
      amount: note.amount,
      merklePath: merkleProof.path,
      pathIndices: merkleProof.indices
    });
    if (!teeResult.success) {
      return {
        success: false,
        zkProof: new Uint8Array(),
        teeAttestation: new Uint8Array(),
        error: teeResult.error
      };
    }
    const associationProofBytes = this.encodeAssociationProof(complianceProof);
    const tx = await this.vault.withdrawWithCompliance(
      bytesToHex(nullifierBytes),
      root,
      recipient,
      note.amount,
      bytesToHex(teeResult.zkProof),
      bytesToHex(associationProofBytes),
      aspProvider,
      { gasLimit: DEFAULT_GAS_LIMIT * 2n }
    );
    const receipt = await tx.wait();
    return {
      success: true,
      txHash: receipt.hash,
      zkProof: teeResult.zkProof,
      teeAttestation: teeResult.teeAttestation
    };
  }
  async getVaultStats() {
    const [totalDeposits, totalWithdrawals, nextLeafIndex, latestRoot] = await Promise.all([
      this.provider.getBalance(this.config.vaultAddress),
      0n,
      this.vault.getNextLeafIndex(),
      this.vault.getLatestRoot()
    ]);
    return {
      totalDeposits,
      totalWithdrawals,
      nextLeafIndex: Number(nextLeafIndex),
      latestRoot: hexToBytes(latestRoot)
    };
  }
  async isRootKnown(root) {
    return this.vault.isKnownRoot(bytesToHex(root));
  }
  async isNullifierUsed(nullifier) {
    return this.vault.isNullifierUsed(bytesToHex(nullifier));
  }
  async getActiveASPs() {
    return this.aspRegistry.getActiveProviders();
  }
  async getHighReputationASPs(minScore) {
    return this.aspRegistry.getHighReputationProviders(minScore);
  }
  async getUserDeposits(address) {
    const commitments = await this.vault.getUserDeposits(address);
    return commitments.map((c) => hexToBytes(c));
  }
  syncMerkleTree(leaves) {
    this.merkleTree = new MerkleTree();
    for (const leaf of leaves) {
      this.merkleTree.insert(leaf);
    }
  }
  getMerkleProof(index) {
    return this.merkleTree.generateProof(index);
  }
  encodeAssociationProof(proof) {
    const result = new Uint8Array(64 + proof.zkProof.length);
    const depositRoot = this.merkleTree.generateProof(0).root;
    result.set(depositRoot, 0);
    result.set(proof.associationRoot, 32);
    result.set(proof.zkProof, 64);
    return result;
  }
};
function createVaultSDK(config) {
  return new PrivacyVaultSDK(config);
}
async function createVaultSDKWithSigner(config, privateKey) {
  const provider = new ethers.JsonRpcProvider(config.rpcUrl);
  const signer = new ethers.Wallet(privateKey, provider);
  return new PrivacyVaultSDK(config, signer);
}
export {
  ASP_REGISTRY_ABI,
  CHAIN_CONFIG,
  CONTRACT_ADDRESSES,
  DEFAULT_BATCH_SIZE,
  DEFAULT_GAS_LIMIT,
  FIELD_SIZE,
  MERKLE_TREE_DEPTH,
  MerkleTree,
  POSEIDON_CONSTANTS,
  PRIVACY_VAULT_ABI,
  PROOF_EXPIRY_MS,
  PhatClient,
  PrivacyVaultSDK,
  ZERO_BYTES32,
  ZK_VERIFIER_ABI,
  bigIntToBytes32,
  bytes32ToBigInt,
  bytesToHex,
  computeCommitment,
  computeNullifier,
  createVaultSDK,
  createVaultSDKWithSigner,
  decryptNote,
  deserializeNote,
  encryptNote,
  generateDepositNote,
  generateRandomBytes,
  getZeroNode,
  hexToBytes,
  poseidonHash,
  serializeNote
};
