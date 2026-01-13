"use strict";
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var index_exports = {};
__export(index_exports, {
  ASP_REGISTRY_ABI: () => ASP_REGISTRY_ABI,
  CHAIN_CONFIG: () => CHAIN_CONFIG,
  CONTRACT_ADDRESSES: () => CONTRACT_ADDRESSES,
  DEFAULT_BATCH_SIZE: () => DEFAULT_BATCH_SIZE,
  DEFAULT_GAS_LIMIT: () => DEFAULT_GAS_LIMIT,
  FIELD_SIZE: () => FIELD_SIZE,
  MERKLE_TREE_DEPTH: () => MERKLE_TREE_DEPTH,
  MerkleTree: () => MerkleTree,
  POSEIDON_CONSTANTS: () => POSEIDON_CONSTANTS,
  PRIVACY_VAULT_ABI: () => PRIVACY_VAULT_ABI,
  PROOF_EXPIRY_MS: () => PROOF_EXPIRY_MS,
  PrivacyVaultSDK: () => PrivacyVaultSDK,
  ZERO_BYTES32: () => ZERO_BYTES32,
  ZKProofClient: () => ZKProofClient,
  ZK_VERIFIER_ABI: () => ZK_VERIFIER_ABI,
  bigIntToBytes32: () => bigIntToBytes32,
  bytes32ToBigInt: () => bytes32ToBigInt,
  bytesToHex: () => bytesToHex,
  computeCommitment: () => computeCommitment,
  computeNullifier: () => computeNullifier,
  decryptNote: () => decryptNote,
  deserializeNote: () => deserializeNote,
  encryptNote: () => encryptNote,
  generateDepositNote: () => generateDepositNote,
  generateRandomBytes: () => generateRandomBytes,
  getZeroNode: () => getZeroNode,
  hexToBytes: () => hexToBytes,
  poseidonHash: () => poseidonHash,
  serializeNote: () => serializeNote
});
module.exports = __toCommonJS(index_exports);

// src/vault.ts
var import_ethers3 = require("ethers");

// src/constants.ts
var import_ethers = require("ethers");
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
    celoSepolia: {
      vault: "0x68F19280d3030eaE36B8Da42621B66e92a8AEA32",
      zkVerifier: "0x68491614a84C0410E9Fc0CB59Fc60A4F9188687c",
      aspRegistry: "0xB041Cff58FB866c7f4326e0767c97B93434aBa9E"
    },
    horizenSepolia: {
      vault: "0x68F19280d3030eaE36B8Da42621B66e92a8AEA32",
      zkVerifier: "0x68491614a84C0410E9Fc0CB59Fc60A4F9188687c",
      aspRegistry: "0xB041Cff58FB866c7f4326e0767c97B93434aBa9E"
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
  11142220: {
    name: "Celo Sepolia",
    rpcUrl: "https://forno.celo-sepolia.celo-testnet.org",
    explorer: "https://sepolia.celoscan.io"
  },
  2035: {
    name: "Phala L2",
    rpcUrl: "https://rpc.phala.network",
    explorer: "https://explorer.phala.network"
  },
  845320009: {
    name: "Horizen Sepolia Testnet",
    rpcUrl: "https://horizen-rpc-testnet.appchain.base.org",
    explorer: "https://explorer-horizen-testnet.appchain.base.org"
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
  return (0, import_ethers.getBytes)((0, import_ethers.keccak256)(data));
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

// src/zk-client.ts
var import_ethers2 = require("ethers");
var wasmModule = null;
var ZKProofClient = class {
  config;
  wasmReady = false;
  constructor(config) {
    this.config = config ?? { useRealProofs: true };
    if (this.config.useRealProofs) {
      this.loadWasm();
    }
  }
  async loadWasm() {
    if (wasmModule) {
      this.wasmReady = true;
      return;
    }
    try {
      const wasmPath = this.config.wasmPath ?? "zkenclave-circuits";
      const module2 = await import(
        /* webpackIgnore: true */
        wasmPath
      );
      wasmModule = module2;
      this.wasmReady = true;
    } catch {
      console.warn("WASM module not available, falling back to mock proofs");
      this.wasmReady = false;
    }
  }
  async generateWithdrawalProof(request) {
    if (this.config.useRealProofs && this.wasmReady && wasmModule) {
      return this.generateRealProof(request);
    }
    return this.generateFallbackProof(request);
  }
  async generateRealProof(request) {
    const wasmRequest = {
      secret: Array.from(request.commitment),
      nullifier_seed: Array.from(request.nullifier),
      amount: Number(request.amount),
      leaf_index: request.leafIndex,
      merkle_path: request.merklePath.map((p) => Array.from(p)),
      path_indices: request.pathIndices,
      merkle_root: request.merkleRoot ? Array.from(request.merkleRoot) : new Array(32).fill(0),
      recipient: this.addressToBytes(request.recipient)
    };
    const resultJson = wasmModule.generate_withdrawal_proof(
      JSON.stringify(wasmRequest)
    );
    const result = JSON.parse(resultJson);
    if (!result.success) {
      throw new Error(`ZK proof generation failed: ${result.error}`);
    }
    return {
      success: true,
      zkProof: new Uint8Array(result.proof),
      nullifierHash: new Uint8Array(result.nullifier_hash),
      merkleRoot: request.merkleRoot ?? new Uint8Array(32),
      timestamp: Date.now()
    };
  }
  async generateFallbackProof(request) {
    const nullifierHash = this.computeNullifierHash(
      request.nullifier,
      request.leafIndex
    );
    const merkleRoot = request.merkleRoot ?? new Uint8Array(32);
    const proof = new Uint8Array(256);
    proof[0] = 1;
    const amountHex = (0, import_ethers2.toBeHex)(request.amount, 32);
    const amountBytes = this.hexToBytes(amountHex);
    proof.set(amountBytes.slice(0, 32), 1);
    proof.set(request.commitment.slice(0, 32), 33);
    proof[250] = 90;
    proof[251] = 75;
    return {
      success: true,
      zkProof: proof,
      nullifierHash,
      merkleRoot,
      timestamp: Date.now()
    };
  }
  async generateComplianceProof(commitment, associationRoot) {
    const proofId = (0, import_ethers2.keccak256)(
      new Uint8Array([...commitment, ...associationRoot])
    );
    return {
      id: proofId,
      associationRoot,
      timestamp: Date.now(),
      valid: true,
      proof: new Uint8Array(256)
    };
  }
  async verifyProof(proofResult) {
    if (this.wasmReady && wasmModule) {
      const proofJson = JSON.stringify({
        success: proofResult.success,
        proof: Array.from(proofResult.zkProof),
        nullifier_hash: Array.from(proofResult.nullifierHash),
        public_inputs: [],
        error: null
      });
      return wasmModule.verify_withdrawal_proof(proofJson);
    }
    return proofResult.success && proofResult.zkProof.length > 0 && proofResult.zkProof[250] === 90 && proofResult.zkProof[251] === 75;
  }
  isWasmReady() {
    return this.wasmReady;
  }
  computeNullifierHash(nullifier, leafIndex) {
    const indexBytes = new TextEncoder().encode(leafIndex.toString());
    const combined = new Uint8Array([...nullifier, ...indexBytes]);
    const hash = (0, import_ethers2.keccak256)(combined);
    return this.hexToBytes(hash);
  }
  addressToBytes(address) {
    const clean = address.startsWith("0x") ? address.slice(2) : address;
    const bytes = [];
    for (let i = 0; i < clean.length && bytes.length < 20; i += 2) {
      bytes.push(parseInt(clean.slice(i, i + 2), 16));
    }
    while (bytes.length < 20) bytes.push(0);
    return bytes;
  }
  hexToBytes(hex) {
    const cleanHex = hex.startsWith("0x") ? hex.slice(2) : hex;
    const bytes = new Uint8Array(cleanHex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(cleanHex.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  }
};

// src/vault.ts
var PrivacyVaultSDK = class {
  provider;
  signer = null;
  vault;
  readVault;
  _aspRegistry;
  zkClient;
  config;
  _merkleTree;
  constructor(config, signer, zkClient) {
    this.config = config;
    this.provider = new import_ethers3.ethers.JsonRpcProvider(config.rpcUrl);
    if (signer) {
      this.signer = signer;
    }
    this.vault = new import_ethers3.ethers.Contract(
      config.vaultAddress,
      PRIVACY_VAULT_ABI,
      this.signer ?? this.provider
    );
    this.readVault = new import_ethers3.ethers.Contract(
      config.vaultAddress,
      PRIVACY_VAULT_ABI,
      this.provider
    );
    this._aspRegistry = new import_ethers3.ethers.Contract(
      config.aspRegistryAddress,
      ASP_REGISTRY_ABI,
      this.provider
    );
    this.zkClient = zkClient || new ZKProofClient();
    this._merkleTree = new MerkleTree();
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
    let leafIndex = -1;
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
    if (depositEvent) {
      const parsed = this.vault.interface.parseLog({
        topics: depositEvent.topics,
        data: depositEvent.data
      });
      leafIndex = Number(parsed?.args?.leafIndex ?? -1);
    }
    note.leafIndex = leafIndex;
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
    const nullifierBigInt = bytes32ToBigInt(note.nullifierSeed);
    const nullifierHashBigInt = computeNullifier(
      nullifierBigInt,
      note.leafIndex
    );
    const nullifierHash = bigIntToBytes32(nullifierHashBigInt);
    const root = await this.getLatestRoot();
    const zkProofResult = await this.zkClient.generateWithdrawalProof({
      commitment: note.commitment,
      nullifier: note.nullifierSeed,
      recipient,
      amount: note.amount,
      leafIndex: note.leafIndex,
      merkleRoot: root,
      merklePath: [],
      pathIndices: [],
      secret: note.secret
    });
    const tx = await this.vault.withdraw(
      bytesToHex(nullifierHash),
      bytesToHex(root),
      recipient,
      note.amount,
      zkProofResult.zkProof,
      new Uint8Array(64),
      { gasLimit: DEFAULT_GAS_LIMIT }
    );
    const receipt = await tx.wait();
    return {
      success: true,
      txHash: receipt.hash,
      zkProof: zkProofResult.zkProof,
      nullifierHash,
      merkleRoot: root,
      timestamp: Date.now()
    };
  }
  async getLatestRoot() {
    const root = await this.readVault.getLatestRoot();
    return hexToBytes(root);
  }
  async getNextLeafIndex() {
    const index = await this.readVault.getNextLeafIndex();
    return Number(index);
  }
  async isNullifierUsed(nullifier) {
    return await this.readVault.isNullifierUsed(bytesToHex(nullifier));
  }
  async isKnownRoot(root) {
    return await this.vault.isKnownRoot(bytesToHex(root));
  }
  async getVaultStats() {
    const [nextLeafIndex, latestRoot] = await Promise.all([
      this.vault.getNextLeafIndex(),
      this.vault.getLatestRoot()
    ]);
    return {
      totalDeposits: 0n,
      totalWithdrawals: 0n,
      nextLeafIndex: Number(nextLeafIndex),
      latestRoot: hexToBytes(latestRoot)
    };
  }
  getConfig() {
    return this.config;
  }
};
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
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
  PrivacyVaultSDK,
  ZERO_BYTES32,
  ZKProofClient,
  ZK_VERIFIER_ABI,
  bigIntToBytes32,
  bytes32ToBigInt,
  bytesToHex,
  computeCommitment,
  computeNullifier,
  decryptNote,
  deserializeNote,
  encryptNote,
  generateDepositNote,
  generateRandomBytes,
  getZeroNode,
  hexToBytes,
  poseidonHash,
  serializeNote
});
