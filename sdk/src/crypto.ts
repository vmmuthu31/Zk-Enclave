import { MERKLE_TREE_DEPTH, FIELD_SIZE, POSEIDON_CONSTANTS } from "./constants";
import type { DepositNote, MerkleProof } from "./types";

export function generateRandomBytes(length: number): Uint8Array {
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

export function bytesToHex(bytes: Uint8Array): string {
  return (
    "0x" +
    Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("")
  );
}

export function hexToBytes(hex: string): Uint8Array {
  const cleanHex = hex.startsWith("0x") ? hex.slice(2) : hex;
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(cleanHex.substr(i * 2, 2), 16);
  }
  return bytes;
}

export function bigIntToBytes32(value: bigint): Uint8Array {
  const hex = value.toString(16).padStart(64, "0");
  return hexToBytes(hex);
}

export function bytes32ToBigInt(bytes: Uint8Array): bigint {
  if (bytes.length !== 32) {
    throw new Error("Invalid bytes32 length");
  }
  return BigInt(bytesToHex(bytes));
}

export function poseidonHash(inputs: bigint[]): bigint {
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
    0x08dff3487e8ac99e1f29a058d0fa80b930c728730b7ab36ce879f3890ecf73f5n,
  ];

  const M = [
    [
      0x109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118bn,
      0x16ed41e13bb9c0c66ae119424fddbcbc9314dc9fdbdeea55d6c64543dc4903e0n,
      0x2b90bba00f05d28c6d4c9d2f1d4d3c2e7f5d8e4a3b2c1d0e9f8a7b6c5d4e3f2an,
    ],
    [
      0x2969f27eed31a480b9c36c764379dbca2cc8fdd1415c3dded62940bcde0bd771n,
      0x143021ec686a3f330d5f9e654638065ce6cd79e28c5b3753326244ee65a1b1a7n,
      0x1e3f7a4c5d6b8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3fn,
    ],
    [
      0x176cc029695ad02582a70eff08a6fd99d057e12e58e7d7b6b16cdfabc8ee2911n,
      0x19a3fc0a56702bf417ba7fee3802593fa644470307043f7773c5e6f71c7c5e3an,
      0x2b4129c2e5a87d9c3e1f5b7d9a2c4e6f8a0b2d4c6e8f0a2b4c6d8e0f2a4b6c8dn,
    ],
  ];

  const sbox = (x: bigint): bigint => {
    const x2 = (x * x) % FIELD_SIZE;
    const x4 = (x2 * x2) % FIELD_SIZE;
    return (x4 * x) % FIELD_SIZE;
  };

  const mix = (s: bigint[]): bigint[] => {
    const result: bigint[] = [];
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

export function computeCommitment(
  secret: bigint,
  nullifierSeed: bigint,
  amount: bigint
): bigint {
  const intermediate = poseidonHash([secret, nullifierSeed]);
  return poseidonHash([intermediate, amount]);
}

export function computeNullifier(
  nullifierSeed: bigint,
  leafIndex: number
): bigint {
  return poseidonHash([nullifierSeed, BigInt(leafIndex)]);
}

export function generateDepositNote(amount: bigint): DepositNote {
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
    timestamp: Date.now(),
  };
}

export function serializeNote(note: DepositNote): string {
  const data = {
    commitment: bytesToHex(note.commitment),
    secret: bytesToHex(note.secret),
    nullifierSeed: bytesToHex(note.nullifierSeed),
    amount: note.amount.toString(),
    leafIndex: note.leafIndex,
    timestamp: note.timestamp,
  };
  return btoa(JSON.stringify(data));
}

export function deserializeNote(serialized: string): DepositNote {
  const data = JSON.parse(atob(serialized));
  return {
    commitment: hexToBytes(data.commitment),
    secret: hexToBytes(data.secret),
    nullifierSeed: hexToBytes(data.nullifierSeed),
    amount: BigInt(data.amount),
    leafIndex: data.leafIndex,
    timestamp: data.timestamp,
  };
}

export function encryptNote(note: DepositNote, password: string): string {
  const serialized = serializeNote(note);
  const encrypted = xorEncrypt(serialized, password);
  return bytesToHex(encrypted);
}

export function decryptNote(encrypted: string, password: string): DepositNote {
  const bytes = hexToBytes(encrypted);
  const decrypted = xorDecrypt(bytes, password);
  return deserializeNote(decrypted);
}

function xorEncrypt(data: string, key: string): Uint8Array {
  const dataBytes = new TextEncoder().encode(data);
  const keyBytes = new TextEncoder().encode(key);
  const result = new Uint8Array(dataBytes.length);

  for (let i = 0; i < dataBytes.length; i++) {
    result[i] = dataBytes[i] ^ keyBytes[i % keyBytes.length];
  }

  return result;
}

function xorDecrypt(data: Uint8Array, key: string): string {
  const keyBytes = new TextEncoder().encode(key);
  const result = new Uint8Array(data.length);

  for (let i = 0; i < data.length; i++) {
    result[i] = data[i] ^ keyBytes[i % keyBytes.length];
  }

  return new TextDecoder().decode(result);
}

export class MerkleTree {
  private leaves: bigint[];
  private layers: bigint[][];
  private readonly depth: number;
  private readonly zeroValues: bigint[];

  constructor(depth: number = MERKLE_TREE_DEPTH) {
    this.depth = depth;
    this.leaves = [];
    this.layers = [];
    this.zeroValues = this.computeZeroValues();
  }

  private computeZeroValues(): bigint[] {
    const zeros: bigint[] = [0n];
    for (let i = 1; i <= this.depth; i++) {
      zeros.push(poseidonHash([zeros[i - 1], zeros[i - 1]]));
    }
    return zeros;
  }

  insert(leaf: bigint): number {
    const index = this.leaves.length;
    this.leaves.push(leaf);
    this.rebuild();
    return index;
  }

  private rebuild(): void {
    this.layers = [this.leaves.slice()];

    const targetSize = 1 << this.depth;
    while (this.layers[0].length < targetSize) {
      this.layers[0].push(this.zeroValues[0]);
    }

    for (let level = 0; level < this.depth; level++) {
      const currentLayer = this.layers[level];
      const nextLayer: bigint[] = [];

      for (let i = 0; i < currentLayer.length; i += 2) {
        const left = currentLayer[i];
        const right = currentLayer[i + 1] ?? this.zeroValues[level];
        nextLayer.push(poseidonHash([left, right]));
      }

      this.layers.push(nextLayer);
    }
  }

  getRoot(): bigint {
    if (this.layers.length === 0) {
      return this.zeroValues[this.depth];
    }
    return this.layers[this.layers.length - 1][0];
  }

  generateProof(index: number): MerkleProof {
    if (index >= this.leaves.length) {
      throw new Error("Index out of bounds");
    }

    const path: Uint8Array[] = [];
    const indices: boolean[] = [];
    let currentIndex = index;

    for (let level = 0; level < this.depth; level++) {
      const isRight = currentIndex % 2 === 1;
      const siblingIndex = isRight ? currentIndex - 1 : currentIndex + 1;

      const sibling =
        this.layers[level][siblingIndex] ?? this.zeroValues[level];
      path.push(bigIntToBytes32(sibling));
      indices.push(isRight);

      currentIndex = Math.floor(currentIndex / 2);
    }

    return {
      path,
      indices,
      root: bigIntToBytes32(this.getRoot()),
    };
  }

  verifyProof(leaf: bigint, proof: MerkleProof): boolean {
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
}
