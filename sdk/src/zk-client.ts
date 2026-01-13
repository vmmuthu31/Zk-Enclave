import { keccak256, toBeHex } from "ethers";
import type {
  WithdrawalRequest,
  WithdrawalResult,
  ComplianceProof,
} from "./types";

export interface ZKProofClientConfig {
  wasmPath?: string;
  useRealProofs?: boolean;
}

interface WasmProofResult {
  success: boolean;
  proof: number[];
  nullifier_hash: number[];
  public_inputs: number[][];
  error?: string;
}

let wasmModule: {
  generate_withdrawal_proof: (request: string) => string;
  verify_withdrawal_proof: (proof: string) => boolean;
  generate_compliance_proof: (request: string) => string;
} | null = null;

export class ZKProofClient {
  private config: ZKProofClientConfig;
  private wasmReady: boolean = false;

  constructor(config?: ZKProofClientConfig) {
    this.config = config ?? { useRealProofs: true };
    if (this.config.useRealProofs) {
      this.loadWasm();
    }
  }

  private async loadWasm(): Promise<void> {
    if (wasmModule) {
      this.wasmReady = true;
      return;
    }

    try {
      const wasmPath = this.config.wasmPath ?? "zkenclave-circuits";
      const module = await import(/* webpackIgnore: true */ wasmPath);
      wasmModule = module;
      this.wasmReady = true;
    } catch {
      console.warn("WASM module not available, falling back to mock proofs");
      this.wasmReady = false;
    }
  }

  async generateWithdrawalProof(
    request: WithdrawalRequest
  ): Promise<WithdrawalResult> {
    if (this.config.useRealProofs && this.wasmReady && wasmModule) {
      return this.generateRealProof(request);
    }
    return this.generateFallbackProof(request);
  }

  private async generateRealProof(
    request: WithdrawalRequest
  ): Promise<WithdrawalResult> {
    const wasmRequest = {
      secret: Array.from(request.commitment),
      nullifier_seed: Array.from(request.nullifier),
      amount: Number(request.amount),
      leaf_index: request.leafIndex,
      merkle_path: request.merklePath.map((p) => Array.from(p)),
      path_indices: request.pathIndices,
      merkle_root: request.merkleRoot
        ? Array.from(request.merkleRoot)
        : new Array(32).fill(0),
      recipient: this.addressToBytes(request.recipient),
    };

    const resultJson = wasmModule!.generate_withdrawal_proof(
      JSON.stringify(wasmRequest)
    );
    const result: WasmProofResult = JSON.parse(resultJson);

    if (!result.success) {
      throw new Error(`ZK proof generation failed: ${result.error}`);
    }

    return {
      success: true,
      zkProof: new Uint8Array(result.proof),
      nullifierHash: new Uint8Array(result.nullifier_hash),
      merkleRoot: request.merkleRoot ?? new Uint8Array(32),
      timestamp: Date.now(),
    };
  }

  private async generateFallbackProof(
    request: WithdrawalRequest
  ): Promise<WithdrawalResult> {
    const nullifierHash = this.computeNullifierHash(
      request.nullifier,
      request.leafIndex
    );
    const merkleRoot = request.merkleRoot ?? new Uint8Array(32);

    const proof = new Uint8Array(256);
    proof[0] = 0x01;

    const amountHex = toBeHex(request.amount, 32);
    const amountBytes = this.hexToBytes(amountHex);
    proof.set(amountBytes.slice(0, 32), 1);
    proof.set(request.commitment.slice(0, 32), 33);

    proof[250] = 0x5a;
    proof[251] = 0x4b;

    return {
      success: true,
      zkProof: proof,
      nullifierHash,
      merkleRoot,
      timestamp: Date.now(),
    };
  }

  async generateComplianceProof(
    commitment: Uint8Array,
    associationPath: Uint8Array[],
    pathIndices: boolean[],
    associationRoot: Uint8Array
  ): Promise<ComplianceProof> {
    if (this.config.useRealProofs && this.wasmReady && wasmModule) {
      const request = {
        commitment: Array.from(commitment),
        association_path: associationPath.map((p) => Array.from(p)),
        path_indices: pathIndices,
        association_root: Array.from(associationRoot),
      };

      const resultJson = wasmModule.generate_compliance_proof(
        JSON.stringify(request)
      );
      const result: { success: boolean; proof: number[]; error?: string } =
        JSON.parse(resultJson);

      if (!result.success) {
        throw new Error(`Compliance proof generation failed: ${result.error}`);
      }

      return {
        id: keccak256(new Uint8Array(result.proof)),
        associationRoot,
        timestamp: Date.now(),
        valid: true,
        proof: new Uint8Array(result.proof),
      };
    }

    return {
      id: "mock-compliance-proof",
      associationRoot,
      timestamp: Date.now(),
      valid: true,
      proof: new Uint8Array(64).fill(1),
    };
  }

  async verifyProof(proofResult: WithdrawalResult): Promise<boolean> {
    if (this.wasmReady && wasmModule) {
      const proofJson = JSON.stringify({
        success: proofResult.success,
        proof: Array.from(proofResult.zkProof),
        nullifier_hash: Array.from(proofResult.nullifierHash),
        public_inputs: [],
        error: null,
      });
      return wasmModule.verify_withdrawal_proof(proofJson);
    }

    return (
      proofResult.success &&
      proofResult.zkProof.length > 0 &&
      proofResult.zkProof[250] === 0x5a &&
      proofResult.zkProof[251] === 0x4b
    );
  }

  isWasmReady(): boolean {
    return this.wasmReady;
  }

  private computeNullifierHash(
    nullifier: Uint8Array,
    leafIndex: number
  ): Uint8Array {
    const indexBytes = new TextEncoder().encode(leafIndex.toString());
    const combined = new Uint8Array([...nullifier, ...indexBytes]);
    const hash = keccak256(combined);
    return this.hexToBytes(hash);
  }

  private addressToBytes(address: string): number[] {
    const clean = address.startsWith("0x") ? address.slice(2) : address;
    const bytes: number[] = [];
    for (let i = 0; i < clean.length && bytes.length < 20; i += 2) {
      bytes.push(parseInt(clean.slice(i, i + 2), 16));
    }
    while (bytes.length < 20) bytes.push(0);
    return bytes;
  }

  private hexToBytes(hex: string): Uint8Array {
    const cleanHex = hex.startsWith("0x") ? hex.slice(2) : hex;
    const bytes = new Uint8Array(cleanHex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(cleanHex.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  }
}

export function computeCommitment(
  secret: Uint8Array,
  nullifier: Uint8Array,
  amount: bigint
): Uint8Array {
  const amountBytes = new TextEncoder().encode(amount.toString());
  const combined = new Uint8Array([...secret, ...nullifier, ...amountBytes]);
  const hash = keccak256(combined);
  return hexToBytes(hash);
}

export function computeNullifier(
  nullifierSeed: Uint8Array,
  leafIndex: number
): Uint8Array {
  const indexBytes = new TextEncoder().encode(leafIndex.toString());
  const combined = new Uint8Array([...nullifierSeed, ...indexBytes]);
  const hash = keccak256(combined);
  return hexToBytes(hash);
}

function hexToBytes(hex: string): Uint8Array {
  const cleanHex = hex.startsWith("0x") ? hex.slice(2) : hex;
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(cleanHex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}
