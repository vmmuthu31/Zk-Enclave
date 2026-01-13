import { keccak256 } from "ethers";
import type {
  WithdrawalRequest,
  WithdrawalResult,
  ComplianceProof,
} from "zkenclave-sdk";
import {
  generateProof,
  type ProofRequest,
  initWasm,
  isWasmReady,
} from "./zkproof";

interface ExtendedWithdrawalRequest extends WithdrawalRequest {
  secret?: Uint8Array;
}

export class WebZKProofClient {
  private wasmReady: boolean = false;

  constructor() {
    this.initializeWasm();
  }

  private async initializeWasm(): Promise<void> {
    this.wasmReady = await initWasm();
  }

  async generateWithdrawalProof(
    request: WithdrawalRequest
  ): Promise<WithdrawalResult> {
    console.log("Generating ZK proof in browser...");

    if (!this.wasmReady) {
      this.wasmReady = await initWasm();
    }

    const fullRequest = request as ExtendedWithdrawalRequest;

    const wasmRequest: ProofRequest = {
      secret: Array.from(fullRequest.secret || new Uint8Array(32)),
      nullifier_seed: Array.from(request.nullifier),
      amount: Number(request.amount),
      leaf_index: request.leafIndex,
      merkle_path: request.merklePath.map((p) => Array.from(p)),
      path_indices: request.pathIndices,
      merkle_root: request.merkleRoot
        ? Array.from(request.merkleRoot)
        : new Array(32).fill(0),
      recipient: this.addressToBytesWeb(request.recipient),
    };

    const result = await generateProof(wasmRequest);

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

  async generateComplianceProof(
    commitment: Uint8Array,
    associationPath: Uint8Array[],
    pathIndices: boolean[],
    associationRoot: Uint8Array
  ): Promise<ComplianceProof> {
    const proofData = {
      commitment: Array.from(commitment),
      associationPath: associationPath.map((p) => Array.from(p)),
      pathIndices,
      associationRoot: Array.from(associationRoot),
      timestamp: Date.now(),
    };

    const proofBytes = new TextEncoder().encode(JSON.stringify(proofData));
    const proofHash = keccak256(proofBytes);

    return {
      id: proofHash,
      associationRoot,
      timestamp: Date.now(),
      valid: true,
      proof: new Uint8Array(proofBytes),
    };
  }

  isWasmReady(): boolean {
    return this.wasmReady || isWasmReady();
  }

  private addressToBytesWeb(address: string): number[] {
    const clean = address.startsWith("0x") ? address.slice(2) : address;
    const bytes: number[] = [];
    for (let i = 0; i < clean.length && bytes.length < 20; i += 2) {
      bytes.push(parseInt(clean.slice(i, i + 2), 16));
    }
    while (bytes.length < 20) bytes.push(0);
    return bytes;
  }
}
