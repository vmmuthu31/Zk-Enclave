import {
  ZKProofClient,
  type WithdrawalRequest,
  type WithdrawalResult,
  type ComplianceProof,
} from "zkenclave-sdk";
import { generateProof, type ProofRequest } from "./zkproof";

export class WebZKProofClient extends ZKProofClient {
  async generateWithdrawalProof(
    request: WithdrawalRequest
  ): Promise<WithdrawalResult> {
    console.log("Generating real ZK proof in browser...");

    // Convert SDK types to WASM types
    const wasmRequest: ProofRequest = {
      secret: Array.from((request as any).secret || new Uint8Array(32)), // Cast for runtime compatibility
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

  // Override to do nothing or implement compliance if needed
  async generateComplianceProof(
    commitment: Uint8Array,
    associationRoot: Uint8Array
  ): Promise<ComplianceProof> {
    return super.generateComplianceProof(commitment, associationRoot);
  }

  isWasmReady(): boolean {
    return true; // We use the global loader
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
