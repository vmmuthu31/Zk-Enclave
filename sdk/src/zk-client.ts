import { keccak256, toBeHex } from "ethers";
import type {
  WithdrawalRequest,
  WithdrawalResult,
  ComplianceProof,
} from "./types";

export interface ZKProofClientConfig {
  circuitPath?: string;
}

export class ZKProofClient {
  private config: ZKProofClientConfig;

  constructor(config?: ZKProofClientConfig) {
    this.config = config ?? {};
  }

  async generateWithdrawalProof(
    request: WithdrawalRequest
  ): Promise<WithdrawalResult> {
    const nullifierHash = this.computeNullifierHash(
      request.nullifier,
      request.leafIndex
    );

    const zkProof = this.generateMockProof(request);

    const merkleRoot = request.merkleRoot ?? new Uint8Array(32);

    return {
      success: true,
      nullifierHash,
      zkProof,
      merkleRoot,
      timestamp: Date.now(),
    };
  }

  async generateComplianceProof(
    commitment: Uint8Array,
    associationRoot: Uint8Array
  ): Promise<ComplianceProof> {
    const proofId = keccak256(
      new Uint8Array([...commitment, ...associationRoot])
    );

    return {
      id: proofId,
      associationRoot,
      timestamp: Date.now(),
      valid: true,
      proof: new Uint8Array(256),
    };
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

  private generateMockProof(request: WithdrawalRequest): Uint8Array {
    const proof = new Uint8Array(256);
    proof[0] = 0x01;

    const amountHex = toBeHex(request.amount, 32);
    const amountBytes = this.hexToBytes(amountHex);
    proof.set(amountBytes.slice(0, 32), 1);

    proof.set(request.commitment.slice(0, 32), 33);

    return proof;
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
