import type {
  WithdrawalRequest,
  WithdrawalResult,
  ComplianceProof,
} from "./types";
import { bytesToHex, hexToBytes } from "./crypto";

export interface PhatClientConfig {
  endpoint?: string;
  timeout?: number;
}

export class PhatClient {
  private contractAddress: string;
  private endpoint: string;
  private timeout: number;

  constructor(contractAddress: string, config?: PhatClientConfig) {
    this.contractAddress = contractAddress;
    this.endpoint = config?.endpoint ?? "https://poc5.phala.network/tee-api/v1";
    this.timeout = config?.timeout ?? 30000;
  }

  async processWithdrawal(
    request: WithdrawalRequest
  ): Promise<WithdrawalResult> {
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
        error: error instanceof Error ? error.message : "Unknown error",
      };
    }
  }

  async generateComplianceProof(
    commitment: Uint8Array,
    aspProvider: string
  ): Promise<ComplianceProof> {
    const params = {
      commitment: bytesToHex(commitment),
      asp_provider: aspProvider,
    };

    const response = await this.callPhatContract(
      "generate_compliance_proof",
      params
    );

    return this.decodeComplianceProof(response);
  }

  async getAttestationReport(): Promise<Uint8Array> {
    const response = await this.callPhatContract(
      "get_tee_attestation_report",
      {}
    );
    return hexToBytes(response.attestation);
  }

  async isNullifierUsed(nullifier: Uint8Array): Promise<boolean> {
    const params = {
      nullifier: bytesToHex(nullifier),
    };

    const response = await this.callPhatContract("is_nullifier_used", params);
    return response.used === true;
  }

  async getCommitmentRoot(): Promise<Uint8Array> {
    const response = await this.callPhatContract("get_commitment_root", {});
    return hexToBytes(response.root);
  }

  private async callPhatContract(
    method: string,
    params: unknown
  ): Promise<Record<string, unknown>> {
    if (this.contractAddress === "" || this.contractAddress === "0x") {
      return this.simulateLocalResponse(method, params);
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await fetch(`${this.endpoint}/call`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          contract: this.contractAddress,
          method,
          params,
        }),
        signal: controller.signal,
      });

      if (!response.ok) {
        throw new Error(`Phat contract call failed: ${response.statusText}`);
      }

      return (await response.json()) as Record<string, unknown>;
    } finally {
      clearTimeout(timeoutId);
    }
  }

  private simulateLocalResponse(
    method: string,
    params: unknown
  ): Record<string, unknown> {
    switch (method) {
      case "process_withdrawal": {
        const request = params as { commitment: string; nullifier: string };

        const mockProof = new Uint8Array(256);
        mockProof[0] = 0x01;

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
            (timestamp >> BigInt(i * 8)) & 0xffn
          );
        }

        return {
          success: true,
          tx_hash: null,
          zk_proof: bytesToHex(mockProof),
          tee_attestation: bytesToHex(mockAttestation),
          error: null,
        };
      }

      case "generate_compliance_proof": {
        const request = params as { commitment: string };
        const commitmentBytes = hexToBytes(request.commitment);

        const mockRoot = this.simpleHash(commitmentBytes);
        const mockProof = new Uint8Array(64);
        mockProof.set(mockRoot, 0);

        return {
          deposit_commitment: request.commitment,
          association_root: bytesToHex(mockRoot),
          zk_proof: bytesToHex(mockProof),
          asp_signature: bytesToHex(new Uint8Array(64)),
          timestamp: Date.now(),
        };
      }

      case "get_tee_attestation_report": {
        const mockReport = new Uint8Array(96);
        return {
          attestation: bytesToHex(mockReport),
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

  private simpleHash(data: Uint8Array): Uint8Array {
    const result = new Uint8Array(32);
    let hash = 0x811c9dc5;

    for (let i = 0; i < data.length; i++) {
      hash ^= data[i];
      hash = Math.imul(hash, 0x01000193);
    }

    for (let i = 0; i < 32; i++) {
      result[i] = (hash >> ((i % 4) * 8)) & 0xff;
      hash = Math.imul(hash, 0x01000193) ^ i;
    }

    return result;
  }

  private encodeWithdrawalRequest(
    request: WithdrawalRequest
  ): Record<string, unknown> {
    return {
      commitment: bytesToHex(request.commitment),
      nullifier: bytesToHex(request.nullifier),
      recipient: bytesToHex(request.recipient),
      amount: request.amount.toString(),
      merkle_proof: request.merklePath.map((p) => bytesToHex(p)),
      proof_indices: request.pathIndices,
    };
  }

  private decodeWithdrawalResponse(
    response: Record<string, unknown>
  ): WithdrawalResult {
    return {
      success: response.success as boolean,
      txHash: response.tx_hash as string | undefined,
      zkProof: hexToBytes(response.zk_proof as string),
      teeAttestation: hexToBytes(response.tee_attestation as string),
      error: response.error as string | undefined,
    };
  }

  private decodeComplianceProof(
    response: Record<string, unknown>
  ): ComplianceProof {
    return {
      depositCommitment: hexToBytes(response.deposit_commitment as string),
      associationRoot: hexToBytes(response.association_root as string),
      zkProof: hexToBytes(response.zk_proof as string),
      aspSignature: hexToBytes(response.asp_signature as string),
      timestamp: response.timestamp as number,
    };
  }
}
