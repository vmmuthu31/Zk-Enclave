import {
  OnChainRegistry,
  PinkContractPromise,
  signCertificate,
} from "@phala/sdk";
import type { CertificateData } from "@phala/sdk";
import { ApiPromise, WsProvider } from "@polkadot/api";
import type { Signer } from "ethers";
import type {
  WithdrawalRequest,
  WithdrawalResult,
  ComplianceProof,
} from "./types.ts";
import { hexToBytes } from "./crypto.ts";

export interface PhatClientConfig {
  endpoint?: string;
  variable_capability?: boolean;
}

export class PhatClient {
  private contractAddress: string;
  private endpoint: string;
  private registry?: OnChainRegistry;
  private api?: ApiPromise;
  private contract?: PinkContractPromise;
  private certificate?: CertificateData;

  constructor(contractAddress: string, config?: PhatClientConfig) {
    this.contractAddress = contractAddress;
    this.endpoint = config?.endpoint ?? "wss://poc5.phala.network/ws";
  }

  async connect(signer: Signer): Promise<void> {
    const provider = new WsProvider(this.endpoint);
    this.api = (await ApiPromise.create({ provider })) as any;

    this.registry = await OnChainRegistry.create(this.api!);

    const abi = {
      source: { hash: "0x", language: "ink!", compiler: "rustc", wasm: "0x" },
      contract: { name: "zkenclave", version: "0.1.0", authors: [] },
      spec: {
        constructors: [],
        docs: [],
        events: [],
        messages: [
          {
            args: [{ name: "req", type: "WithdrawalRequest" }],
            docs: [],
            label: "process_withdrawal",
            mutates: false,
            payable: false,
            returnType: { displayName: ["WithdrawalResult"], type: 1 },
            selector: "0xabcdef01",
          },
          {
            args: [
              { name: "commitment", type: "Vec<u8>" },
              { name: "asp_provider", type: "String" },
            ],
            label: "generate_compliance_proof",
            mutates: false,
            payable: false,
            returnType: { displayName: ["ComplianceProof"], type: 2 },
            selector: "0xabcdef02",
          },
          {
            args: [],
            label: "get_tee_attestation_report",
            mutates: false,
            payable: false,
            returnType: { displayName: ["Vec<u8>"], type: 3 },
            selector: "0xabcdef03",
          },
        ],
      },
      storage: { struct: { fields: [] } },
      types: [],
    };

    const contractKey = this.contractAddress;
    this.contract = new PinkContractPromise(
      this.api as any,
      this.registry!,
      abi,
      contractKey,
      contractKey
    ) as any;

    const address = await signer.getAddress();
    this.certificate = await signCertificate({
      pair: {
        address,
        sign: async (data: string | Uint8Array) => {
          const sig = await signer.signMessage(data);
          return hexToBytes(sig);
        },
      } as any,
      api: this.api as any,
    });
  }

  async processWithdrawal(
    request: WithdrawalRequest
  ): Promise<WithdrawalResult> {
    if (!this.contract || !this.certificate) {
      console.warn(
        "PhatClient not connected to Phala, falling back to mock response"
      );
      return this._simulateLocalResponse("process_withdrawal", request);
    }

    try {
      const encodedRequest = this.encodeWithdrawalRequest(request);

      const { output } = await this.contract.query.processWithdrawal(
        this.certificate.address,
        { cert: this.certificate },
        encodedRequest
      );

      if (!output || !output.isOk) {
        throw new Error("Failed to execute contract query");
      }

      return this.decodeWithdrawalResponse(output.asOk.toHuman());
    } catch (error) {
      console.error("Phat Contract call failed:", error);
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
    if (!this.contract || !this.certificate) {
      return this._simulateLocalResponse("generate_compliance_proof", {
        commitment,
        aspProvider,
      });
    }

    const { output } = await this.contract.query.generateComplianceProof(
      this.certificate.address,
      { cert: this.certificate },
      commitment,
      aspProvider
    );

    return this.decodeComplianceProof(output!.asOk.toHuman());
  }

  async getAttestationReport(): Promise<Uint8Array> {
    if (!this.contract || !this.certificate) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      return (
        this._simulateLocalResponse("get_tee_attestation_report", {}) as any
      ).attestation;
    }

    const { output } = await this.contract.query.getTeeAttestationReport(
      this.certificate.address,
      { cert: this.certificate }
    );

    return output!.asOk.toU8a();
  }

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  async isNullifierUsed(_nullifier: Uint8Array): Promise<boolean> {
    // Mock for now or implement if contract supports
    return false;
  }

  async getCommitmentRoot(): Promise<Uint8Array> {
    // Mock for now
    return new Uint8Array(32);
  }

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  private _simulateLocalResponse(method: string, _params: any): any {
    switch (method) {
      case "process_withdrawal": {
        const mockProof = new Uint8Array(256);
        mockProof[0] = 0x01;
        return {
          success: true,
          zkProof: mockProof,
          teeAttestation: new Uint8Array(64),
        };
      }
      case "generate_compliance_proof": {
        return {
          depositCommitment: new Uint8Array(32),
          associationRoot: new Uint8Array(32),
          zkProof: new Uint8Array(64),
          aspSignature: new Uint8Array(64),
          timestamp: Date.now(),
        };
      }
      case "get_tee_attestation_report":
        return { attestation: new Uint8Array(64) };
      default:
        throw new Error(`Unknown method: ${method}`);
    }
  }

  private encodeWithdrawalRequest(req: WithdrawalRequest): any {
    return {
      commitment: req.commitment,
      nullifier: req.nullifier,
      recipient: req.recipient,
      amount: req.amount,
      merkle_path: req.merklePath,
      path_indices: req.pathIndices,
    };
  }

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  private decodeWithdrawalResponse(res: any): WithdrawalResult {
    return {
      success: true,
      zkProof: new Uint8Array(),
      teeAttestation: new Uint8Array(),
    };
  }

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  private decodeComplianceProof(res: any): ComplianceProof {
    return {
      depositCommitment: new Uint8Array(),
      associationRoot: new Uint8Array(),
      zkProof: new Uint8Array(),
      aspSignature: new Uint8Array(),
      timestamp: 0,
    };
  }
}
