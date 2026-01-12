import { ethers } from "ethers";
import {
  PRIVACY_VAULT_ABI,
  ZK_VERIFIER_ABI,
  ASP_REGISTRY_ABI,
  DEFAULT_GAS_LIMIT,
} from "./constants";
import {
  generateDepositNote,
  computeNullifier,
  bytes32ToBigInt,
  bytesToHex,
  hexToBytes,
  bigIntToBytes32,
  MerkleTree,
} from "./crypto";
import type {
  DepositNote,
  DepositResult,
  WithdrawalResult,
  VaultConfig,
  VaultStats,
  ComplianceProof,
  MerkleProof,
} from "./types";
import { PhatClient } from "./phat-client";

export class PrivacyVaultSDK {
  private provider: ethers.Provider;
  private signer: ethers.Signer | null = null;
  private vault: ethers.Contract;
  private _zkVerifier: ethers.Contract;
  private aspRegistry: ethers.Contract;
  private phatClient: PhatClient;
  private config: VaultConfig;
  private merkleTree: MerkleTree;

  constructor(config: VaultConfig, signer?: ethers.Signer) {
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

  async connect(signer: ethers.Signer): Promise<void> {
    this.signer = signer;
    this.vault = this.vault.connect(signer) as ethers.Contract;
  }

  async deposit(amount: bigint): Promise<DepositResult> {
    if (!this.signer) {
      throw new Error("Signer required for deposits");
    }

    const note = generateDepositNote(amount);
    const commitmentHex = bytesToHex(note.commitment);

    const tx = await this.vault.deposit(commitmentHex, {
      value: amount,
      gasLimit: DEFAULT_GAS_LIMIT,
    });

    const receipt = await tx.wait();

    const depositEvent = receipt.logs.find((log: ethers.Log) => {
      try {
        const parsed = this.vault.interface.parseLog({
          topics: log.topics as string[],
          data: log.data,
        });
        return parsed?.name === "Deposit";
      } catch {
        return false;
      }
    });

    let leafIndex = -1;
    if (depositEvent) {
      const parsed = this.vault.interface.parseLog({
        topics: depositEvent.topics as string[],
        data: depositEvent.data,
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
      note,
    };
  }

  async withdraw(
    note: DepositNote,
    recipient: string
  ): Promise<WithdrawalResult> {
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
        error: "Nullifier already used",
      };
    }

    const merkleProof = this.merkleTree.generateProof(note.leafIndex);
    const root = await this.vault.getLatestRoot();

    const teeResult = await this.phatClient.processWithdrawal({
      commitment: note.commitment,
      nullifier: nullifierBytes,
      recipient: recipient,
      amount: note.amount,
      merklePath: merkleProof.path,
      pathIndices: merkleProof.indices,
    });

    if (!teeResult.success) {
      return {
        success: false,
        zkProof: new Uint8Array(),
        teeAttestation: new Uint8Array(),
        error: teeResult.error,
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
      teeAttestation: teeResult.teeAttestation,
    };
  }

  async withdrawWithCompliance(
    note: DepositNote,
    recipient: string,
    aspProvider: string
  ): Promise<WithdrawalResult> {
    if (!this.signer) {
      throw new Error("Signer required for withdrawals");
    }

    const isRegistered = await this.aspRegistry.isRegistered(aspProvider);
    if (!isRegistered) {
      return {
        success: false,
        zkProof: new Uint8Array(),
        teeAttestation: new Uint8Array(),
        error: "ASP provider not registered",
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
      recipient: recipient,
      amount: note.amount,
      merklePath: merkleProof.path,
      pathIndices: merkleProof.indices,
    });

    if (!teeResult.success) {
      return {
        success: false,
        zkProof: new Uint8Array(),
        teeAttestation: new Uint8Array(),
        error: teeResult.error,
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
      teeAttestation: teeResult.teeAttestation,
    };
  }

  async getVaultStats(): Promise<VaultStats> {
    const [totalDeposits, totalWithdrawals, nextLeafIndex, latestRoot] =
      await Promise.all([
        this.provider.getBalance(this.config.vaultAddress),
        0n,
        this.vault.getNextLeafIndex(),
        this.vault.getLatestRoot(),
      ]);

    return {
      totalDeposits,
      totalWithdrawals,
      nextLeafIndex: Number(nextLeafIndex),
      latestRoot: hexToBytes(latestRoot),
    };
  }

  async isRootKnown(root: Uint8Array): Promise<boolean> {
    return this.vault.isKnownRoot(bytesToHex(root));
  }

  async isNullifierUsed(nullifier: Uint8Array): Promise<boolean> {
    return this.vault.isNullifierUsed(bytesToHex(nullifier));
  }

  async getActiveASPs(): Promise<string[]> {
    return this.aspRegistry.getActiveProviders();
  }

  async getHighReputationASPs(minScore: number): Promise<string[]> {
    return this.aspRegistry.getHighReputationProviders(minScore);
  }

  async getUserDeposits(address: string): Promise<Uint8Array[]> {
    const commitments = await this.vault.getUserDeposits(address);
    return commitments.map((c: string) => hexToBytes(c));
  }

  syncMerkleTree(leaves: bigint[]): void {
    this.merkleTree = new MerkleTree();
    for (const leaf of leaves) {
      this.merkleTree.insert(leaf);
    }
  }

  getMerkleProof(index: number): MerkleProof {
    return this.merkleTree.generateProof(index);
  }

  private encodeAssociationProof(proof: ComplianceProof): Uint8Array {
    const result = new Uint8Array(64 + proof.zkProof.length);

    const depositRoot = this.merkleTree.generateProof(0).root;
    result.set(depositRoot, 0);
    result.set(proof.associationRoot, 32);
    result.set(proof.zkProof, 64);

    return result;
  }
}

export function createVaultSDK(config: VaultConfig): PrivacyVaultSDK {
  return new PrivacyVaultSDK(config);
}

export async function createVaultSDKWithSigner(
  config: VaultConfig,
  privateKey: string
): Promise<PrivacyVaultSDK> {
  const provider = new ethers.JsonRpcProvider(config.rpcUrl);
  const signer = new ethers.Wallet(privateKey, provider);
  return new PrivacyVaultSDK(config, signer);
}
