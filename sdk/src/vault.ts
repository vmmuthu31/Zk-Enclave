import { ethers } from "ethers";
import {
  PRIVACY_VAULT_ABI,
  ASP_REGISTRY_ABI,
  DEFAULT_GAS_LIMIT,
} from "./constants";
import {
  generateDepositNote,
  computeNullifier,
  bytesToHex,
  hexToBytes,
  bytes32ToBigInt,
  bigIntToBytes32,
  MerkleTree,
} from "./crypto";
import type {
  DepositNote,
  DepositResult,
  WithdrawalResult,
  VaultConfig,
  VaultStats,
} from "./types";
import { ZKProofClient } from "./zk-client";

export class PrivacyVaultSDK {
  private provider: ethers.Provider;
  private signer: ethers.Signer | null = null;
  private vault: ethers.Contract;
  private readVault: ethers.Contract;
  private _aspRegistry: ethers.Contract;
  private zkClient: ZKProofClient;
  private config: VaultConfig;
  private _merkleTree: MerkleTree;

  constructor(
    config: VaultConfig,
    signer?: ethers.Signer,
    zkClient?: ZKProofClient
  ) {
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

    this.readVault = new ethers.Contract(
      config.vaultAddress,
      PRIVACY_VAULT_ABI,
      this.provider
    );

    this._aspRegistry = new ethers.Contract(
      config.aspRegistryAddress,
      ASP_REGISTRY_ABI,
      this.provider
    );

    this.zkClient = zkClient || new ZKProofClient();
    this._merkleTree = new MerkleTree();
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

    let leafIndex = -1;
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

    if (depositEvent) {
      const parsed = this.vault.interface.parseLog({
        topics: depositEvent.topics as string[],
        data: depositEvent.data,
      });
      leafIndex = Number(parsed?.args?.leafIndex ?? -1);
    }

    note.leafIndex = leafIndex;

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
      secret: note.secret,
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
      timestamp: Date.now(),
    };
  }

  async getLatestRoot(): Promise<Uint8Array> {
    const root = await this.readVault.getLatestRoot();
    return hexToBytes(root);
  }

  async getNextLeafIndex(): Promise<number> {
    const index = await this.readVault.getNextLeafIndex();
    return Number(index);
  }

  async isNullifierUsed(nullifier: Uint8Array): Promise<boolean> {
    return await this.readVault.isNullifierUsed(bytesToHex(nullifier));
  }

  async isKnownRoot(root: Uint8Array): Promise<boolean> {
    return await this.vault.isKnownRoot(bytesToHex(root));
  }

  async getVaultStats(): Promise<VaultStats> {
    const [nextLeafIndex, latestRoot] = await Promise.all([
      this.vault.getNextLeafIndex(),
      this.vault.getLatestRoot(),
    ]);

    return {
      totalDeposits: 0n,
      totalWithdrawals: 0n,
      nextLeafIndex: Number(nextLeafIndex),
      latestRoot: hexToBytes(latestRoot),
    };
  }

  getConfig(): VaultConfig {
    return this.config;
  }
}
