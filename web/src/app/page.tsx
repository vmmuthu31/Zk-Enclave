"use client";

import { useState, useEffect, useCallback } from "react";
import { BrowserProvider, parseEther, formatEther } from "ethers";
import { PrivacyVaultSDK, CHAIN_CONFIG, bytesToHex } from "zkenclave-sdk";
import type { DepositNote as SDKDepositNote, VaultConfig } from "zkenclave-sdk";
import { WebZKProofClient } from "../lib/WebZKProofClient";
import { createComplianceTree } from "../lib/merkle";

const VAULT_CONFIG: VaultConfig = {
  vaultAddress: "0x5215D0bf334668c5722bc94fEF1F82d95443Cf57",
  zkVerifierAddress: "0x85cf5E0d401db57a48a0477eC0433114C8F5774d",
  aspRegistryAddress: "0xc4eD99B7f7299635Edff19202e4Db635259A2353",
  chainId: 845320009,
  rpcUrl:
    CHAIN_CONFIG[845320009]?.rpcUrl ||
    "https://horizen-rpc-testnet.appchain.base.org",
};

interface UINote {
  id: string;
  secret: string;
  nullifier: string;
  commitment: string;
  amount: string;
  leafIndex: number;
  timestamp: number;
}

const STORAGE_KEY = "privacy_vault_notes";

function loadNotes(): UINote[] {
  if (typeof window === "undefined") return [];
  const stored = localStorage.getItem(STORAGE_KEY);
  return stored ? JSON.parse(stored) : [];
}

function saveNotes(notes: UINote[]) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(notes));
}

function hexToBytes(hex: string): Uint8Array {
  const cleanHex = hex.startsWith("0x") ? hex.slice(2) : hex;
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(cleanHex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

export default function Home() {
  const [mounted, setMounted] = useState(false);
  const [sdk, setSdk] = useState<PrivacyVaultSDK | null>(null);
  const [zkClient, setZkClient] = useState<WebZKProofClient | null>(null);
  const [connected, setConnected] = useState(false);
  const [address, setAddress] = useState("");
  const [balance, setBalance] = useState("0");
  const [depositAmount, setDepositAmount] = useState("0.01");
  const [savedNotes, setSavedNotes] = useState<UINote[]>([]);
  const [selectedNote, setSelectedNote] = useState<UINote | null>(null);
  const [withdrawAddress, setWithdrawAddress] = useState("");
  const [loading, setLoading] = useState(false);
  const [status, setStatus] = useState("");
  const [vaultStats, setVaultStats] = useState({ deposits: 0, root: "" });

  useEffect(() => {
    setMounted(true);
  }, []);

  const loadVaultStats = useCallback(async () => {
    try {
      const tempClient = new WebZKProofClient();
      const tempSdk = new PrivacyVaultSDK(VAULT_CONFIG, undefined, tempClient);
      const stats = await tempSdk.getVaultStats();
      setVaultStats({
        deposits: stats.nextLeafIndex,
        root: bytesToHex(stats.latestRoot).slice(0, 16) + "…",
      });
    } catch (error) {
      console.error("Failed to load vault stats:", error);
    }
  }, []);

  const checkConnection = useCallback(async () => {
    if (typeof window !== "undefined" && window.ethereum) {
      try {
        const provider = new BrowserProvider(window.ethereum);
        const accounts = await provider.listAccounts();
        if (accounts.length > 0) {
          setAddress(accounts[0].address);
          setConnected(true);
          const bal = await provider.getBalance(accounts[0].address);
          setBalance(formatEther(bal));
          const signer = await provider.getSigner();
          const client = new WebZKProofClient();
          setZkClient(client);
          const newSdk = new PrivacyVaultSDK(VAULT_CONFIG, signer, client);
          setSdk(newSdk);
        }
      } catch (error) {
        console.error("Check connection error:", error);
      }
    }
  }, []);

  useEffect(() => {
    loadVaultStats();
    checkConnection();
    setSavedNotes(loadNotes());

    if (window.ethereum) {
      window.ethereum.on("accountsChanged", checkConnection);
      window.ethereum.on("chainChanged", checkConnection);
    }

    return () => {
      if (window.ethereum) {
        window.ethereum.removeListener("accountsChanged", checkConnection);
        window.ethereum.removeListener("chainChanged", checkConnection);
      }
    };
  }, [loadVaultStats, checkConnection]);

  async function connectWallet() {
    if (typeof window !== "undefined" && window.ethereum) {
      try {
        const provider = new BrowserProvider(window.ethereum);
        await provider.send("eth_requestAccounts", []);
        await switchNetwork();
        await checkConnection();
      } catch (error) {
        console.error("Connection error:", error);
        setStatus("Connection failed");
      }
    } else {
      setStatus("Install MetaMask");
    }
  }

  async function switchNetwork() {
    if (!window.ethereum) return;
    try {
      await window.ethereum.request({
        method: "wallet_switchEthereumChain",
        params: [{ chainId: `0x${VAULT_CONFIG.chainId.toString(16)}` }],
      });
    } catch (e: unknown) {
      if ((e as { code: number }).code === 4902) {
        await window.ethereum.request({
          method: "wallet_addEthereumChain",
          params: [
            {
              chainId: `0x${VAULT_CONFIG.chainId.toString(16)}`,
              chainName: "Horizen Sepolia",
              nativeCurrency: { name: "ETH", symbol: "ETH", decimals: 18 },
              rpcUrls: [VAULT_CONFIG.rpcUrl],
              blockExplorerUrls: [
                "https://horizen-explorer-testnet.appchain.base.org",
              ],
            },
          ],
        });
      }
    }
  }

  async function handleDeposit() {
    if (!sdk) return;
    setLoading(true);
    setStatus("Depositing…");

    try {
      const amount = parseEther(depositAmount);
      const result = await sdk.deposit(amount);

      const newNote: UINote = {
        id: crypto.randomUUID(),
        secret: bytesToHex(result.note.secret),
        nullifier: bytesToHex(result.note.nullifierSeed),
        commitment: bytesToHex(result.commitment),
        amount: depositAmount,
        leafIndex: result.leafIndex,
        timestamp: Date.now(),
      };

      const updated = [...savedNotes, newNote];
      setSavedNotes(updated);
      saveNotes(updated);

      setStatus(`Deposited ${depositAmount} ETH`);
      await checkConnection();
      await loadVaultStats();
    } catch (error) {
      setStatus(`Error: ${(error as Error).message.slice(0, 50)}`);
    } finally {
      setLoading(false);
    }
  }

  const [includeCompliance, setIncludeCompliance] = useState(false);

  async function handleWithdraw() {
    if (!sdk || !selectedNote || !withdrawAddress || !zkClient) return;
    setLoading(true);
    setStatus("Withdrawing…");

    try {
      const sdkNote: SDKDepositNote = {
        commitment: hexToBytes(selectedNote.commitment),
        secret: hexToBytes(selectedNote.secret),
        nullifierSeed: hexToBytes(selectedNote.nullifier),
        amount: parseEther(selectedNote.amount),
        leafIndex: selectedNote.leafIndex,
        timestamp: selectedNote.timestamp,
      };

      let complianceProof: Uint8Array | undefined;
      if (includeCompliance) {
        setStatus("Generating Compliance Proof (Real ZK)...");
        const { path, indices, root } = createComplianceTree(
          selectedNote.commitment
        );

        const proofResult = await zkClient.generateComplianceProof(
          sdkNote.commitment,
          path,
          indices,
          root
        );
        complianceProof = proofResult.proof;
      }

      await sdk.withdraw(sdkNote, withdrawAddress, complianceProof);

      const updated = savedNotes.filter((n) => n.id !== selectedNote.id);
      setSavedNotes(updated);
      saveNotes(updated);
      setSelectedNote(null);

      setStatus("Withdrawal complete");
      await checkConnection();
      await loadVaultStats();
    } catch (error) {
      console.error(error);
      setStatus(`Error: ${(error as Error).message.slice(0, 50)}`);
    } finally {
      setLoading(false);
    }
  }

  if (!mounted) return null;

  return (
    <div className="min-h-screen bg-neutral-950 text-neutral-200 p-8 font-mono">
      <div className="max-w-md mx-auto space-y-8">
        <div className="flex justify-between items-start">
          <div>
            <h1 className="text-xl font-bold text-neutral-100 tracking-tight">
              PRIVACY VAULT
            </h1>
            <div className="flex items-center gap-2 mt-2 text-xs text-neutral-500">
              <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
              <span>HORIZEN SEPOLIA</span>
            </div>
          </div>
          <div className="text-right">
            <div className="text-xs text-neutral-500 mb-1">VAULT STATS</div>
            <div className="text-sm">
              <span className="text-neutral-400">LEAVES:</span>{" "}
              <span className="text-neutral-200">{vaultStats.deposits}</span>
            </div>
            <div className="text-xs text-neutral-600 mt-1">
              ROOT: {vaultStats.root || "Loading..."}
            </div>
          </div>
        </div>

        {!connected ? (
          <button
            onClick={connectWallet}
            className="w-full border border-neutral-800 p-4 hover:bg-neutral-900 transition-colors text-left group"
          >
            <div className="text-sm text-neutral-500 group-hover:text-neutral-400 mb-1">
              STATUS
            </div>
            <div className="text-neutral-300">
              {status || "Connect Wallet to Access Vault"}
            </div>
          </button>
        ) : (
          <div className="space-y-6">
            <div className="grid grid-cols-2 gap-4">
              <div className="border border-neutral-800 p-3">
                <div className="text-xs text-neutral-500 mb-1">ADDRESS</div>
                <div className="text-xs truncate">{address}</div>
              </div>
              <div className="border border-neutral-800 p-3">
                <div className="text-xs text-neutral-500 mb-1">BALANCE</div>
                <div className="text-xs">{Number(balance).toFixed(4)} ETH</div>
              </div>
            </div>

            <div className="border border-neutral-800 p-4">
              <h2 className="text-sm text-neutral-500 mb-3">DEPOSIT</h2>
              <div className="flex gap-2">
                <input
                  type="text"
                  value={depositAmount}
                  onChange={(e) => setDepositAmount(e.target.value)}
                  className="flex-1 bg-transparent border border-neutral-700 px-3 py-2 text-sm focus:outline-none focus:border-neutral-500"
                />
                <button
                  onClick={handleDeposit}
                  disabled={loading || !sdk}
                  className="px-4 bg-neutral-100 text-neutral-950 text-sm font-medium hover:bg-neutral-300 disabled:opacity-50 transition-colors"
                >
                  DEPOSIT
                </button>
              </div>
            </div>

            <div className="border border-neutral-800 p-4">
              <h2 className="text-sm text-neutral-500 mb-3">YOUR NOTES</h2>
              <div className="space-y-2 max-h-48 overflow-y-auto">
                {savedNotes.length === 0 ? (
                  <div className="text-xs text-neutral-600 italic">
                    No notes found
                  </div>
                ) : (
                  savedNotes.map((note) => (
                    <div
                      key={note.id}
                      onClick={() => setSelectedNote(note)}
                      className={`p-2 border text-xs cursor-pointer transition-colors ${
                        selectedNote?.id === note.id
                          ? "border-neutral-500 bg-neutral-900"
                          : "border-neutral-800 hover:border-neutral-700"
                      }`}
                    >
                      <div className="flex justify-between mb-1">
                        <span>{note.amount} ETH</span>
                        <span className="text-neutral-500">
                          #{note.leafIndex}
                        </span>
                      </div>
                      <div className="text-neutral-600 truncate">
                        {note.commitment}
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>

            <div className="border border-neutral-800 p-4">
              <h2 className="text-sm text-neutral-500 mb-3">WITHDRAW</h2>
              <div className="space-y-3">
                <div className="text-sm">
                  <span className="text-neutral-500">Selected: </span>
                  {selectedNote ? (
                    <span>{selectedNote.amount} ETH</span>
                  ) : (
                    <span className="text-neutral-600">
                      Select a note above
                    </span>
                  )}
                </div>
                <input
                  type="text"
                  value={withdrawAddress}
                  onChange={(e) => setWithdrawAddress(e.target.value)}
                  placeholder="Recipient 0x…"
                  className="w-full bg-transparent border border-neutral-700 px-3 py-2 text-sm focus:outline-none focus:border-neutral-500"
                />

                <div className="flex items-center gap-2 mb-2">
                  <input
                    type="checkbox"
                    id="compliance"
                    checked={includeCompliance}
                    onChange={(e) => setIncludeCompliance(e.target.checked)}
                    className="accent-neutral-100 cursor-pointer"
                  />
                  <label
                    htmlFor="compliance"
                    className="text-sm text-neutral-400 select-none cursor-pointer"
                  >
                    Generate Compliance Proof (ASP)
                  </label>
                </div>

                <button
                  onClick={handleWithdraw}
                  disabled={
                    loading || !sdk || !selectedNote || !withdrawAddress
                  }
                  className="w-full border border-neutral-700 py-2 text-sm hover:bg-neutral-900 disabled:opacity-50 transition-colors"
                >
                  {loading ? "Processing…" : "Withdraw"}
                </button>
              </div>
            </div>

            {status && (
              <div
                className={`border p-3 text-sm ${
                  status.includes("Error")
                    ? "border-red-900 text-red-400"
                    : "border-neutral-800 text-neutral-400"
                }`}
              >
                {status}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
