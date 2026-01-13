"use client";

import { useState, useEffect, useCallback } from "react";
import { BrowserProvider, parseEther, formatEther } from "ethers";
import { PrivacyVaultSDK, CHAIN_CONFIG, bytesToHex } from "zkenclave-sdk";
import type { DepositNote as SDKDepositNote, VaultConfig } from "zkenclave-sdk";

const VAULT_CONFIG: VaultConfig = {
  vaultAddress: "0x68F19280d3030eaE36B8Da42621B66e92a8AEA32",
  zkVerifierAddress: "0x68491614a84C0410E9Fc0CB59Fc60A4F9188687c",
  aspRegistryAddress: "0xB041Cff58FB866c7f4326e0767c97B93434aBa9E",
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

import { WebZKProofClient } from "../lib/WebZKProofClient";

// ...

export default function Home() {
  const [sdk, setSdk] = useState<PrivacyVaultSDK | null>(null);
  const [connected, setConnected] = useState(false);
  const [address, setAddress] = useState("");
  const [balance, setBalance] = useState("0");
  const [depositAmount, setDepositAmount] = useState("0.001");
  const [savedNotes, setSavedNotes] = useState<UINote[]>([]);
  const [selectedNote, setSelectedNote] = useState<UINote | null>(null);
  const [withdrawAddress, setWithdrawAddress] = useState("");
  const [loading, setLoading] = useState(false);
  const [status, setStatus] = useState("");
  const [vaultStats, setVaultStats] = useState({ deposits: 0, root: "" });

  const loadVaultStats = useCallback(async () => {
    try {
      const tempSdk = new PrivacyVaultSDK(VAULT_CONFIG);
      const stats = await tempSdk.getVaultStats();
      setVaultStats({
        deposits: stats.nextLeafIndex,
        root: bytesToHex(stats.latestRoot).slice(0, 16) + "…",
      });
    } catch (error) {
      console.error("Failed to load vault stats:", error);
    }
  }, []);

  useEffect(() => {
    loadVaultStats();
    checkConnection();
    setSavedNotes(loadNotes());
  }, [loadVaultStats]);

  async function checkConnection() {
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
          // Use WebZKProofClient for WASM proofs
          const zkClient = new WebZKProofClient();
          const newSdk = new PrivacyVaultSDK(VAULT_CONFIG, signer, zkClient);
          setSdk(newSdk);
        }
      } catch (error) {
        console.error("Check connection error:", error);
      }
    }
  }

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

  async function handleWithdraw() {
    if (!sdk || !selectedNote || !withdrawAddress) return;
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

      await sdk.withdraw(sdkNote, withdrawAddress);

      const updated = savedNotes.filter((n) => n.id !== selectedNote.id);
      setSavedNotes(updated);
      saveNotes(updated);
      setSelectedNote(null);

      setStatus("Withdrawal complete");
      await checkConnection();
      await loadVaultStats();
    } catch (error) {
      setStatus(`Error: ${(error as Error).message.slice(0, 50)}`);
    } finally {
      setLoading(false);
    }
  }

  function deleteNote(id: string) {
    const updated = savedNotes.filter((n) => n.id !== id);
    setSavedNotes(updated);
    saveNotes(updated);
    if (selectedNote?.id === id) setSelectedNote(null);
  }

  function hexToBytes(hex: string): Uint8Array {
    const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
    const bytes = new Uint8Array(clean.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  }

  return (
    <div className="min-h-screen bg-neutral-950 text-neutral-100 font-mono">
      <div className="max-w-2xl mx-auto px-4 py-8">
        {/* Header */}
        <header className="mb-8 border-b border-neutral-800 pb-6">
          <h1 className="text-2xl font-bold tracking-tight">Privacy Vault</h1>
          <p className="text-neutral-500 text-sm mt-1">
            zkenclave-sdk • Horizen Sepolia
          </p>
        </header>

        {/* Stats */}
        <div className="grid grid-cols-3 gap-4 mb-8 text-sm">
          <div className="border border-neutral-800 p-3">
            <p className="text-neutral-500">Deposits</p>
            <p className="text-lg">{vaultStats.deposits}</p>
          </div>
          <div className="border border-neutral-800 p-3">
            <p className="text-neutral-500">Root</p>
            <p className="text-xs truncate">{vaultStats.root || "—"}</p>
          </div>
          <div className="border border-neutral-800 p-3">
            <p className="text-neutral-500">SDK</p>
            <p className={sdk ? "text-green-500" : "text-yellow-500"}>
              {sdk ? "Ready" : "—"}
            </p>
          </div>
        </div>

        {!connected ? (
          <button
            onClick={connectWallet}
            className="w-full border border-neutral-700 hover:bg-neutral-900 py-3 transition-colors"
          >
            Connect Wallet
          </button>
        ) : (
          <div className="space-y-6">
            {/* Wallet */}
            <div className="border border-neutral-800 p-4 flex justify-between items-center text-sm">
              <span className="text-neutral-500">
                {address.slice(0, 8)}…{address.slice(-6)}
              </span>
              <span>{parseFloat(balance).toFixed(4)} ETH</span>
            </div>

            {/* Deposit */}
            <div className="border border-neutral-800 p-4">
              <h2 className="text-sm text-neutral-500 mb-3">DEPOSIT</h2>
              <div className="flex gap-2">
                <input
                  type="number"
                  value={depositAmount}
                  onChange={(e) => setDepositAmount(e.target.value)}
                  className="flex-1 bg-transparent border border-neutral-700 px-3 py-2 text-sm focus:outline-none focus:border-neutral-500"
                  step="0.001"
                  min="0.001"
                />
                <button
                  onClick={handleDeposit}
                  disabled={loading || !sdk}
                  className="border border-neutral-700 px-4 py-2 text-sm hover:bg-neutral-900 disabled:opacity-50 transition-colors"
                >
                  {loading ? "…" : "Deposit"}
                </button>
              </div>
            </div>

            {/* Saved Notes */}
            <div className="border border-neutral-800 p-4">
              <h2 className="text-sm text-neutral-500 mb-3">
                NOTES ({savedNotes.length})
              </h2>
              {savedNotes.length === 0 ? (
                <p className="text-neutral-600 text-sm">No saved notes</p>
              ) : (
                <div className="space-y-2 max-h-48 overflow-y-auto">
                  {savedNotes.map((note) => (
                    <div
                      key={note.id}
                      onClick={() => setSelectedNote(note)}
                      className={`flex justify-between items-center p-2 cursor-pointer text-sm border ${
                        selectedNote?.id === note.id
                          ? "border-neutral-500 bg-neutral-900"
                          : "border-neutral-800 hover:border-neutral-700"
                      }`}
                    >
                      <div>
                        <span className="text-neutral-400">
                          {note.amount} ETH
                        </span>
                        <span className="text-neutral-600 ml-2 text-xs">
                          #{note.leafIndex === -1 ? "pending" : note.leafIndex}
                        </span>
                      </div>
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          deleteNote(note.id);
                        }}
                        className="text-neutral-600 hover:text-red-500 text-xs"
                      >
                        ×
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Withdraw */}
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

            {/* Status */}
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

        {/* Footer */}
        <footer className="mt-12 pt-6 border-t border-neutral-800 text-neutral-600 text-xs">
          <p>npm install zkenclave-sdk</p>
        </footer>
      </div>
    </div>
  );
}
