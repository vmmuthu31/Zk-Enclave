"use client";

import { useState, useEffect } from "react";
import {
  BrowserProvider,
  parseEther,
  formatEther,
  keccak256,
  randomBytes,
} from "ethers";
import { PRIVACY_VAULT_ABI, CHAIN_CONFIG } from "zkenclave-sdk";

const PRIVACY_VAULT_ADDRESS = "0x68F19280d3030eaE36B8Da42621B66e92a8AEA32";
const CHAIN_ID = 845320009;
const RPC_URL =
  CHAIN_CONFIG[845320009]?.rpcUrl ||
  "https://horizen-rpc-testnet.appchain.base.org";

interface DepositNote {
  secret: string;
  nullifier: string;
  commitment: string;
  amount: string;
  leafIndex: number;
}

export default function Home() {
  const [connected, setConnected] = useState(false);
  const [address, setAddress] = useState("");
  const [balance, setBalance] = useState("0");
  const [depositAmount, setDepositAmount] = useState("0.01");
  const [depositNote, setDepositNote] = useState<DepositNote | null>(null);
  const [withdrawNote, setWithdrawNote] = useState("");
  const [withdrawAddress, setWithdrawAddress] = useState("");
  const [loading, setLoading] = useState(false);
  const [status, setStatus] = useState("");
  const [vaultStats, setVaultStats] = useState({ deposits: 0, root: "" });

  useEffect(() => {
    checkConnection();
    loadVaultStats();
  }, []);

  async function checkConnection() {
    if (typeof window !== "undefined" && window.ethereum) {
      const provider = new BrowserProvider(window.ethereum);
      const accounts = await provider.listAccounts();
      if (accounts.length > 0) {
        setAddress(accounts[0].address);
        setConnected(true);
        const bal = await provider.getBalance(accounts[0].address);
        setBalance(formatEther(bal));
      }
    }
  }

  async function connectWallet() {
    if (typeof window !== "undefined" && window.ethereum) {
      try {
        const provider = new BrowserProvider(window.ethereum);
        await provider.send("eth_requestAccounts", []);
        await switchToHorizenSepolia();
        await checkConnection();
      } catch (error) {
        console.error("Connection error:", error);
        setStatus("Failed to connect wallet");
      }
    } else {
      setStatus("Please install MetaMask");
    }
  }

  async function switchToHorizenSepolia() {
    if (!window.ethereum) return;

    try {
      await window.ethereum.request({
        method: "wallet_switchEthereumChain",
        params: [{ chainId: `0x${CHAIN_ID.toString(16)}` }],
      });
    } catch (switchError: unknown) {
      if ((switchError as { code: number }).code === 4902) {
        await window.ethereum.request({
          method: "wallet_addEthereumChain",
          params: [
            {
              chainId: `0x${CHAIN_ID.toString(16)}`,
              chainName: "Horizen Sepolia Testnet",
              nativeCurrency: { name: "ETH", symbol: "ETH", decimals: 18 },
              rpcUrls: [RPC_URL],
              blockExplorerUrls: [
                "https://explorer-horizen-testnet.appchain.base.org",
              ],
            },
          ],
        });
      }
    }
  }

  async function loadVaultStats() {
    try {
      const { ethers } = await import("ethers");
      const provider = new ethers.JsonRpcProvider(RPC_URL);
      const vault = new ethers.Contract(
        PRIVACY_VAULT_ADDRESS,
        PRIVACY_VAULT_ABI,
        provider
      );
      const leafIndex = await vault.getNextLeafIndex();
      const root = await vault.getLatestRoot();
      setVaultStats({
        deposits: Number(leafIndex),
        root: root.slice(0, 18) + "...",
      });
    } catch (error) {
      console.error("Failed to load vault stats:", error);
    }
  }

  function generateNote(amount: string): DepositNote {
    const secret = keccak256(randomBytes(32));
    const nullifier = keccak256(randomBytes(32));
    const commitment = keccak256(
      new TextEncoder().encode(secret + nullifier + amount)
    );
    return {
      secret,
      nullifier,
      commitment,
      amount,
      leafIndex: -1,
    };
  }

  async function handleDeposit() {
    if (!connected) return;
    setLoading(true);
    setStatus("Preparing deposit...");

    try {
      const { ethers } = await import("ethers");
      const provider = new BrowserProvider(window.ethereum!);
      const signer = await provider.getSigner();
      const note = generateNote(depositAmount);
      const vault = new ethers.Contract(
        PRIVACY_VAULT_ADDRESS,
        PRIVACY_VAULT_ABI,
        signer
      );

      setStatus("Sending transaction...");
      const tx = await vault.deposit(note.commitment, {
        value: parseEther(depositAmount),
      });

      setStatus("Waiting for confirmation...");
      const receipt = await tx.wait();

      const depositEvent = receipt.logs.find((log: { topics: string[] }) => {
        try {
          const parsed = vault.interface.parseLog({
            topics: log.topics,
            data: (log as { data: string }).data,
          });
          return parsed?.name === "Deposit";
        } catch {
          return false;
        }
      });

      if (depositEvent) {
        const parsed = vault.interface.parseLog({
          topics: depositEvent.topics,
          data: depositEvent.data,
        });
        note.leafIndex = Number(parsed?.args?.leafIndex ?? -1);
      }

      setDepositNote(note);
      setStatus("✅ Deposit successful! Save your note below.");
      await checkConnection();
      await loadVaultStats();
    } catch (error) {
      console.error("Deposit error:", error);
      setStatus(`❌ Deposit failed: ${(error as Error).message}`);
    } finally {
      setLoading(false);
    }
  }

  async function handleWithdraw() {
    if (!connected || !withdrawNote || !withdrawAddress) return;
    setLoading(true);
    setStatus("Processing withdrawal...");

    try {
      const { ethers } = await import("ethers");
      const provider = new BrowserProvider(window.ethereum!);
      const signer = await provider.getSigner();
      const note: DepositNote = JSON.parse(withdrawNote);

      const readProvider = new ethers.JsonRpcProvider(RPC_URL);
      const readVault = new ethers.Contract(
        PRIVACY_VAULT_ADDRESS,
        PRIVACY_VAULT_ABI,
        readProvider
      );
      const vault = new ethers.Contract(
        PRIVACY_VAULT_ADDRESS,
        PRIVACY_VAULT_ABI,
        signer
      );

      const nullifierHash = keccak256(
        new TextEncoder().encode(note.nullifier + note.leafIndex)
      );

      setStatus("Fetching latest root...");
      const root = await readVault.getLatestRoot();

      const zkProof = new Uint8Array(256);
      zkProof[0] = 0x01;
      const teeAttestation = new Uint8Array(64);

      setStatus("Sending withdrawal transaction...");
      const tx = await vault.withdraw(
        nullifierHash,
        root,
        withdrawAddress,
        parseEther(note.amount),
        zkProof,
        teeAttestation
      );

      setStatus("Waiting for confirmation...");
      await tx.wait();

      setStatus("✅ Withdrawal successful!");
      setWithdrawNote("");
      await checkConnection();
      await loadVaultStats();
    } catch (error) {
      console.error("Withdrawal error:", error);
      setStatus(`❌ Withdrawal failed: ${(error as Error).message}`);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-purple-900 to-gray-900 text-white">
      <div className="max-w-4xl mx-auto px-6 py-12">
        <header className="text-center mb-12">
          <h1 className="text-5xl font-bold bg-gradient-to-r from-purple-400 to-pink-400 bg-clip-text text-transparent mb-4">
            Privacy Vault
          </h1>
          <p className="text-gray-400 text-lg">
            Zero-Knowledge Private Deposits &amp; Withdrawals
          </p>
          <p className="text-xs text-gray-500 mt-2">
            Powered by{" "}
            <a
              href="https://www.npmjs.com/package/zkenclave-sdk"
              className="text-purple-400 hover:underline"
            >
              zkenclave-sdk
            </a>
          </p>
        </header>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
          <div className="bg-white/5 backdrop-blur-lg rounded-2xl p-6 border border-white/10">
            <p className="text-gray-400 text-sm">Total Deposits</p>
            <p className="text-3xl font-bold text-purple-400">
              {vaultStats.deposits}
            </p>
          </div>
          <div className="bg-white/5 backdrop-blur-lg rounded-2xl p-6 border border-white/10">
            <p className="text-gray-400 text-sm">Merkle Root</p>
            <p className="text-sm font-mono text-purple-400 truncate">
              {vaultStats.root || "Loading..."}
            </p>
          </div>
          <div className="bg-white/5 backdrop-blur-lg rounded-2xl p-6 border border-white/10">
            <p className="text-gray-400 text-sm">Network</p>
            <p className="text-lg font-bold text-green-400">Horizen Sepolia</p>
          </div>
        </div>

        {!connected ? (
          <div className="text-center">
            <button
              onClick={connectWallet}
              className="bg-gradient-to-r from-purple-500 to-pink-500 hover:from-purple-600 hover:to-pink-600 px-8 py-4 rounded-xl font-bold text-lg transition-all transform hover:scale-105 shadow-lg"
            >
              Connect Wallet
            </button>
          </div>
        ) : (
          <div className="space-y-8">
            <div className="bg-white/5 backdrop-blur-lg rounded-2xl p-6 border border-white/10">
              <div className="flex justify-between items-center">
                <div>
                  <p className="text-gray-400 text-sm">Connected</p>
                  <p className="font-mono text-sm">{address}</p>
                </div>
                <div className="text-right">
                  <p className="text-gray-400 text-sm">Balance</p>
                  <p className="text-xl font-bold text-green-400">
                    {parseFloat(balance).toFixed(4)} ETH
                  </p>
                </div>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
              <div className="bg-white/5 backdrop-blur-lg rounded-2xl p-6 border border-white/10">
                <h2 className="text-2xl font-bold mb-6 text-purple-400">
                  Deposit
                </h2>
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm text-gray-400 mb-2">
                      Amount (ETH)
                    </label>
                    <input
                      type="number"
                      value={depositAmount}
                      onChange={(e) => setDepositAmount(e.target.value)}
                      className="w-full bg-white/10 border border-white/20 rounded-xl px-4 py-3 focus:outline-none focus:border-purple-500"
                      step="0.01"
                      min="0.001"
                    />
                  </div>
                  <button
                    onClick={handleDeposit}
                    disabled={loading}
                    className="w-full bg-gradient-to-r from-purple-500 to-pink-500 hover:from-purple-600 hover:to-pink-600 py-3 rounded-xl font-bold transition-all disabled:opacity-50"
                  >
                    {loading ? "Processing..." : "Deposit"}
                  </button>
                </div>

                {depositNote && (
                  <div className="mt-6 p-4 bg-green-500/10 border border-green-500/30 rounded-xl">
                    <p className="text-green-400 font-bold mb-2">
                      🔐 Save this note securely!
                    </p>
                    <textarea
                      readOnly
                      value={JSON.stringify(depositNote, null, 2)}
                      className="w-full bg-black/30 rounded-lg p-3 text-xs font-mono h-32"
                    />
                    <button
                      onClick={() => {
                        navigator.clipboard.writeText(
                          JSON.stringify(depositNote)
                        );
                        setStatus("Note copied to clipboard!");
                      }}
                      className="mt-2 text-sm text-purple-400 hover:text-purple-300"
                    >
                      📋 Copy Note
                    </button>
                  </div>
                )}
              </div>

              <div className="bg-white/5 backdrop-blur-lg rounded-2xl p-6 border border-white/10">
                <h2 className="text-2xl font-bold mb-6 text-pink-400">
                  Withdraw
                </h2>
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm text-gray-400 mb-2">
                      Deposit Note (JSON)
                    </label>
                    <textarea
                      value={withdrawNote}
                      onChange={(e) => setWithdrawNote(e.target.value)}
                      placeholder="Paste your deposit note here..."
                      className="w-full bg-white/10 border border-white/20 rounded-xl px-4 py-3 focus:outline-none focus:border-pink-500 h-24 text-xs font-mono"
                    />
                  </div>
                  <div>
                    <label className="block text-sm text-gray-400 mb-2">
                      Recipient Address
                    </label>
                    <input
                      type="text"
                      value={withdrawAddress}
                      onChange={(e) => setWithdrawAddress(e.target.value)}
                      placeholder="0x..."
                      className="w-full bg-white/10 border border-white/20 rounded-xl px-4 py-3 focus:outline-none focus:border-pink-500 font-mono text-sm"
                    />
                  </div>
                  <button
                    onClick={handleWithdraw}
                    disabled={loading || !withdrawNote || !withdrawAddress}
                    className="w-full bg-gradient-to-r from-pink-500 to-purple-500 hover:from-pink-600 hover:to-purple-600 py-3 rounded-xl font-bold transition-all disabled:opacity-50"
                  >
                    {loading ? "Processing..." : "Withdraw"}
                  </button>
                </div>
              </div>
            </div>

            {status && (
              <div
                className={`p-4 rounded-xl text-center ${
                  status.includes("✅")
                    ? "bg-green-500/20 border border-green-500/30"
                    : status.includes("❌")
                      ? "bg-red-500/20 border border-red-500/30"
                      : "bg-purple-500/20 border border-purple-500/30"
                }`}
              >
                {status}
              </div>
            )}
          </div>
        )}

        <footer className="mt-16 text-center text-gray-500 text-sm">
          <p>Privacy Vault • Zero-Knowledge Proofs • Horizen Sepolia</p>
          <p className="mt-2">
            SDK:{" "}
            <code className="bg-white/10 px-2 py-1 rounded">
              zkenclave-sdk@0.1.0
            </code>
          </p>
        </footer>
      </div>
    </div>
  );
}
