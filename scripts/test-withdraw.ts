import { ethers } from "ethers";
import * as dotenv from "dotenv";

dotenv.config();

const VAULT_ADDRESS = "0x5215D0bf334668c5722bc94fEF1F82d95443Cf57";
const RPC_URL = "https://horizen-rpc-testnet.appchain.base.org";

const PRIVACY_VAULT_ABI = [
  "function deposit(bytes32 commitment) external payable",
  "function withdraw(bytes32 nullifierHash, bytes32 root, address recipient, uint256 amount, bytes zkProof, bytes teeAttestation) external",
  "function getLatestRoot() external view returns (bytes32)",
  "function getNextLeafIndex() external view returns (uint256)",
  "function isNullifierUsed(bytes32 nullifier) external view returns (bool)",
  "function isKnownRoot(bytes32 root) external view returns (bool)",
  "event Deposit(bytes32 indexed commitment, uint256 leafIndex, uint256 amount, uint256 timestamp)",
  "event Withdrawal(bytes32 indexed nullifierHash, address indexed recipient, uint256 amount, bytes32 merkleRoot)",
];

async function main() {
  console.log("Testing FULL deposit + withdraw flow...\n");

  const provider = new ethers.JsonRpcProvider(RPC_URL);
  const privateKey = process.env.PRIVATE_KEY;

  if (!privateKey) {
    console.error("PRIVATE_KEY not found in .env");
    process.exit(1);
  }

  const wallet = new ethers.Wallet(privateKey, provider);
  console.log("Using wallet:", wallet.address);

  const initialBalance = await provider.getBalance(wallet.address);
  console.log("Initial balance:", ethers.formatEther(initialBalance), "ETH");

  const vault = new ethers.Contract(VAULT_ADDRESS, PRIVACY_VAULT_ABI, wallet);

  console.log("\n=== STEP 1: DEPOSIT ===");

  const secret = ethers.randomBytes(32);
  const nullifierSeed = ethers.randomBytes(32);
  const amount = ethers.parseEther("0.01");

  const commitment = ethers.keccak256(
    ethers.concat([
      secret,
      nullifierSeed,
      ethers.zeroPadValue(ethers.toBeHex(amount), 32),
    ])
  );
  console.log("Commitment:", commitment);

  const depositTx = await vault.deposit(commitment, {
    value: amount,
    gasLimit: 3000000n,
  });
  console.log("Deposit tx:", depositTx.hash);

  const depositReceipt = await depositTx.wait();
  console.log(
    "Deposit confirmed, gas used:",
    depositReceipt?.gasUsed.toString()
  );

  let leafIndex = 0;
  for (const log of depositReceipt?.logs || []) {
    try {
      const parsed = vault.interface.parseLog({
        topics: log.topics as string[],
        data: log.data,
      });
      if (parsed?.name === "Deposit") {
        leafIndex = Number(parsed.args?.leafIndex);
        console.log("Leaf index:", leafIndex);
      }
    } catch {}
  }

  console.log("\n=== STEP 2: GET MERKLE ROOT ===");

  const merkleRoot = await vault.getLatestRoot();
  console.log("Latest merkle root:", merkleRoot);

  const isKnownRoot = await vault.isKnownRoot(merkleRoot);
  console.log("Is known root:", isKnownRoot);

  console.log("\n=== STEP 3: COMPUTE NULLIFIER ===");

  const nullifierHash = ethers.keccak256(
    ethers.concat([
      nullifierSeed,
      ethers.zeroPadValue(ethers.toBeHex(leafIndex), 4),
    ])
  );
  console.log("Nullifier hash:", nullifierHash);

  const isNullifierUsed = await vault.isNullifierUsed(nullifierHash);
  console.log("Is nullifier used:", isNullifierUsed);

  console.log("\n=== STEP 4: WITHDRAW ===");

  const recipient = wallet.address;

  const mockProof = ethers.randomBytes(256);
  const teeAttestation = new Uint8Array(64);

  try {
    console.log("Attempting withdrawal...");
    console.log("  Nullifier:", nullifierHash);
    console.log("  Root:", merkleRoot);
    console.log("  Recipient:", recipient);
    console.log("  Amount:", ethers.formatEther(amount), "ETH");

    const withdrawTx = await vault.withdraw(
      nullifierHash,
      merkleRoot,
      recipient,
      amount,
      mockProof,
      teeAttestation,
      { gasLimit: 3000000n }
    );
    console.log("Withdraw tx:", withdrawTx.hash);

    const withdrawReceipt = await withdrawTx.wait();
    console.log("\n✅ Withdrawal SUCCESS!");
    console.log("Gas used:", withdrawReceipt?.gasUsed.toString());

    for (const log of withdrawReceipt?.logs || []) {
      try {
        const parsed = vault.interface.parseLog({
          topics: log.topics as string[],
          data: log.data,
        });
        if (parsed?.name === "Withdrawal") {
          console.log("\n--- Withdrawal Event ---");
          console.log("Nullifier:", parsed.args?.nullifierHash);
          console.log("Recipient:", parsed.args?.recipient);
          console.log(
            "Amount:",
            ethers.formatEther(parsed.args?.amount || 0),
            "ETH"
          );
        }
      } catch {}
    }
  } catch (error: unknown) {
    console.error("\n❌ Withdrawal Failed");
    if (error instanceof Error) {
      console.error("Error:", error.message.slice(0, 200));

      if (error.message.includes("InvalidProof")) {
        console.log("\n⚠️  This is expected - the mock ZK proof is not valid.");
        console.log(
          "The contract's ZK verifier correctly rejected the fake proof."
        );
        console.log(
          "In production, use the real ZK proof generated by the WASM circuit."
        );
      }
    }
  }

  console.log("\n=== FINAL STATE ===");
  const finalBalance = await provider.getBalance(wallet.address);
  console.log("Final balance:", ethers.formatEther(finalBalance), "ETH");
  console.log("Next leaf index:", (await vault.getNextLeafIndex()).toString());
  console.log("Nullifier used:", await vault.isNullifierUsed(nullifierHash));
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
