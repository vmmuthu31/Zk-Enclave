import { ethers } from "ethers";
import * as dotenv from "dotenv";

dotenv.config();

const VAULT_ADDRESS = "0x5215D0bf334668c5722bc94fEF1F82d95443Cf57";
const RPC_URL = "https://horizen-rpc-testnet.appchain.base.org";

const PRIVACY_VAULT_ABI = [
  "function deposit(bytes32 commitment) external payable",
  "function getLatestRoot() external view returns (bytes32)",
  "function getNextLeafIndex() external view returns (uint256)",
  "function paused() external view returns (bool)",
  "event Deposit(bytes32 indexed commitment, uint256 leafIndex, uint256 amount, uint256 timestamp)",
];

async function main() {
  console.log("Testing deposit on NEW optimized PrivacyVault...\n");

  const provider = new ethers.JsonRpcProvider(RPC_URL);
  const privateKey = process.env.PRIVATE_KEY;

  if (!privateKey) {
    console.error("PRIVATE_KEY not found in .env");
    process.exit(1);
  }

  const wallet = new ethers.Wallet(privateKey, provider);
  console.log("Using wallet:", wallet.address);

  const vault = new ethers.Contract(VAULT_ADDRESS, PRIVACY_VAULT_ABI, wallet);

  console.log("\n--- Contract State ---");
  const paused = await vault.paused();
  console.log("Contract paused:", paused);

  const nextLeafIndex = await vault.getNextLeafIndex();
  console.log("Next leaf index:", nextLeafIndex.toString());

  console.log("\n--- Testing Deposit ---");

  const randomBytes = new Uint8Array(32);
  crypto.getRandomValues(randomBytes);
  const randomCommitment = ethers.keccak256(randomBytes);
  console.log("Generated commitment:", randomCommitment);

  const depositAmount = ethers.parseEther("0.01");
  console.log("Deposit amount:", ethers.formatEther(depositAmount), "ETH");

  try {
    console.log("\nEstimating gas...");
    const gasEstimate = await vault.deposit.estimateGas(randomCommitment, {
      value: depositAmount,
    });
    console.log("Estimated gas:", gasEstimate.toString());

    console.log("\nSending deposit transaction...");
    const tx = await vault.deposit(randomCommitment, {
      value: depositAmount,
      gasLimit: gasEstimate * 2n,
    });
    console.log("Transaction hash:", tx.hash);

    console.log("Waiting for confirmation...");
    const receipt = await tx.wait();
    console.log("\n✅ Transaction confirmed in block:", receipt?.blockNumber);
    console.log("Gas used:", receipt?.gasUsed.toString());
    console.log("Status:", receipt?.status === 1 ? "SUCCESS" : "FAILED");

    if (receipt?.logs) {
      for (const log of receipt.logs) {
        try {
          const parsed = vault.interface.parseLog({
            topics: log.topics as string[],
            data: log.data,
          });
          if (parsed?.name === "Deposit") {
            console.log("\n--- Deposit Event ---");
            console.log("Commitment:", parsed.args?.commitment);
            console.log("Leaf Index:", parsed.args?.leafIndex?.toString());
            console.log(
              "Amount:",
              ethers.formatEther(parsed.args?.amount || 0),
              "ETH"
            );
          }
        } catch {
          // Not our event
        }
      }
    }
  } catch (error: unknown) {
    console.error("\n--- Deposit Failed ---");
    if (error instanceof Error) {
      console.error("Error:", error.message);
    }
  }

  console.log("\n--- Final State ---");
  const finalLeafIndex = await vault.getNextLeafIndex();
  console.log("Next leaf index:", finalLeafIndex.toString());
  const finalRoot = await vault.getLatestRoot();
  console.log("Latest root:", finalRoot);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
