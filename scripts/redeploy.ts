import { ethers } from "ethers";
import * as dotenv from "dotenv";
import * as fs from "fs";

dotenv.config();

const RPC_URL = "https://horizen-rpc-testnet.appchain.base.org";

async function main() {
  console.log("=".repeat(60));
  console.log("Privacy Vault - Optimized Redeployment");
  console.log("=".repeat(60));

  const provider = new ethers.JsonRpcProvider(RPC_URL);
  const privateKey = process.env.PRIVATE_KEY;

  if (!privateKey) {
    console.error("PRIVATE_KEY not found in .env");
    process.exit(1);
  }

  const wallet = new ethers.Wallet(privateKey, provider);
  console.log("\nDeployer:", wallet.address);
  const balance = await provider.getBalance(wallet.address);
  console.log("Balance:", ethers.formatEther(balance), "ETH\n");

  const aspRegistryArtifact = JSON.parse(
    fs.readFileSync(
      "./artifacts/contracts/ASPRegistry.sol/ASPRegistry.json",
      "utf8"
    )
  );
  const zkVerifierArtifact = JSON.parse(
    fs.readFileSync(
      "./artifacts/contracts/ZKVerifier.sol/ZKVerifier.json",
      "utf8"
    )
  );
  const privacyVaultArtifact = JSON.parse(
    fs.readFileSync(
      "./artifacts/contracts/PrivacyVault.sol/PrivacyVault.json",
      "utf8"
    )
  );

  console.log("1. Deploying ASPRegistry...");
  const aspFactory = new ethers.ContractFactory(
    aspRegistryArtifact.abi,
    aspRegistryArtifact.bytecode,
    wallet
  );
  const aspRegistry = await aspFactory.deploy();
  await aspRegistry.waitForDeployment();
  const aspAddress = await aspRegistry.getAddress();
  console.log("   ✓ ASPRegistry:", aspAddress);

  console.log("2. Deploying ZKVerifier...");
  const zkFactory = new ethers.ContractFactory(
    zkVerifierArtifact.abi,
    zkVerifierArtifact.bytecode,
    wallet
  );
  const zkVerifier = await zkFactory.deploy();
  await zkVerifier.waitForDeployment();
  const zkAddress = await zkVerifier.getAddress();
  console.log("   ✓ ZKVerifier:", zkAddress);

  console.log("3. Deploying PrivacyVault (optimized)...");
  const vaultFactory = new ethers.ContractFactory(
    privacyVaultArtifact.abi,
    privacyVaultArtifact.bytecode,
    wallet
  );
  const vault = await vaultFactory.deploy(zkAddress, aspAddress);
  await vault.waitForDeployment();
  const vaultAddress = await vault.getAddress();
  console.log("   ✓ PrivacyVault:", vaultAddress);

  console.log("\n" + "=".repeat(60));
  console.log("DEPLOYMENT COMPLETE!");
  console.log("=".repeat(60));
  console.log("\n📋 Contract Addresses:");
  console.log("   ASPRegistry:   ", aspAddress);
  console.log("   ZKVerifier:    ", zkAddress);
  console.log("   PrivacyVault:  ", vaultAddress);

  console.log("\n📦 Update page.tsx with:");
  console.log(`const VAULT_CONFIG: VaultConfig = {`);
  console.log(`  vaultAddress: "${vaultAddress}",`);
  console.log(`  zkVerifierAddress: "${zkAddress}",`);
  console.log(`  aspRegistryAddress: "${aspAddress}",`);
  console.log(`  chainId: 845320009,`);
  console.log(`  rpcUrl: "https://horizen-rpc-testnet.appchain.base.org",`);
  console.log(`};`);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("Deployment failed:", error);
    process.exit(1);
  });
