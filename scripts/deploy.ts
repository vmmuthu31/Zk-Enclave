import hre from "hardhat";
import { ethers } from "ethers";

async function main() {
  console.log("=".repeat(60));
  console.log("Privacy Vault - Deployment Script");
  console.log("=".repeat(60));

  const networkConnection = await hre.network.connect();
  const provider = new ethers.BrowserProvider(networkConnection.provider);

  const accounts = await provider.listAccounts();
  const deployer = accounts[0];

  console.log("\nNetwork:", hre.network || "unknown");
  console.log("Deployer:", deployer.address);
  const balance = await provider.getBalance(deployer.address);
  console.log("Balance:", ethers.formatEther(balance), "ETH\n");

  if (balance === 0n) {
    console.error(
      "ERROR: Deployer has no balance. Please fund the account first."
    );
    process.exit(1);
  }

  console.log("1. Deploying ASPRegistry...");
  const aspRegistryArtifact = await hre.artifacts.readArtifact("ASPRegistry");
  const ASPRegistryFactory = new ethers.ContractFactory(
    aspRegistryArtifact.abi,
    aspRegistryArtifact.bytecode,
    deployer
  );
  const aspRegistry = await ASPRegistryFactory.deploy();
  await aspRegistry.waitForDeployment();
  const aspRegistryAddress = await aspRegistry.getAddress();
  console.log("   ✓ ASPRegistry deployed to:", aspRegistryAddress);

  console.log("2. Deploying ZKVerifier...");
  const zkVerifierArtifact = await hre.artifacts.readArtifact("ZKVerifier");
  const ZKVerifierFactory = new ethers.ContractFactory(
    zkVerifierArtifact.abi,
    zkVerifierArtifact.bytecode,
    deployer
  );
  const zkVerifier = await ZKVerifierFactory.deploy();
  await zkVerifier.waitForDeployment();
  const zkVerifierAddress = await zkVerifier.getAddress();
  console.log("   ✓ ZKVerifier deployed to:", zkVerifierAddress);

  console.log("3. Deploying PrivacyVault...");
  const privacyVaultArtifact = await hre.artifacts.readArtifact("PrivacyVault");
  const PrivacyVaultFactory = new ethers.ContractFactory(
    privacyVaultArtifact.abi,
    privacyVaultArtifact.bytecode,
    deployer
  );
  const privacyVault = await PrivacyVaultFactory.deploy(
    zkVerifierAddress,
    aspRegistryAddress
  );
  await privacyVault.waitForDeployment();
  const privacyVaultAddress = await privacyVault.getAddress();
  console.log("   ✓ PrivacyVault deployed to:", privacyVaultAddress);

  console.log("\n" + "=".repeat(60));
  console.log("DEPLOYMENT COMPLETE!");
  console.log("=".repeat(60));

  console.log("\n📋 Contract Addresses:");
  console.log("   ASPRegistry:   ", aspRegistryAddress);
  console.log("   ZKVerifier:    ", zkVerifierAddress);
  console.log("   PrivacyVault:  ", privacyVaultAddress);

  const chainId = (await provider.getNetwork()).chainId;

  console.log("\n📦 SDK Configuration:");
  const config = {
    vaultAddress: privacyVaultAddress,
    zkVerifierAddress: zkVerifierAddress,
    aspRegistryAddress: aspRegistryAddress,
    phatContractAddress: "",
    chainId: Number(chainId),
    rpcUrl: "UPDATE_WITH_RPC_URL",
  };
  console.log(JSON.stringify(config, null, 2));

  console.log("\n✅ Deployment successful!");
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("Deployment failed:", error);
    process.exit(1);
  });
