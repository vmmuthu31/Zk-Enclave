import hre from "hardhat";
import { ethers } from "ethers";

async function main() {
  console.log("=".repeat(60));
  console.log("Privacy Vault - Functional Test Suite (Hardhat 3)");
  console.log("=".repeat(60));

  const networkConnection = await hre.network.connect();
  const provider = new ethers.BrowserProvider(networkConnection.provider);

  const accounts = await provider.listAccounts();
  console.log("\nAccounts available:", accounts.length);

  const deployer = accounts[0];
  const user1 = accounts[1];

  console.log("Deployer:", deployer.address);
  const balance = await provider.getBalance(deployer.address);
  console.log("Balance:", ethers.formatEther(balance), "ETH\n");

  console.log("1. Deploying ASPRegistry...");
  const aspRegistryArtifact = await hre.artifacts.readArtifact("ASPRegistry");
  const ASPRegistryFactory = new ethers.ContractFactory(
    aspRegistryArtifact.abi,
    aspRegistryArtifact.bytecode,
    deployer
  );
  const aspRegistry = await ASPRegistryFactory.deploy();
  await aspRegistry.waitForDeployment();
  console.log("   ✓ ASPRegistry deployed to:", await aspRegistry.getAddress());

  console.log("2. Deploying ZKVerifier...");
  const zkVerifierArtifact = await hre.artifacts.readArtifact("ZKVerifier");
  const ZKVerifierFactory = new ethers.ContractFactory(
    zkVerifierArtifact.abi,
    zkVerifierArtifact.bytecode,
    deployer
  );
  const zkVerifier = await ZKVerifierFactory.deploy();
  await zkVerifier.waitForDeployment();
  console.log("   ✓ ZKVerifier deployed to:", await zkVerifier.getAddress());

  console.log("3. Deploying PrivacyVault...");
  const privacyVaultArtifact = await hre.artifacts.readArtifact("PrivacyVault");
  const PrivacyVaultFactory = new ethers.ContractFactory(
    privacyVaultArtifact.abi,
    privacyVaultArtifact.bytecode,
    deployer
  );
  const privacyVault = await PrivacyVaultFactory.deploy(
    await zkVerifier.getAddress(),
    await aspRegistry.getAddress()
  );
  await privacyVault.waitForDeployment();
  console.log(
    "   ✓ PrivacyVault deployed to:",
    await privacyVault.getAddress()
  );

  console.log("\n" + "-".repeat(60));
  console.log("Running Functional Tests...");
  console.log("-".repeat(60));

  let passed = 0;
  let failed = 0;

  async function test(name: string, fn: () => Promise<boolean>) {
    try {
      const result = await fn();
      if (result) {
        console.log(`✅ ${name}`);
        passed++;
      } else {
        console.log(`❌ ${name} - assertion failed`);
        failed++;
      }
    } catch (error: any) {
      console.log(`❌ ${name} - ${error.message?.slice(0, 60) || error}`);
      failed++;
    }
  }

  await test("Owner is deployer", async () => {
    return (await privacyVault.owner()) === deployer.address;
  });

  await test("TEE operator is deployer", async () => {
    return (await privacyVault.teeOperator()) === deployer.address;
  });

  await test("Initial total deposits is 0", async () => {
    return (await privacyVault.totalDeposits()) === 0n;
  });

  await test("Merkle tree depth is 20", async () => {
    return (await privacyVault.MERKLE_TREE_DEPTH()) === 20n;
  });

  const commitment1 = ethers.keccak256(ethers.toUtf8Bytes("test_commitment_1"));
  const depositAmount = ethers.parseEther("0.1");

  const vaultWithUser1 = privacyVault.connect(user1) as ethers.Contract;

  await test("Can make valid deposit", async () => {
    const tx = await vaultWithUser1.deposit(commitment1, {
      value: depositAmount,
    });
    const receipt = await tx.wait();
    return receipt !== null;
  });

  await test("Deposit updates total deposits", async () => {
    return (await privacyVault.totalDeposits()) === depositAmount;
  });

  await test("Leaf index increments", async () => {
    return (await privacyVault.getNextLeafIndex()) === 1n;
  });

  await test("Known root updated after deposit", async () => {
    const root = await privacyVault.getLatestRoot();
    return await privacyVault.isKnownRoot(root);
  });

  await test("User deposits tracked", async () => {
    const deposits = await privacyVault.getUserDeposits(user1.address);
    return deposits.length === 1 && deposits[0] === commitment1;
  });

  await test("Reject duplicate commitment", async () => {
    try {
      await vaultWithUser1.deposit(commitment1, { value: depositAmount });
      return false;
    } catch {
      return true;
    }
  });

  await test("Reject zero commitment", async () => {
    try {
      await vaultWithUser1.deposit(ethers.ZeroHash, { value: depositAmount });
      return false;
    } catch {
      return true;
    }
  });

  await test("Reject deposit below minimum", async () => {
    try {
      const tooSmall = ethers.parseEther("0.001");
      const newCommitment = ethers.keccak256(
        ethers.toUtf8Bytes("small_deposit")
      );
      await vaultWithUser1.deposit(newCommitment, { value: tooSmall });
      return false;
    } catch {
      return true;
    }
  });

  await test("Owner can pause contract", async () => {
    await privacyVault.pause();
    return await privacyVault.paused();
  });

  await test("Deposit rejected when paused", async () => {
    try {
      const newCommitment = ethers.keccak256(
        ethers.toUtf8Bytes("paused_deposit")
      );
      await vaultWithUser1.deposit(newCommitment, { value: depositAmount });
      return false;
    } catch {
      return true;
    }
  });

  await test("Owner can unpause contract", async () => {
    await privacyVault.unpause();
    return !(await privacyVault.paused());
  });

  await test("Owner can set TEE operator", async () => {
    await privacyVault.setTEEOperator(user1.address);
    return (await privacyVault.teeOperator()) === user1.address;
  });

  const initialRoot = ethers.keccak256(ethers.toUtf8Bytes("asp_initial_root"));

  await test("Can register ASP provider", async () => {
    await aspRegistry.registerProvider(user1.address, "Test ASP", initialRoot);
    return await aspRegistry.isRegistered(user1.address);
  });

  const aspWithUser1 = aspRegistry.connect(user1) as ethers.Contract;

  await test("ASP provider can update root", async () => {
    const newRoot = ethers.keccak256(ethers.toUtf8Bytes("asp_new_root"));
    await aspWithUser1.updateRoot(newRoot);
    return (await aspRegistry.getProviderRoot(user1.address)) === newRoot;
  });

  await test("Can get active providers", async () => {
    const providers = await aspRegistry.getActiveProviders();
    return providers.length === 1;
  });

  await test("ZKVerifier simple proof verification works", async () => {
    const merkleRoot = ethers.keccak256(ethers.toUtf8Bytes("merkle_root"));
    const nullifier = ethers.keccak256(ethers.toUtf8Bytes("nullifier"));
    const recipient = ethers.zeroPadValue(deployer.address, 32);
    const amount = ethers.toBeHex(ethers.parseEther("0.1"), 32);

    // Proof format for simple verification:
    // byte[0] = 0x01 (version)
    // bytes[1:33] = computed hash (32 bytes, can be any non-zero value)
    // bytes[33:65] = merkle root (must match publicInputs[0])
    // bytes[65:97] = nullifier (must match publicInputs[1])
    const computedHash = ethers.keccak256(
      ethers.concat([merkleRoot, nullifier, recipient, amount])
    );

    // Build proof: 1 byte version + 32 byte hash + 32 byte root + 32 byte nullifier = 97 bytes
    const proofBytes = new Uint8Array(97);
    proofBytes[0] = 0x01;

    // Copy computed hash at position 1
    const hashBytes = ethers.getBytes(computedHash);
    proofBytes.set(hashBytes, 1);

    // Copy merkle root at position 33
    const rootBytes = ethers.getBytes(merkleRoot);
    proofBytes.set(rootBytes, 33);

    // Copy nullifier at position 65
    const nullifierBytes = ethers.getBytes(nullifier);
    proofBytes.set(nullifierBytes, 65);

    const proof = ethers.hexlify(proofBytes);
    const publicInputs = [merkleRoot, nullifier, recipient, amount];
    const result = await zkVerifier.verifyProof(proof, publicInputs);
    return result === true;
  });

  console.log("\n" + "=".repeat(60));
  console.log(`Results: ${passed} passed, ${failed} failed`);
  console.log("=".repeat(60));

  if (failed > 0) {
    process.exit(1);
  }
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
