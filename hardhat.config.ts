import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-ethers";
import * as dotenv from "dotenv";

dotenv.config();

const PRIVATE_KEY = process.env.PRIVATE_KEY || "";

const config: HardhatUserConfig = {
  solidity: {
    version: "0.8.23",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200,
      },
      viaIR: true,
    },
  },
  networks: {
    hardhat: {
      type: "edr-simulated",
      chainId: 31337,
    },
    celoSepolia: {
      type: "http",
      url:
        process.env.CELO_SEPOLIA_RPC_URL ||
        "https://forno.celo-sepolia.celo-testnet.org",
      accounts: [PRIVATE_KEY],
      chainId: 11142220,
    },
    horizenSepolia: {
      type: "http",
      url:
        process.env.HORIZEN_RPC_URL ||
        "https://horizen-rpc-testnet.appchain.base.org",
      accounts: [PRIVATE_KEY],
      chainId: 845320009,
    },
  },
  paths: {
    sources: "./contracts",
    tests: "./test",
    cache: "./cache",
    artifacts: "./artifacts",
  },
};

export default config;
