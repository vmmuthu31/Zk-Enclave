import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  reactCompiler: true,
  webpack: (config) => {
    config.experiments = {
      ...config.experiments,
      asyncWebAssembly: true,
      layers: true,
    };

    config.output = {
      ...config.output,
      webassemblyModuleFilename: "static/wasm/[modulehash].wasm",
    };

    return config;
  },
};

export default nextConfig;
