let wasmModule: {
  generate_withdrawal_proof: (request: string) => string;
  verify_withdrawal_proof: (proof: string) => boolean;
  generate_compliance_proof: (request: string) => string;
} | null = null;

let initPromise: Promise<void> | null = null;

export async function loadWasmModule() {
  if (wasmModule) {
    return wasmModule;
  }

  if (initPromise) {
    await initPromise;
    return wasmModule!;
  }

  initPromise = (async () => {
    try {
      const wasmUrl = "/wasm/zkenclave_circuits_bg.wasm";
      const jsUrl = "/wasm/zkenclave_circuits.js";

      const response = await fetch(jsUrl);
      if (!response.ok) {
        throw new Error(
          `Failed to fetch WASM JS wrapper: ${response.statusText}`
        );
      }

      const jsText = await response.text();

      const moduleBlob = new Blob([jsText], { type: "application/javascript" });
      const moduleUrl = URL.createObjectURL(moduleBlob);

      const wasmInit = await import(/* webpackIgnore: true */ moduleUrl);

      await wasmInit.default({ module_or_path: wasmUrl });

      wasmModule = {
        generate_withdrawal_proof: wasmInit.generate_withdrawal_proof,
        verify_withdrawal_proof: wasmInit.verify_withdrawal_proof,
        generate_compliance_proof:
          wasmInit.generate_compliance_proof ||
          (() => {
            throw new Error(
              "Compliance proof generation not available in WASM module"
            );
          }),
      };
    } catch (error) {
      initPromise = null;
      throw new Error(
        `Failed to load WASM module: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  })();

  await initPromise;
  return wasmModule!;
}

export function getWasmModule() {
  return wasmModule;
}
