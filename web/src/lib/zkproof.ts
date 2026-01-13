import init, {
  generate_withdrawal_proof,
  verify_withdrawal_proof,
} from "./wasm/zkenclave_circuits.js";

let wasmInitialized = false;
let initPromise: Promise<void> | null = null;

export async function initWasm(): Promise<boolean> {
  if (wasmInitialized) return true;

  if (initPromise) {
    await initPromise;
    return wasmInitialized;
  }

  initPromise = (async () => {
    try {
      await init("/wasm/zkenclave_circuits_bg.wasm");
      wasmInitialized = true;
    } catch (error) {
      console.error("Failed to initialize WASM:", error);
      wasmInitialized = false;
    }
  })();

  await initPromise;
  return wasmInitialized;
}

export interface ProofRequest {
  secret: number[];
  nullifier_seed: number[];
  amount: number;
  leaf_index: number;
  merkle_path: number[][];
  path_indices: boolean[];
  merkle_root: number[];
  recipient: number[];
}

export interface ProofResult {
  success: boolean;
  proof: number[];
  nullifier_hash: number[];
  public_inputs: number[][];
  error?: string;
}

export async function generateProof(
  request: ProofRequest
): Promise<ProofResult> {
  const ready = await initWasm();
  if (!ready) {
    return {
      success: false,
      proof: [],
      nullifier_hash: [],
      public_inputs: [],
      error: "WASM not initialized",
    };
  }

  try {
    const resultJson = generate_withdrawal_proof(JSON.stringify(request));
    return JSON.parse(resultJson);
  } catch (error) {
    return {
      success: false,
      proof: [],
      nullifier_hash: [],
      public_inputs: [],
      error: String(error),
    };
  }
}

export async function verifyProof(proofResult: ProofResult): Promise<boolean> {
  const ready = await initWasm();
  if (!ready) return false;

  try {
    return verify_withdrawal_proof(JSON.stringify(proofResult));
  } catch {
    return false;
  }
}

export function isWasmReady(): boolean {
  return wasmInitialized;
}
