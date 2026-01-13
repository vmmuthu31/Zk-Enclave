declare module "/wasm/zkenclave_circuits.js" {
  export default function init(wasmPath: string): Promise<void>;
  export function generate_withdrawal_proof(request: string): string;
  export function verify_withdrawal_proof(proof: string): boolean;
}
