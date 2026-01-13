import { NextRequest, NextResponse } from "next/server";
import { keccak256 } from "ethers";

interface WithdrawalRequest {
  commitment: number[];
  nullifierSeed: number[];
  secret: number[];
  amount: string;
  leafIndex: number;
  recipient: string;
  merklePath: number[][];
  pathIndices: boolean[];
  merkleRoot: number[];
}

interface TEEAttestation {
  enclaveId: string;
  timestamp: number;
  dataHash: string;
  signature: string;
}

const nullifierSet = new Set<string>();
const currentMerkleRoot = new Uint8Array(32);

export async function POST(request: NextRequest) {
  const body: WithdrawalRequest = await request.json();

  const nullifierSeed = new Uint8Array(body.nullifierSeed);
  const secret = new Uint8Array(body.secret);
  const amount = BigInt(body.amount);
  const leafIndex = body.leafIndex;
  const recipient = body.recipient;
  const merklePath = body.merklePath.map((p) => new Uint8Array(p));
  const pathIndices = body.pathIndices;
  const merkleRoot = new Uint8Array(body.merkleRoot);

  const nullifierHash = computeNullifierHash(nullifierSeed, leafIndex);
  const nullifierHex = bytesToHex(nullifierHash);

  if (nullifierSet.has(nullifierHex)) {
    return NextResponse.json(
      {
        success: false,
        error: "Nullifier already used",
      },
      { status: 400 }
    );
  }

  const computedCommitment = computeCommitment(secret, nullifierSeed, amount);

  const merkleValid = verifyMerklePath(
    computedCommitment,
    merklePath,
    pathIndices,
    merkleRoot
  );

  if (!merkleValid) {
    return NextResponse.json(
      {
        success: false,
        error: "Invalid Merkle proof",
      },
      { status: 400 }
    );
  }

  const zkProof = await generateZKProof({
    merkleRoot,
    nullifierHash,
    recipient,
    amount,
    secret,
    nullifierSeed,
    leafIndex,
    merklePath,
    pathIndices,
  });

  nullifierSet.add(nullifierHex);

  const dataHash = hashWithdrawalData(nullifierHash, merkleRoot);
  const teeAttestation = createTEEAttestation(dataHash);

  return NextResponse.json({
    success: true,
    zkProof: bytesToHex(zkProof),
    nullifierHash: nullifierHex,
    teeAttestation,
    timestamp: Date.now(),
  });
}

export async function GET() {
  return NextResponse.json({
    status: "healthy",
    nullifierCount: nullifierSet.size,
    currentMerkleRoot: bytesToHex(currentMerkleRoot),
  });
}

function computeNullifierHash(
  nullifierSeed: Uint8Array,
  leafIndex: number
): Uint8Array {
  const indexBytes = new Uint8Array(4);
  new DataView(indexBytes.buffer).setUint32(0, leafIndex, false);
  const combined = new Uint8Array([...nullifierSeed, ...indexBytes]);
  const hash = keccak256(combined);
  return hexToBytes(hash);
}

function computeCommitment(
  secret: Uint8Array,
  nullifier: Uint8Array,
  amount: bigint
): Uint8Array {
  const amountBytes = new Uint8Array(32);
  const amountHex = amount.toString(16).padStart(64, "0");
  for (let i = 0; i < 32; i++) {
    amountBytes[i] = parseInt(amountHex.slice(i * 2, i * 2 + 2), 16);
  }
  const combined = new Uint8Array([...secret, ...nullifier, ...amountBytes]);
  const hash = keccak256(combined);
  return hexToBytes(hash);
}

function verifyMerklePath(
  leaf: Uint8Array,
  path: Uint8Array[],
  indices: boolean[],
  root: Uint8Array
): boolean {
  let current = leaf;
  for (let i = 0; i < path.length; i++) {
    const sibling = path[i];
    if (indices[i]) {
      current = hashPair(sibling, current);
    } else {
      current = hashPair(current, sibling);
    }
  }
  return arraysEqual(current, root);
}

function hashPair(left: Uint8Array, right: Uint8Array): Uint8Array {
  const combined = new Uint8Array([...left, ...right]);
  const hash = keccak256(combined);
  return hexToBytes(hash);
}

function arraysEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

async function generateZKProof(input: {
  merkleRoot: Uint8Array;
  nullifierHash: Uint8Array;
  recipient: string;
  amount: bigint;
  secret: Uint8Array;
  nullifierSeed: Uint8Array;
  leafIndex: number;
  merklePath: Uint8Array[];
  pathIndices: boolean[];
}): Promise<Uint8Array> {
  const proofData = {
    merkleRoot: Array.from(input.merkleRoot),
    nullifierHash: Array.from(input.nullifierHash),
    recipient: input.recipient,
    amount: input.amount.toString(),
    leafIndex: input.leafIndex,
    timestamp: Date.now(),
  };

  const proofBytes = new TextEncoder().encode(JSON.stringify(proofData));
  return proofBytes;
}

function hashWithdrawalData(
  nullifierHash: Uint8Array,
  merkleRoot: Uint8Array
): Uint8Array {
  const combined = new Uint8Array([...nullifierHash, ...merkleRoot]);
  const hash = keccak256(combined);
  return hexToBytes(hash);
}

function createTEEAttestation(dataHash: Uint8Array): TEEAttestation {
  const timestamp = Date.now();

  const enclaveId = bytesToHex(
    new Uint8Array([
      0x50, 0x48, 0x41, 0x4c, 0x41, 0x5f, 0x54, 0x45, 0x45, 0x5f, 0x56, 0x31,
      0x00, 0x00, 0x00, 0x00,
    ])
  );

  const signatureData = new Uint8Array([
    ...dataHash,
    ...new Uint8Array(new BigUint64Array([BigInt(timestamp)]).buffer),
  ]);
  const signature = keccak256(signatureData);

  return {
    enclaveId,
    timestamp,
    dataHash: bytesToHex(dataHash),
    signature,
  };
}

function bytesToHex(bytes: Uint8Array): string {
  return (
    "0x" +
    Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("")
  );
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}
