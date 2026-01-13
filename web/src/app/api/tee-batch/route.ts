import { NextRequest, NextResponse } from "next/server";

interface BatchRequest {
  withdrawal: {
    commitment: number[];
    nullifierSeed: number[];
    secret: number[];
    amount: string;
    leafIndex: number;
    recipient: string;
    merklePath: number[][];
    pathIndices: boolean[];
    merkleRoot: number[];
  };
}

interface PendingWithdrawal {
  request: BatchRequest["withdrawal"];
  requestId: string;
  addedAt: number;
}

const pendingBatch: PendingWithdrawal[] = [];
const MAX_BATCH_SIZE = 100;
const BATCH_WINDOW_MS = 30000;

let batchTimer: NodeJS.Timeout | null = null;

export async function POST(request: NextRequest) {
  const body: BatchRequest = await request.json();
  const requestId = generateRequestId();

  pendingBatch.push({
    request: body.withdrawal,
    requestId,
    addedAt: Date.now(),
  });

  if (pendingBatch.length >= MAX_BATCH_SIZE) {
    const result = await processBatch();
    return NextResponse.json({
      requestId,
      batchProcessed: true,
      batchResult: result,
    });
  }

  if (!batchTimer) {
    batchTimer = setTimeout(async () => {
      await processBatch();
      batchTimer = null;
    }, BATCH_WINDOW_MS);
  }

  return NextResponse.json({
    requestId,
    pendingCount: pendingBatch.length,
    estimatedProcessingTime: BATCH_WINDOW_MS,
  });
}

export async function GET() {
  return NextResponse.json({
    pendingCount: pendingBatch.length,
    maxBatchSize: MAX_BATCH_SIZE,
    batchWindowMs: BATCH_WINDOW_MS,
  });
}

async function processBatch(): Promise<{
  success: boolean;
  processedCount: number;
  batchId: string;
}> {
  if (pendingBatch.length === 0) {
    return { success: false, processedCount: 0, batchId: "" };
  }

  const batch = pendingBatch.splice(0, MAX_BATCH_SIZE);
  const batchId = generateRequestId();

  const aggregatedData = {
    batchId,
    withdrawalCount: batch.length,
    recipients: batch.map((b) => b.request.recipient),
    amounts: batch.map((b) => b.request.amount),
    timestamp: Date.now(),
  };

  const aggregatedProof = new TextEncoder().encode(
    JSON.stringify(aggregatedData)
  );

  console.log(
    `Batch ${batchId} processed: ${batch.length} withdrawals, proof: ${bytesToHex(aggregatedProof).slice(0, 20)}...`
  );

  return {
    success: true,
    processedCount: batch.length,
    batchId,
  };
}

function generateRequestId(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return bytesToHex(bytes);
}

function bytesToHex(bytes: Uint8Array): string {
  return (
    "0x" +
    Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("")
  );
}
