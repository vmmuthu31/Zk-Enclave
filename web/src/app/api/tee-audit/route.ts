import { NextRequest, NextResponse } from "next/server";
import { keccak256 } from "ethers";

interface AuditEntry {
  id: string;
  operationType: "withdrawal" | "batch_withdrawal" | "compliance_check";
  timestamp: number;
  dataHash: string;
  nullifierHash?: string;
  encryptedMetadata: string;
}

const auditLog: Map<string, AuditEntry> = new Map();
const entryOrder: string[] = [];

export async function POST(request: NextRequest) {
  const { action, ...params } = await request.json();

  switch (action) {
    case "add": {
      const entry = await addAuditEntry(params);
      return NextResponse.json({ success: true, entryId: entry.id });
    }

    case "query": {
      const entries = getEntriesInRange(params.startTime, params.endTime);
      return NextResponse.json({ entries });
    }

    case "disclose": {
      const disclosure = await generateDisclosure(
        params.entryId,
        params.regulatorId
      );
      return NextResponse.json(disclosure);
    }

    default:
      return NextResponse.json({ error: "Unknown action" }, { status: 400 });
  }
}

export async function GET(request: NextRequest) {
  const url = new URL(request.url);
  const startTime = url.searchParams.get("startTime");
  const endTime = url.searchParams.get("endTime");

  if (startTime && endTime) {
    const entries = getEntriesInRange(parseInt(startTime), parseInt(endTime));
    return NextResponse.json({
      entries: entries.map((e) => ({
        id: e.id,
        operationType: e.operationType,
        timestamp: e.timestamp,
        dataHash: e.dataHash,
      })),
    });
  }

  return NextResponse.json({
    totalEntries: auditLog.size,
    oldestEntry:
      entryOrder.length > 0 ? auditLog.get(entryOrder[0])?.timestamp : null,
    newestEntry:
      entryOrder.length > 0
        ? auditLog.get(entryOrder[entryOrder.length - 1])?.timestamp
        : null,
  });
}

async function addAuditEntry(params: {
  operationType: AuditEntry["operationType"];
  nullifierHash?: string;
  merkleRoot: string;
  metadata: Record<string, unknown>;
}): Promise<AuditEntry> {
  const id = generateEntryId();
  const timestamp = Date.now();

  const dataHash = keccak256(
    new TextEncoder().encode(
      JSON.stringify({
        operationType: params.operationType,
        nullifierHash: params.nullifierHash,
        merkleRoot: params.merkleRoot,
        timestamp,
      })
    )
  );

  const encryptedMetadata = Buffer.from(
    JSON.stringify(params.metadata)
  ).toString("base64");

  const entry: AuditEntry = {
    id,
    operationType: params.operationType,
    timestamp,
    dataHash,
    nullifierHash: params.nullifierHash,
    encryptedMetadata,
  };

  auditLog.set(id, entry);
  entryOrder.push(id);

  return entry;
}

function getEntriesInRange(startTime: number, endTime: number): AuditEntry[] {
  return Array.from(auditLog.values()).filter(
    (entry) => entry.timestamp >= startTime && entry.timestamp <= endTime
  );
}

async function generateDisclosure(
  entryId: string,
  _regulatorId: string
): Promise<{
  success: boolean;
  entry?: Partial<AuditEntry>;
  metadata?: Record<string, unknown>;
  error?: string;
}> {
  const entry = auditLog.get(entryId);
  if (!entry) {
    return { success: false, error: "Entry not found" };
  }

  const metadata = JSON.parse(
    Buffer.from(entry.encryptedMetadata, "base64").toString()
  );

  return {
    success: true,
    entry: {
      id: entry.id,
      operationType: entry.operationType,
      timestamp: entry.timestamp,
      dataHash: entry.dataHash,
    },
    metadata,
  };
}

function generateEntryId(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return (
    "0x" +
    Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("")
  );
}
