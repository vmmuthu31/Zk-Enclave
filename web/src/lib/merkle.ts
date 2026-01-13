import { MerkleTree } from "merkletreejs";
import keccak256 from "keccak256";

export function createComplianceTree(userCommitmentHex: string): {
  path: Uint8Array[];
  indices: boolean[];
  root: Uint8Array;
} {
  const leaves = [
    "0x1111111111111111111111111111111111111111111111111111111111111111",
    "0x2222222222222222222222222222222222222222222222222222222222222222",
    "0x3333333333333333333333333333333333333333333333333333333333333333",
    userCommitmentHex,
    "0x4444444444444444444444444444444444444444444444444444444444444444",
  ];

  const tree = new MerkleTree(leaves, keccak256, {
    sortPairs: true,
    hashLeaves: true,
  });
  const leaf = keccak256(userCommitmentHex);
  const proof = tree.getProof(leaf);
  const root = tree.getRoot();

  const path: Uint8Array[] = proof.map((p) => p.data);

  const indices: boolean[] = proof.map((p) => p.position === "right");

  return {
    path,
    indices,
    root: new Uint8Array(root),
  };
}
