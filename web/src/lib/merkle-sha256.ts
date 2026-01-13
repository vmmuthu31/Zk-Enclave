import { sha256, concat } from "ethers";

// Matches contract's MERKLE_TREE_DEPTH = 20
export const MERKLE_TREE_DEPTH = 20;

export class MerkleTreeSHA256 {
  private leaves: string[];
  private layers: string[][];
  private readonly depth: number;
  private readonly zeroValues: string[];

  constructor(leaves: string[] = [], depth: number = MERKLE_TREE_DEPTH) {
    this.depth = depth;
    this.leaves = [...leaves];
    this.layers = [];
    this.zeroValues = this.computeZeroValues();
    this.rebuild();
  }

  private computeZeroValues(): string[] {
    let currentZero = "0x" + "00".repeat(32);
    const zeros: string[] = [currentZero];

    for (let i = 0; i < this.depth; i++) {
      currentZero = this.hashPair(currentZero, currentZero);
      zeros.push(currentZero);
    }
    return zeros;
  }

  private hashPair(left: string, right: string): string {
    return sha256(concat([left, right]));
  }

  // Purely rebuilds the tree based on current leaves
  // Inefficient for large trees but fine for MVP with few leaves
  private rebuild(): void {
    this.layers = [this.leaves.map((l) => l)]; // Level 0

    // Fill Level 0 to current size, but logically it's sparse.
    // However, to compute root, we just need to hash up.
    // The contract puts new leaves at 'nextIndex'.
    // We assume 'this.leaves' is the sparse array from 0 to last_index.

    // We will build layers dynamically like the contract does IMPLICITLY?
    // Actually the contract stores 'filledSubtrees' which is the frontier.
    // Here we can just simulate the full tree path for the specific leaf we want.
    // But to be generic, let's build layers.
  }

  // Standard getProof for a static tree snapshot
  public getProof(index: number): {
    path: string[];
    indices: boolean[];
    root: string;
  } {
    const path: string[] = [];
    const indices: boolean[] = [];

    let currentIndex = index;
    let currentLevelValues = [...this.leaves]; // Start with leaves

    for (let level = 0; level < this.depth; level++) {
      const isRight = currentIndex % 2 === 1;
      const siblingIndex = isRight ? currentIndex - 1 : currentIndex + 1;

      let sibling: string;

      if (siblingIndex < currentLevelValues.length) {
        sibling = currentLevelValues[siblingIndex];
      } else {
        sibling = this.zeroValues[level]; // Use zero value for that level
      }

      path.push(sibling);
      indices.push(isRight); // Correct direction?
      // If node is Right, Sibling is Left.
      // The contract/verifier usually wants the sibling.
      // path_indices[i] = 1 if sibling is Left? or 1 if node is Right?
      // Usually: 0 -> sibling is right (element is left)
      //          1 -> sibling is left (element is right)

      // Let's compute next level for the loop
      const nextLevelValues: string[] = [];
      for (let i = 0; i < currentLevelValues.length; i += 2) {
        const left = currentLevelValues[i];
        const right =
          i + 1 < currentLevelValues.length
            ? currentLevelValues[i + 1]
            : this.zeroValues[level];
        nextLevelValues.push(this.hashPair(left, right));
      }
      currentLevelValues = nextLevelValues;
      currentIndex = Math.floor(currentIndex / 2);
    }

    // Verification: Root should be currentLevelValues[0] (after loop finishes, level=depth)
    // Actually loop runs 'depth' times. After level 19, we have level 20 (root).

    return {
      path, // array of 20 siblings
      indices, // array of 20 booleans
      root: currentLevelValues[0] || this.zeroValues[this.depth],
    };
  }

  public getRoot(): string {
    // Quick root calc
    let currentLevelValues = [...this.leaves];
    for (let level = 0; level < this.depth; level++) {
      const nextLevelValues: string[] = [];
      for (let i = 0; i < currentLevelValues.length; i += 2) {
        const left = currentLevelValues[i];
        const right =
          i + 1 < currentLevelValues.length
            ? currentLevelValues[i + 1]
            : this.zeroValues[level];
        nextLevelValues.push(this.hashPair(left, right));
      }
      currentLevelValues = nextLevelValues;
      // Optimization: if currentLevelValues is empty or only zeros, we can short circuit?
      // But strict impl is safer.
    }
    return currentLevelValues[0] || this.zeroValues[this.depth];
  }
}
