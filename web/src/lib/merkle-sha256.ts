import { sha256, concat } from "ethers";

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

  private rebuild(): void {
    this.layers = [this.leaves.map((l) => l)];
  }

  public getProof(index: number): {
    path: string[];
    indices: boolean[];
    root: string;
  } {
    const path: string[] = [];
    const indices: boolean[] = [];

    let currentIndex = index;
    let currentLevelValues = [...this.leaves];

    for (let level = 0; level < this.depth; level++) {
      const isRight = currentIndex % 2 === 1;
      const siblingIndex = isRight ? currentIndex - 1 : currentIndex + 1;

      let sibling: string;

      if (siblingIndex < currentLevelValues.length) {
        sibling = currentLevelValues[siblingIndex];
      } else {
        sibling = this.zeroValues[level];
      }

      path.push(sibling);
      indices.push(isRight);
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

    return {
      path,
      indices,
      root: currentLevelValues[0] || this.zeroValues[this.depth],
    };
  }

  public getRoot(): string {
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
    }
    return currentLevelValues[0] || this.zeroValues[this.depth];
  }
}
