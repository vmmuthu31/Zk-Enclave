// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "./PoseidonT3.sol";

library MerkleTreeLib {
    uint256 constant ROOT_HISTORY_SIZE = 30;

    struct MerkleTree {
        uint256 depth;
        uint256 nextIndex;
        bytes32[ROOT_HISTORY_SIZE] roots;
        uint256 currentRootIndex;
        mapping(uint256 => bytes32) filledSubtrees;
        mapping(bytes32 => bool) knownRoots;
    }

    function initialize(MerkleTree storage tree, uint256 _depth) internal {
        tree.depth = _depth;
        tree.nextIndex = 0;
        tree.currentRootIndex = 0;

        bytes32 currentZero = bytes32(0);
        for (uint256 i = 0; i < _depth; i++) {
            tree.filledSubtrees[i] = currentZero;
            currentZero = hashPair(currentZero, currentZero);
        }

        tree.roots[0] = currentZero;
        tree.knownRoots[currentZero] = true;
    }

    function insert(MerkleTree storage tree, bytes32 leaf) internal returns (uint256) {
        uint256 index = tree.nextIndex;
        require(index < 2**tree.depth, "Merkle tree is full");

        uint256 currentIndex = index;
        bytes32 currentHash = leaf;

        for (uint256 i = 0; i < tree.depth; i++) {
            if (currentIndex % 2 == 0) {
                tree.filledSubtrees[i] = currentHash;
                currentHash = hashPair(currentHash, zeros(i));
            } else {
                currentHash = hashPair(tree.filledSubtrees[i], currentHash);
            }
            currentIndex /= 2;
        }

        tree.currentRootIndex = (tree.currentRootIndex + 1) % ROOT_HISTORY_SIZE;
        tree.roots[tree.currentRootIndex] = currentHash;
        tree.knownRoots[currentHash] = true;
        tree.nextIndex = index + 1;

        return index;
    }

    function isKnownRoot(MerkleTree storage tree, bytes32 root) internal view returns (bool) {
        if (root == bytes32(0)) return false;
        return tree.knownRoots[root];
    }

    function getLastRoot(MerkleTree storage tree) internal view returns (bytes32) {
        return tree.roots[tree.currentRootIndex];
    }

    function hashPair(bytes32 left, bytes32 right) internal pure returns (bytes32) {
        uint256 l = uint256(left);
        uint256 r = uint256(right);
        return bytes32(PoseidonT3.hash([l, r]));
    }

    function zeros(uint256 level) internal pure returns (bytes32) {
        if (level == 0) return bytes32(0);
        
        bytes32 result = bytes32(0);
        for (uint256 i = 0; i < level; i++) {
            result = hashPair(result, result);
        }
        return result;
    }

    function verify(
        bytes32 root,
        bytes32 leaf,
        bytes32[] memory proof,
        uint256[] memory positions
    ) internal pure returns (bool) {
        bytes32 computedHash = leaf;

        for (uint256 i = 0; i < proof.length; i++) {
            if (positions[i] == 0) {
                computedHash = hashPair(computedHash, proof[i]);
            } else {
                computedHash = hashPair(proof[i], computedHash);
            }
        }

        return computedHash == root;
    }
}
