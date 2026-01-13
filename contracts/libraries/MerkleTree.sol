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
        if (level == 1) return bytes32(0x2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864);
        if (level == 2) return bytes32(0x1069673dcdb12263df301a6ff584a7ec261a44cb9dc68df067a4774460b1f1e1);
        if (level == 3) return bytes32(0x18f43331537ee2af2e3d758d50f72106467c6eea50371dd528d57eb2b856d238);
        if (level == 4) return bytes32(0x07f9d837cb17b0d36320ffe93ba52345f1b728571a568265caac97559dbc952a);
        if (level == 5) return bytes32(0x2b94cf5e8746b3f5c9631f4c5df32907a699c58c94b2ad4d7b5cec1639183f55);
        if (level == 6) return bytes32(0x2dee93c5a666459646ea7d22cca9e1bcfed71e6951b953611d11dda32ea09d78);
        if (level == 7) return bytes32(0x078295e5a22b84e982cf601eb639597b8b0515a88cb5ac7fa8a4aabe3c87349d);
        if (level == 8) return bytes32(0x2fa5e5f18f6027a6501bec864564472a616b2e274a41211c5e5d0de4abcf7b24);
        if (level >= 9) return bytes32(0x16b574c67f335db71e4222d86784166001642d4b1e3c2c72b49cc57864ee4f20);
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
