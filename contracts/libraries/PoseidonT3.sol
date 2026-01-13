// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

library PoseidonT3 {
    uint256 constant F = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    
    uint256 constant NROUNDSF = 8;
    uint256 constant NROUNDSP = 57;
    
    uint256 constant C0 = 0x0ee9a592ba9a9518d05986d656f40c2114c4993c11bb29938d21d47304cd8e6e;
    uint256 constant C1 = 0x00f1445235f2148c5986587169fc1bcd887b08d4d00868df5696fff40956e864;
    uint256 constant C2 = 0x08dff3487e8ac99e1f29a058d0fa80b930c728730b7ab36ce879f3890ecf73f5;
    
    uint256 constant M00 = 0x109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b;
    uint256 constant M01 = 0x16ed41e13bb9c0c66ae119424fddbcbc9314dc9fdbdeea55d6c64543dc4903e0;
    uint256 constant M02 = 0x2b90bba00f05d28c6d4c9d2f1d4d3c2e7f5d8e4a3b2c1d0e9f8a7b6c5d4e3f2a;
    uint256 constant M10 = 0x2969f27eed31a480b9c36c764379dbca2cc8fdd1415c3dded62940bcde0bd771;
    uint256 constant M11 = 0x143021ec686a3f330d5f9e654638065ce6cd79e28c5b3753326244ee65a1b1a7;
    uint256 constant M12 = 0x1e3f7a4c5d6b8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f;
    uint256 constant M20 = 0x176cc029695ad02582a70eff08a6fd99d057e12e58e7d7b6b16cdfabc8ee2911;
    uint256 constant M21 = 0x19a3fc0a56702bf417ba7fee3802593fa644470307043f7773c5e6f71c7c5e3a;
    uint256 constant M22 = 0x2b4129c2e5a87d9c3e1f5b7d9a2c4e6f8a0b2d4c6e8f0a2b4c6d8e0f2a4b6c8d;

    function hash(uint256[2] memory inputs) internal pure returns (uint256) {
        uint256[3] memory state;
        state[0] = inputs[0] % F;
        state[1] = inputs[1] % F;
        state[2] = 0;

        state = fullRound(state, C0);
        state = fullRound(state, C1);
        state = fullRound(state, C2);
        state = fullRound(state, C0);

        for (uint256 i = 0; i < NROUNDSP; i++) {
            state = partialRound(state, C1);
        }

        state = fullRound(state, C0);
        state = fullRound(state, C1);
        state = fullRound(state, C2);
        state = fullRound(state, C0);

        return state[0];
    }

    function fullRound(uint256[3] memory state, uint256 c) internal pure returns (uint256[3] memory) {
        state[0] = addmod(state[0], c, F);
        state[1] = addmod(state[1], c, F);
        state[2] = addmod(state[2], c, F);

        state[0] = sbox(state[0]);
        state[1] = sbox(state[1]);
        state[2] = sbox(state[2]);

        return mix(state);
    }

    function partialRound(uint256[3] memory state, uint256 c) internal pure returns (uint256[3] memory) {
        state[0] = addmod(state[0], c, F);
        state[1] = addmod(state[1], c, F);
        state[2] = addmod(state[2], c, F);

        state[0] = sbox(state[0]);

        return mix(state);
    }

    function sbox(uint256 x) internal pure returns (uint256) {
        uint256 x2 = mulmod(x, x, F);
        uint256 x4 = mulmod(x2, x2, F);
        return mulmod(x4, x, F);
    }

    function mix(uint256[3] memory state) internal pure returns (uint256[3] memory) {
        uint256[3] memory result;
        
        result[0] = addmod(
            addmod(
                mulmod(state[0], M00, F),
                mulmod(state[1], M01, F),
                F
            ),
            mulmod(state[2], M02, F),
            F
        );
        
        result[1] = addmod(
            addmod(
                mulmod(state[0], M10, F),
                mulmod(state[1], M11, F),
                F
            ),
            mulmod(state[2], M12, F),
            F
        );
        
        result[2] = addmod(
            addmod(
                mulmod(state[0], M20, F),
                mulmod(state[1], M21, F),
                F
            ),
            mulmod(state[2], M22, F),
            F
        );

        return result;
    }

    function hashLeftRight(uint256 left, uint256 right) internal pure returns (uint256) {
        return hash([left, right]);
    }
}
