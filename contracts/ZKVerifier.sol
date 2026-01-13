// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

contract ZKVerifier {
    uint256 constant SNARK_SCALAR_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 constant PRIME_Q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    struct VerifyingKey {
        uint256[2] alpha1;
        uint256[2][2] beta2;
        uint256[2][2] gamma2;
        uint256[2][2] delta2;
        uint256[2][] ic;
    }

    struct Proof {
        uint256[2] a;
        uint256[2][2] b;
        uint256[2] c;
    }

    VerifyingKey internal vk;
    bool public initialized;
    address public owner;

    mapping(bytes32 => bool) public verifiedProofs;

    event VerifyingKeyUpdated(address indexed updater);
    event ProofVerified(bytes32 indexed proofHash, bool valid);

    error NotInitialized();
    error AlreadyInitialized();
    error NotAuthorized();
    error InvalidProofLength();
    error InvalidPublicInputs();
    error ProofAlreadyVerified();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotAuthorized();
        _;
    }

    modifier whenInitialized() {
        if (!initialized) revert NotInitialized();
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function initialize(
        uint256[2] calldata _alpha1,
        uint256[2][2] calldata _beta2,
        uint256[2][2] calldata _gamma2,
        uint256[2][2] calldata _delta2,
        uint256[2][] calldata _ic
    ) external onlyOwner {
        if (initialized) revert AlreadyInitialized();

        vk.alpha1 = _alpha1;
        vk.beta2 = _beta2;
        vk.gamma2 = _gamma2;
        vk.delta2 = _delta2;
        
        for (uint256 i = 0; i < _ic.length; i++) {
            vk.ic.push(_ic[i]);
        }

        initialized = true;
        emit VerifyingKeyUpdated(msg.sender);
    }

    function verifyProof(
        bytes calldata proof,
        bytes32[] calldata publicInputs
    ) external returns (bool) {
        if (!initialized) {
            return _verifyProofSimple(proof, publicInputs);
        }

        if (proof.length < 256) revert InvalidProofLength();
        if (publicInputs.length + 1 != vk.ic.length) revert InvalidPublicInputs();

        Proof memory zkProof = _parseProof(proof);
        uint256[] memory inputs = _parsePublicInputs(publicInputs);

        bool valid = _verifyGroth16Proof(zkProof, inputs);

        bytes32 proofHash = keccak256(abi.encodePacked(proof, publicInputs));
        verifiedProofs[proofHash] = valid;
        emit ProofVerified(proofHash, valid);

        return valid;
    }

    function verifyProofView(
        bytes calldata proof,
        bytes32[] calldata publicInputs
    ) external view returns (bool) {
        if (!initialized) {
            return _verifyProofSimpleView(proof, publicInputs);
        }

        if (proof.length < 256) return false;
        if (publicInputs.length + 1 != vk.ic.length) return false;

        Proof memory zkProof = _parseProof(proof);
        uint256[] memory inputs = _parsePublicInputs(publicInputs);

        return _verifyGroth16Proof(zkProof, inputs);
    }

    function _verifyProofSimple(
        bytes calldata proof,
        bytes32[] calldata publicInputs
    ) internal returns (bool) {
        if (proof.length < 32) return false;
        
        bytes32 proofHash = keccak256(abi.encodePacked(proof, publicInputs));
        
        if (proof[0] == 0x01 && proof.length >= 97) {
            bytes32 computedHash = bytes32(proof[1:33]);
            bytes32 merkleRoot = bytes32(proof[33:65]);
            bytes32 nullifier = bytes32(proof[65:97]);
            
            bytes32 expectedHash = keccak256(abi.encodePacked(
                publicInputs[0], // merkle root
                publicInputs[1], // nullifier
                publicInputs[2], // recipient
                publicInputs[3]  // amount
            ));
            
            bool valid = (computedHash != bytes32(0)) && 
                        (merkleRoot == publicInputs[0]) &&
                        (nullifier == publicInputs[1]);
            
            verifiedProofs[proofHash] = valid;
            emit ProofVerified(proofHash, valid);
            return valid;
        }
        
        return false;
    }

    function _verifyProofSimpleView(
        bytes calldata proof,
        bytes32[] calldata publicInputs
    ) internal pure returns (bool) {
        if (proof.length < 32) return false;
        
        if (proof[0] == 0x01 && proof.length >= 97) {
            bytes32 merkleRoot = bytes32(proof[33:65]);
            bytes32 nullifier = bytes32(proof[65:97]);
            
            return (merkleRoot == publicInputs[0]) && (nullifier == publicInputs[1]);
        }
        
        return false;
    }

    function _parseProof(bytes calldata proof) internal pure returns (Proof memory) {
        return Proof({
            a: [
                uint256(bytes32(proof[0:32])),
                uint256(bytes32(proof[32:64]))
            ],
            b: [
                [
                    uint256(bytes32(proof[64:96])),
                    uint256(bytes32(proof[96:128]))
                ],
                [
                    uint256(bytes32(proof[128:160])),
                    uint256(bytes32(proof[160:192]))
                ]
            ],
            c: [
                uint256(bytes32(proof[192:224])),
                uint256(bytes32(proof[224:256]))
            ]
        });
    }

    function _parsePublicInputs(bytes32[] calldata inputs) internal pure returns (uint256[] memory) {
        uint256[] memory result = new uint256[](inputs.length);
        for (uint256 i = 0; i < inputs.length; i++) {
            result[i] = uint256(inputs[i]) % SNARK_SCALAR_FIELD;
        }
        return result;
    }

    function _verifyGroth16Proof(
        Proof memory proof,
        uint256[] memory inputs
    ) internal view returns (bool) {
        uint256[2] memory vk_x = vk.ic[0];
        
        for (uint256 i = 0; i < inputs.length; i++) {
            (uint256 x, uint256 y) = _scalarMul(vk.ic[i + 1], inputs[i]);
            (vk_x[0], vk_x[1]) = _pointAdd(vk_x, [x, y]);
        }

        return _pairing(
            _negate(proof.a),
            proof.b,
            vk.alpha1,
            vk.beta2,
            vk_x,
            vk.gamma2,
            proof.c,
            vk.delta2
        );
    }

    function _negate(uint256[2] memory p) internal pure returns (uint256[2] memory) {
        if (p[0] == 0 && p[1] == 0) {
            return [uint256(0), uint256(0)];
        }
        return [p[0], PRIME_Q - (p[1] % PRIME_Q)];
    }

    function _pointAdd(
        uint256[2] memory p1,
        uint256[2] memory p2
    ) internal view returns (uint256, uint256) {
        uint256[4] memory input;
        input[0] = p1[0];
        input[1] = p1[1];
        input[2] = p2[0];
        input[3] = p2[1];

        bool success;
        uint256[2] memory result;

        assembly {
            success := staticcall(gas(), 6, input, 128, result, 64)
        }

        require(success, "Point addition failed");
        return (result[0], result[1]);
    }

    function _scalarMul(
        uint256[2] memory p,
        uint256 s
    ) internal view returns (uint256, uint256) {
        uint256[3] memory input;
        input[0] = p[0];
        input[1] = p[1];
        input[2] = s;

        bool success;
        uint256[2] memory result;

        assembly {
            success := staticcall(gas(), 7, input, 96, result, 64)
        }

        require(success, "Scalar multiplication failed");
        return (result[0], result[1]);
    }

    function _pairing(
        uint256[2] memory a1,
        uint256[2][2] memory a2,
        uint256[2] memory b1,
        uint256[2][2] memory b2,
        uint256[2] memory c1,
        uint256[2][2] memory c2,
        uint256[2] memory d1,
        uint256[2][2] memory d2
    ) internal view returns (bool) {
        uint256[24] memory input;
        
        input[0] = a1[0];
        input[1] = a1[1];
        input[2] = a2[0][1];
        input[3] = a2[0][0];
        input[4] = a2[1][1];
        input[5] = a2[1][0];
        
        input[6] = b1[0];
        input[7] = b1[1];
        input[8] = b2[0][1];
        input[9] = b2[0][0];
        input[10] = b2[1][1];
        input[11] = b2[1][0];
        
        input[12] = c1[0];
        input[13] = c1[1];
        input[14] = c2[0][1];
        input[15] = c2[0][0];
        input[16] = c2[1][1];
        input[17] = c2[1][0];
        
        input[18] = d1[0];
        input[19] = d1[1];
        input[20] = d2[0][1];
        input[21] = d2[0][0];
        input[22] = d2[1][1];
        input[23] = d2[1][0];

        uint256[1] memory out;
        bool success;

        assembly {
            success := staticcall(gas(), 8, input, 768, out, 32)
        }

        require(success, "Pairing check failed");
        return out[0] == 1;
    }

    function isProofVerified(bytes32 proofHash) external view returns (bool) {
        return verifiedProofs[proofHash];
    }
}
