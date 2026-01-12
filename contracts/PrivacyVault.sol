// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./libraries/MerkleTree.sol";
import "./libraries/PoseidonT3.sol";
import "./ZKVerifier.sol";
import "./ASPRegistry.sol";

contract PrivacyVault {
    using MerkleTreeLib for MerkleTreeLib.MerkleTree;

    uint256 public constant MERKLE_TREE_DEPTH = 20;
    uint256 public constant MAX_DEPOSIT_AMOUNT = 100 ether;
    uint256 public constant MIN_DEPOSIT_AMOUNT = 0.01 ether;

    struct DepositData {
        bytes32 commitment;
        uint256 amount;
        uint256 timestamp;
        uint256 leafIndex;
    }

    MerkleTreeLib.MerkleTree private commitmentTree;
    ZKVerifier public immutable zkVerifier;
    ASPRegistry public immutable aspRegistry;

    mapping(bytes32 => bool) public nullifierHashes;
    mapping(bytes32 => DepositData) public deposits;
    mapping(address => bytes32[]) public userDeposits;

    uint256 public totalDeposits;
    uint256 public totalWithdrawals;
    bool public paused;
    address public owner;
    address public teeOperator;

    event Deposit(
        bytes32 indexed commitment,
        uint256 leafIndex,
        uint256 amount,
        uint256 timestamp
    );

    event Withdrawal(
        bytes32 indexed nullifierHash,
        address indexed recipient,
        uint256 amount,
        bytes32 merkleRoot
    );

    event TEEOperatorUpdated(address indexed oldOperator, address indexed newOperator);
    event EmergencyPaused(address indexed by);
    event EmergencyUnpaused(address indexed by);

    error InvalidAmount();
    error InvalidCommitment();
    error InvalidProof();
    error NullifierAlreadyUsed();
    error InvalidMerkleRoot();
    error InvalidRecipient();
    error ContractPaused();
    error NotAuthorized();
    error TransferFailed();
    error InvalidASPProof();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotAuthorized();
        _;
    }

    modifier onlyTEEOperator() {
        if (msg.sender != teeOperator && msg.sender != owner) revert NotAuthorized();
        _;
    }

    modifier whenNotPaused() {
        if (paused) revert ContractPaused();
        _;
    }

    constructor(address _zkVerifier, address _aspRegistry) {
        owner = msg.sender;
        teeOperator = msg.sender;
        zkVerifier = ZKVerifier(_zkVerifier);
        aspRegistry = ASPRegistry(_aspRegistry);
        commitmentTree.initialize(MERKLE_TREE_DEPTH);
    }

    function deposit(bytes32 commitment) external payable whenNotPaused {
        if (msg.value < MIN_DEPOSIT_AMOUNT || msg.value > MAX_DEPOSIT_AMOUNT) {
            revert InvalidAmount();
        }
        if (commitment == bytes32(0)) {
            revert InvalidCommitment();
        }
        if (deposits[commitment].timestamp != 0) {
            revert InvalidCommitment();
        }

        uint256 leafIndex = commitmentTree.insert(commitment);

        deposits[commitment] = DepositData({
            commitment: commitment,
            amount: msg.value,
            timestamp: block.timestamp,
            leafIndex: leafIndex
        });

        userDeposits[msg.sender].push(commitment);
        totalDeposits += msg.value;

        emit Deposit(commitment, leafIndex, msg.value, block.timestamp);
    }

    function withdraw(
        bytes32 nullifierHash,
        bytes32 root,
        address payable recipient,
        uint256 amount,
        bytes calldata zkProof,
        bytes calldata teeAttestation
    ) external whenNotPaused {
        if (recipient == address(0)) revert InvalidRecipient();
        if (nullifierHashes[nullifierHash]) revert NullifierAlreadyUsed();
        if (!isKnownRoot(root)) revert InvalidMerkleRoot();

        bytes32[] memory publicInputs = new bytes32[](4);
        publicInputs[0] = root;
        publicInputs[1] = nullifierHash;
        publicInputs[2] = bytes32(uint256(uint160(recipient)));
        publicInputs[3] = bytes32(amount);

        if (!zkVerifier.verifyProof(zkProof, publicInputs)) {
            revert InvalidProof();
        }

        if (teeAttestation.length > 0) {
            _verifyTEEAttestation(teeAttestation, nullifierHash, root);
        }

        nullifierHashes[nullifierHash] = true;
        totalWithdrawals += amount;

        (bool success, ) = recipient.call{value: amount}("");
        if (!success) revert TransferFailed();

        emit Withdrawal(nullifierHash, recipient, amount, root);
    }

    function withdrawWithCompliance(
        bytes32 nullifierHash,
        bytes32 root,
        address payable recipient,
        uint256 amount,
        bytes calldata zkProof,
        bytes calldata associationProof,
        address aspProvider
    ) external whenNotPaused {
        if (recipient == address(0)) revert InvalidRecipient();
        if (nullifierHashes[nullifierHash]) revert NullifierAlreadyUsed();
        if (!isKnownRoot(root)) revert InvalidMerkleRoot();

        if (!aspRegistry.isRegistered(aspProvider)) {
            revert InvalidASPProof();
        }
        
        bytes32 aspRoot = aspRegistry.getProviderRoot(aspProvider);
        if (!_verifyAssociationProof(associationProof, root, aspRoot)) {
            revert InvalidASPProof();
        }

        bytes32[] memory publicInputs = new bytes32[](4);
        publicInputs[0] = root;
        publicInputs[1] = nullifierHash;
        publicInputs[2] = bytes32(uint256(uint160(recipient)));
        publicInputs[3] = bytes32(amount);

        if (!zkVerifier.verifyProof(zkProof, publicInputs)) {
            revert InvalidProof();
        }

        nullifierHashes[nullifierHash] = true;
        totalWithdrawals += amount;

        (bool success, ) = recipient.call{value: amount}("");
        if (!success) revert TransferFailed();

        emit Withdrawal(nullifierHash, recipient, amount, root);
    }

    function isKnownRoot(bytes32 root) public view returns (bool) {
        return commitmentTree.isKnownRoot(root);
    }

    function getLatestRoot() external view returns (bytes32) {
        return commitmentTree.getLastRoot();
    }

    function getNextLeafIndex() external view returns (uint256) {
        return commitmentTree.nextIndex;
    }

    function isNullifierUsed(bytes32 nullifier) external view returns (bool) {
        return nullifierHashes[nullifier];
    }

    function getUserDeposits(address user) external view returns (bytes32[] memory) {
        return userDeposits[user];
    }

    function getDepositInfo(bytes32 commitment) external view returns (DepositData memory) {
        return deposits[commitment];
    }

    function setTEEOperator(address newOperator) external onlyOwner {
        address oldOperator = teeOperator;
        teeOperator = newOperator;
        emit TEEOperatorUpdated(oldOperator, newOperator);
    }

    function pause() external onlyOwner {
        paused = true;
        emit EmergencyPaused(msg.sender);
    }

    function unpause() external onlyOwner {
        paused = false;
        emit EmergencyUnpaused(msg.sender);
    }

    function _verifyTEEAttestation(
        bytes calldata attestation,
        bytes32 nullifierHash,
        bytes32 root
    ) internal view {
        if (attestation.length < 64) return;
        
        bytes32 dataHash = keccak256(abi.encodePacked(nullifierHash, root));
        bytes32 attestedHash = bytes32(attestation[0:32]);
        
        require(dataHash == attestedHash || attestation.length >= 32, "Invalid TEE attestation");
    }

    function _verifyAssociationProof(
        bytes calldata proof,
        bytes32 depositRoot,
        bytes32 associationRoot
    ) internal pure returns (bool) {
        if (proof.length < 64) return false;
        
        bytes32 proofDepositRoot = bytes32(proof[0:32]);
        bytes32 proofAssocRoot = bytes32(proof[32:64]);
        
        return proofDepositRoot == depositRoot && proofAssocRoot == associationRoot;
    }

    receive() external payable {
        revert("Use deposit function");
    }
}
