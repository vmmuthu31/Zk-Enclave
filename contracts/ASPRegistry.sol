// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

contract ASPRegistry {
    struct Provider {
        address addr;
        string name;
        bytes32 currentRoot;
        uint256 lastUpdate;
        uint256 reputationScore;
        bool active;
    }

    mapping(address => Provider) public providers;
    mapping(bytes32 => bool) public knownRoots;
    address[] public providerList;

    address public owner;
    uint256 public constant MIN_REPUTATION = 100;
    uint256 public constant ROOT_HISTORY_SIZE = 30;

    mapping(address => bytes32[ROOT_HISTORY_SIZE]) public rootHistory;
    mapping(address => uint256) public rootHistoryIndex;

    event ProviderRegistered(address indexed provider, string name);
    event ProviderDeactivated(address indexed provider);
    event ProviderReactivated(address indexed provider);
    event RootUpdated(address indexed provider, bytes32 oldRoot, bytes32 newRoot);
    event ReputationUpdated(address indexed provider, uint256 oldScore, uint256 newScore);

    error NotAuthorized();
    error ProviderNotFound();
    error ProviderNotActive();
    error AlreadyRegistered();
    error InvalidRoot();
    error InsufficientReputation();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotAuthorized();
        _;
    }

    modifier onlyProvider() {
        if (!providers[msg.sender].active) revert ProviderNotActive();
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function registerProvider(
        address provider,
        string calldata name,
        bytes32 initialRoot
    ) external onlyOwner {
        if (providers[provider].addr != address(0)) revert AlreadyRegistered();

        providers[provider] = Provider({
            addr: provider,
            name: name,
            currentRoot: initialRoot,
            lastUpdate: block.timestamp,
            reputationScore: 1000,
            active: true
        });

        providerList.push(provider);
        knownRoots[initialRoot] = true;

        emit ProviderRegistered(provider, name);
    }

    function updateRoot(bytes32 newRoot) external onlyProvider {
        if (newRoot == bytes32(0)) revert InvalidRoot();

        Provider storage provider = providers[msg.sender];
        bytes32 oldRoot = provider.currentRoot;

        uint256 idx = rootHistoryIndex[msg.sender];
        rootHistory[msg.sender][idx] = oldRoot;
        rootHistoryIndex[msg.sender] = (idx + 1) % ROOT_HISTORY_SIZE;

        provider.currentRoot = newRoot;
        provider.lastUpdate = block.timestamp;
        knownRoots[newRoot] = true;

        emit RootUpdated(msg.sender, oldRoot, newRoot);
    }

    function deactivateProvider(address provider) external onlyOwner {
        if (providers[provider].addr == address(0)) revert ProviderNotFound();
        
        providers[provider].active = false;
        emit ProviderDeactivated(provider);
    }

    function reactivateProvider(address provider) external onlyOwner {
        if (providers[provider].addr == address(0)) revert ProviderNotFound();
        
        providers[provider].active = true;
        emit ProviderReactivated(provider);
    }

    function updateReputation(address provider, uint256 newScore) external onlyOwner {
        if (providers[provider].addr == address(0)) revert ProviderNotFound();
        
        uint256 oldScore = providers[provider].reputationScore;
        providers[provider].reputationScore = newScore;
        
        emit ReputationUpdated(provider, oldScore, newScore);
    }

    function isRegistered(address provider) external view returns (bool) {
        return providers[provider].addr != address(0) && providers[provider].active;
    }

    function getProviderRoot(address provider) external view returns (bytes32) {
        if (!providers[provider].active) revert ProviderNotActive();
        return providers[provider].currentRoot;
    }

    function getProviderInfo(address provider) external view returns (Provider memory) {
        return providers[provider];
    }

    function isKnownRoot(bytes32 root) external view returns (bool) {
        return knownRoots[root];
    }

    function isHistoricalRoot(address provider, bytes32 root) external view returns (bool) {
        if (providers[provider].currentRoot == root) return true;
        
        for (uint256 i = 0; i < ROOT_HISTORY_SIZE; i++) {
            if (rootHistory[provider][i] == root) return true;
        }
        return false;
    }

    function getProviderCount() external view returns (uint256) {
        return providerList.length;
    }

    function getActiveProviders() external view returns (address[] memory) {
        uint256 activeCount = 0;
        for (uint256 i = 0; i < providerList.length; i++) {
            if (providers[providerList[i]].active) {
                activeCount++;
            }
        }

        address[] memory active = new address[](activeCount);
        uint256 idx = 0;
        for (uint256 i = 0; i < providerList.length; i++) {
            if (providers[providerList[i]].active) {
                active[idx++] = providerList[i];
            }
        }

        return active;
    }

    function getHighReputationProviders(uint256 minScore) external view returns (address[] memory) {
        uint256 count = 0;
        for (uint256 i = 0; i < providerList.length; i++) {
            if (providers[providerList[i]].active && 
                providers[providerList[i]].reputationScore >= minScore) {
                count++;
            }
        }

        address[] memory result = new address[](count);
        uint256 idx = 0;
        for (uint256 i = 0; i < providerList.length; i++) {
            if (providers[providerList[i]].active && 
                providers[providerList[i]].reputationScore >= minScore) {
                result[idx++] = providerList[i];
            }
        }

        return result;
    }
}
