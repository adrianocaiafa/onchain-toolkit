// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/// @title MultiSigV2_1
/// @notice Enhanced multi-signature wallet with security improvements
/// @notice v2.1 includes: DoS protection, reentrancy fixes, pausability, and improved validations
contract MultiSigV2_1 is Pausable {
    using EnumerableSet for EnumerableSet.UintSet;

    address[] public signers;
    mapping(address => bool) public isSigner;
    uint256 public threshold;
    
    uint256 public totalUniqueUsers;
    mapping(address => bool) public hasInteracted;
    mapping(address => uint256) public interactionsCount;
    mapping(address => uint256) public signerNonce;

    uint256 public proposalCount;
    
    // Timelock constraints
    uint256 public constant DEFAULT_TIMELOCK = 1 hours;
    uint256 public constant CRITICAL_TIMELOCK = 7 days;
    uint256 public constant DEFAULT_EXPIRATION = 30 days;
    uint256 public constant MIN_CUSTOM_TIMELOCK = 1 hours;
    uint256 public constant MAX_CUSTOM_TIMELOCK = 90 days;
    uint256 public constant MIN_CUSTOM_EXPIRATION = 1 days;
    uint256 public constant MAX_CUSTOM_EXPIRATION = 365 days;
    
    struct Proposal {
        uint256 id;
        address proposer;
        address target;
        uint256 value;
        bytes data;
        bool executed;
        bool cancelled;
        uint256 approvalCount;
        uint256 timelock;
        uint256 createdAt;
        uint256 expiresAt;
        mapping(address => bool) approvals;
    }
    
    mapping(uint256 => Proposal) public proposals;
    EnumerableSet.UintSet private activeProposalIds;

    error NotSigner();
    error InvalidThreshold();
    error AlreadySigner();
    error NotASigner();
    error InvalidProposal();
    error AlreadyApproved();
    error InsufficientApprovals();
    error AlreadyExecuted();
    error ProposalAlreadyCancelled();
    error ExecutionFailed();
    error TimelockNotMet();
    error ProposalExpired();
    error NotProposer();
    error DelegatecallNotAllowed();
    error InsufficientBalance();
    error TimelockOutOfBounds();
    error ExpirationOutOfBounds();
    error InvalidNonce();

    modifier onlySigner() {
        if (!isSigner[msg.sender]) revert NotSigner();
        _;
    }

    modifier onlySelf() {
        require(msg.sender == address(this), "Only self-call allowed");
        _;
    }

    constructor(address[] memory _signers, uint256 _threshold) {
        require(_signers.length > 0, "Must have at least one signer");
        require(_threshold > 0 && _threshold <= _signers.length, "Invalid threshold");
        
        threshold = _threshold;
        
        for (uint256 i = 0; i < _signers.length; i++) {
            require(_signers[i] != address(0), "Invalid signer address");
            require(!isSigner[_signers[i]], "Duplicate signer");
            
            isSigner[_signers[i]] = true;
            signers.push(_signers[i]);
        }
        
        _registerInteraction(msg.sender);
    }

    function _registerInteraction(address _user) internal {
        if (!hasInteracted[_user]) {
            hasInteracted[_user] = true;
            totalUniqueUsers += 1;
        }
        interactionsCount[_user] += 1;
    }

    event SignerAdded(address indexed signer, uint256 newSignerCount, uint256 threshold);
    event SignerRemoved(address indexed signer, uint256 newSignerCount, uint256 threshold);
    event ThresholdChanged(uint256 oldThreshold, uint256 newThreshold);
    event ProposalCreated(
        uint256 indexed proposalId,
        address indexed proposer,
        address target,
        uint256 value,
        uint256 timelock,
        uint256 expiresAt
    );
    event ProposalApproved(uint256 indexed proposalId, address indexed approver, uint256 approvalCount);
    event ProposalExecuted(uint256 indexed proposalId, address indexed executor);
    event ProposalCancelled(uint256 indexed proposalId, address indexed canceller);

    /// @notice Creates a new action proposal
    /// @param _target Address of the contract/target that will receive the call
    /// @param _value Value in wei to send (0 for calls without value)
    /// @param _data Call data (can be empty for simple transfers)
    /// @param _timelock Custom timelock in seconds (0 to use default)
    /// @param _expiration Custom expiration in seconds from now (0 to use default)
    /// @return proposalId ID of the created proposal
    function propose(
        address _target,
        uint256 _value,
        bytes calldata _data,
        uint256 _timelock,
        uint256 _expiration
    ) external onlySigner whenNotPaused returns (uint256 proposalId) {
        require(_target != address(0), "Invalid target");
        if (_value > address(this).balance) revert InsufficientBalance();
        
        // Validate custom timelock
        if (_timelock != 0) {
            if (_timelock < MIN_CUSTOM_TIMELOCK || _timelock > MAX_CUSTOM_TIMELOCK) {
                revert TimelockOutOfBounds();
            }
        }
        
        // Validate custom expiration
        if (_expiration != 0) {
            if (_expiration < MIN_CUSTOM_EXPIRATION || _expiration > MAX_CUSTOM_EXPIRATION) {
                revert ExpirationOutOfBounds();
            }
        }
        
        return _createProposal(_target, _value, _data, _timelock, _expiration);
    }

    /// @notice Internal helper to create proposals
    function _createProposal(
        address _target,
        uint256 _value,
        bytes memory _data,
        uint256 _timelock,
        uint256 _expiration
    ) internal returns (uint256) {
        proposalCount++;
        uint256 proposalId = proposalCount;
        uint256 currentTime = block.timestamp;
        
        uint256 timelock = _timelock == 0 ? DEFAULT_TIMELOCK : _timelock;
        uint256 expiration = _expiration == 0 ? DEFAULT_EXPIRATION : _expiration;
        
        Proposal storage p = proposals[proposalId];
        p.id = proposalId;
        p.proposer = msg.sender;
        p.target = _target;
        p.value = _value;
        p.data = _data;
        p.executed = false;
        p.cancelled = false;
        p.approvalCount = 1;
        p.timelock = timelock;
        p.createdAt = currentTime;
        p.expiresAt = currentTime + expiration;
        p.approvals[msg.sender] = true;
        
        activeProposalIds.add(proposalId);
        
        _registerInteraction(msg.sender);
        
        emit ProposalCreated(proposalId, msg.sender, _target, _value, timelock, p.expiresAt);
        emit ProposalApproved(proposalId, msg.sender, 1);
        
        return proposalId;
    }

    /// @notice Approves an existing proposal with nonce protection
    /// @param _proposalId ID of the proposal to approve
    /// @param _expectedNonce Expected nonce for front-running protection
    function approve(uint256 _proposalId, uint256 _expectedNonce) external onlySigner whenNotPaused {
        if (signerNonce[msg.sender] != _expectedNonce) revert InvalidNonce();
        signerNonce[msg.sender]++;
        
        Proposal storage p = proposals[_proposalId];
        
        if (p.id == 0) revert InvalidProposal();
        if (p.executed) revert AlreadyExecuted();
        if (p.cancelled) revert ProposalAlreadyCancelled();
        if (block.timestamp > p.expiresAt) revert ProposalExpired();
        if (p.approvals[msg.sender]) revert AlreadyApproved();
        
        p.approvals[msg.sender] = true;
        p.approvalCount += 1;
        
        _registerInteraction(msg.sender);
        
        emit ProposalApproved(_proposalId, msg.sender, p.approvalCount);
    }

    /// @notice Executes a proposal that has reached the approval threshold
    /// @param _proposalId ID of the proposal to execute
    function execute(uint256 _proposalId) external whenNotPaused {
        Proposal storage p = proposals[_proposalId];
        
        if (p.id == 0) revert InvalidProposal();
        if (p.executed) revert AlreadyExecuted();
        if (p.cancelled) revert ProposalAlreadyCancelled();
        if (block.timestamp > p.expiresAt) revert ProposalExpired();
        if (p.approvalCount < threshold) revert InsufficientApprovals();
        if (block.timestamp < p.createdAt + p.timelock) revert TimelockNotMet();
        
        // Mark as executed and remove from active proposals BEFORE external call
        p.executed = true;
        activeProposalIds.remove(_proposalId);
        
        // Validate call safety
        _validateCallSafety(p.data);
        
        // Register interaction BEFORE external call (reentrancy protection)
        _registerInteraction(msg.sender);
        
        // Execute external call
        bytes memory callData = p.data;
        (bool success, ) = p.target.call{value: p.value}(callData);
        if (!success) revert ExecutionFailed();
        
        emit ProposalExecuted(_proposalId, msg.sender);
    }

    /// @notice Cancels a proposal (only by the proposer)
    /// @param _proposalId ID of the proposal to cancel
    function cancel(uint256 _proposalId) external {
        Proposal storage p = proposals[_proposalId];
        
        if (p.id == 0) revert InvalidProposal();
        if (p.executed) revert AlreadyExecuted();
        if (p.cancelled) revert ProposalAlreadyCancelled();
        if (msg.sender != p.proposer) revert NotProposer();
        
        p.cancelled = true;
        activeProposalIds.remove(_proposalId);
        
        _registerInteraction(msg.sender);
        
        emit ProposalCancelled(_proposalId, msg.sender);
    }

    /// @notice Validates call data to prevent delegatecall and other dangerous operations
    /// @param _data The call data to validate
    function _validateCallSafety(bytes memory _data) internal pure {
        if (_data.length < 4) return;
        
        bytes4 selector = bytes4(_data);
        
        // Block known dangerous selectors
        // delegatecall(address,bytes) selector: 0xb61d27f6
        // callcode is deprecated but we check for it
        // selfdestruct(address) selector: 0x00f55d9d
        if (
            selector == 0xb61d27f6 || // delegatecall(address,bytes)
            selector == 0x4f51f97b || // callcode (deprecated)
            selector == 0x00f55d9d    // selfdestruct(address)
        ) {
            revert DelegatecallNotAllowed();
        }
        
        // Scan entire data for DELEGATECALL opcode (0xf4)
        for (uint256 i = 0; i < _data.length; i++) {
            if (uint8(_data[i]) == 0xf4) {
                revert DelegatecallNotAllowed();
            }
        }
    }

    /// @notice Creates a proposal to add a new signer
    /// @param _signer Address of the new signer to add
    /// @return proposalId ID of the created proposal
    function proposeAddSigner(address _signer) external onlySigner whenNotPaused returns (uint256 proposalId) {
        if (_signer == address(0)) revert NotASigner();
        if (isSigner[_signer]) revert AlreadySigner();
        
        bytes memory data = abi.encodeWithSignature("_executeAddSigner(address)", _signer);
        proposalId = _createProposal(address(this), 0, data, CRITICAL_TIMELOCK, DEFAULT_EXPIRATION);
    }

    /// @notice Creates a proposal to remove a signer
    /// @param _signer Address of the signer to remove
    /// @return proposalId ID of the created proposal
    function proposeRemoveSigner(address _signer) external onlySigner whenNotPaused returns (uint256 proposalId) {
        if (!isSigner[_signer]) revert NotASigner();
        if (threshold >= signers.length) revert InvalidThreshold();
        
        bytes memory data = abi.encodeWithSignature("_executeRemoveSigner(address)", _signer);
        proposalId = _createProposal(address(this), 0, data, CRITICAL_TIMELOCK, DEFAULT_EXPIRATION);
    }

    /// @notice Creates a proposal to change the threshold
    /// @param _newThreshold New threshold value
    /// @return proposalId ID of the created proposal
    function proposeSetThreshold(uint256 _newThreshold) external onlySigner whenNotPaused returns (uint256 proposalId) {
        require(_newThreshold > 0 && _newThreshold <= signers.length, "Invalid threshold");
        
        bytes memory data = abi.encodeWithSignature("_executeSetThreshold(uint256)", _newThreshold);
        proposalId = _createProposal(address(this), 0, data, CRITICAL_TIMELOCK, DEFAULT_EXPIRATION);
    }

    /// @notice Creates a proposal to pause the contract
    /// @return proposalId ID of the created proposal
    function proposePause() external onlySigner whenNotPaused returns (uint256 proposalId) {
        bytes memory data = abi.encodeWithSignature("_executePause()");
        proposalId = _createProposal(address(this), 0, data, CRITICAL_TIMELOCK, DEFAULT_EXPIRATION);
    }

    /// @notice Creates a proposal to unpause the contract
    /// @return proposalId ID of the created proposal
    function proposeUnpause() external onlySigner returns (uint256 proposalId) {
        bytes memory data = abi.encodeWithSignature("_executeUnpause()");
        proposalId = _createProposal(address(this), 0, data, CRITICAL_TIMELOCK, DEFAULT_EXPIRATION);
    }

    /// @notice Internal function to execute addSigner
    function _executeAddSigner(address _signer) external onlySelf {
        if (_signer == address(0)) revert NotASigner();
        if (isSigner[_signer]) revert AlreadySigner();
        
        isSigner[_signer] = true;
        signers.push(_signer);
        
        emit SignerAdded(_signer, signers.length, threshold);
    }

    /// @notice Internal function to execute removeSigner
    function _executeRemoveSigner(address _signer) external onlySelf {
        if (!isSigner[_signer]) revert NotASigner();
        if (threshold >= signers.length) revert InvalidThreshold();
        
        isSigner[_signer] = false;
        
        for (uint256 i = 0; i < signers.length; i++) {
            if (signers[i] == _signer) {
                signers[i] = signers[signers.length - 1];
                signers.pop();
                break;
            }
        }
        
        emit SignerRemoved(_signer, signers.length, threshold);
    }

    /// @notice Internal function to execute setThreshold
    function _executeSetThreshold(uint256 _newThreshold) external onlySelf {
        require(_newThreshold > 0 && _newThreshold <= signers.length, "Invalid threshold");
        
        uint256 oldThreshold = threshold;
        threshold = _newThreshold;
        
        emit ThresholdChanged(oldThreshold, _newThreshold);
    }

    /// @notice Internal function to pause the contract
    function _executePause() external onlySelf {
        _pause();
    }

    /// @notice Internal function to unpause the contract
    function _executeUnpause() external onlySelf {
        _unpause();
    }

    /// @notice Returns detailed information about a proposal
    function getProposal(uint256 _proposalId)
        external
        view
        returns (
            uint256 id,
            address proposer,
            address target,
            uint256 value,
            bool executed,
            bool cancelled,
            uint256 approvalCount,
            uint256 timelock,
            uint256 createdAt,
            uint256 expiresAt,
            bool executable
        )
    {
        Proposal storage p = proposals[_proposalId];
        uint256 currentTime = block.timestamp;
        bool timelockMet = currentTime >= p.createdAt + p.timelock;
        bool notExpired = currentTime <= p.expiresAt;
        bool hasApprovals = p.approvalCount >= threshold;
        
        return (
            p.id,
            p.proposer,
            p.target,
            p.value,
            p.executed,
            p.cancelled,
            p.approvalCount,
            p.timelock,
            p.createdAt,
            p.expiresAt,
            !p.executed && !p.cancelled && hasApprovals && timelockMet && notExpired
        );
    }

    /// @notice Checks if a signer has approved a specific proposal
    function hasApproved(uint256 _proposalId, address _signer) external view returns (bool) {
        return proposals[_proposalId].approvals[_signer];
    }

    /// @notice Returns array with all active signers
    function getSigners() external view returns (address[] memory) {
        return signers;
    }

    /// @notice Returns IDs of all active (non-executed, non-cancelled, non-expired) proposals
    function getActiveProposals() external view returns (uint256[] memory) {
        uint256 length = activeProposalIds.length();
        uint256[] memory active = new uint256[](length);
        uint256 count = 0;
        uint256 currentTime = block.timestamp;
        
        for (uint256 i = 0; i < length; i++) {
            uint256 proposalId = activeProposalIds.at(i);
            Proposal storage p = proposals[proposalId];
            if (!p.executed && !p.cancelled && currentTime <= p.expiresAt) {
                active[count] = proposalId;
                count++;
            }
        }
        
        uint256[] memory result = new uint256[](count);
        for (uint256 i = 0; i < count; i++) {
            result[i] = active[i];
        }
        
        return result;
    }

    /// @notice Returns the total number of signers
    function getSignerCount() external view returns (uint256) {
        return signers.length;
    }

    /// @notice Returns how many times the caller has interacted with the contract
    function myInteractions() external view returns (uint256) {
        return interactionsCount[msg.sender];
    }

    /// @notice Checks if a proposal can be executed
    function canExecute(uint256 _proposalId) external view returns (bool) {
        Proposal storage p = proposals[_proposalId];
        if (p.id == 0 || p.executed || p.cancelled) return false;
        
        uint256 currentTime = block.timestamp;
        return p.approvalCount >= threshold 
            && currentTime >= p.createdAt + p.timelock
            && currentTime <= p.expiresAt;
    }

    receive() external payable {}
}
