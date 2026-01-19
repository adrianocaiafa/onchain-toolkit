// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title MultiSigV2
/// @notice Enhanced multi-signature system (N-of-M) with timelock, expiration, and improved security
/// @notice Allows actions to be proposed and executed only after N approvals from M signers
/// @notice Features: timelock delays, proposal expiration, delegatecall protection, and governance via proposals
contract MultiSigV2 {
    address[] public signers;
    mapping(address => bool) public isSigner;
    uint256 public threshold;
    
    uint256 public totalUniqueUsers;
    mapping(address => bool) public hasInteracted;
    mapping(address => uint256) public interactionsCount;

    uint256 public proposalCount;
    
    // Default timelock: 1 hour for normal proposals, 7 days for critical operations
    uint256 public constant DEFAULT_TIMELOCK = 1 hours;
    uint256 public constant CRITICAL_TIMELOCK = 7 days;
    uint256 public constant DEFAULT_EXPIRATION = 30 days;
    
    struct Proposal {
        uint256 id;
        address proposer;
        address target;
        uint256 value;
        bytes data;
        bool executed;
        uint256 approvalCount;
        uint256 timelock;        // Minimum delay before execution (in seconds)
        uint256 createdAt;       // Timestamp when proposal was created
        uint256 expiresAt;       // Timestamp when proposal expires
        mapping(address => bool) approvals;
    }
    
    mapping(uint256 => Proposal) public proposals;
    uint256[] public activeProposalIds;

    error NotSigner();
    error InvalidThreshold();
    error AlreadySigner();
    error NotASigner();
    error InvalidProposal();
    error AlreadyApproved();
    error NotApproved();
    error InsufficientApprovals();
    error AlreadyExecuted();
    error ExecutionFailed();
    error TimelockNotMet();
    error ProposalExpired();
    error NotProposer();
    error DelegatecallNotAllowed();

    modifier onlySigner() {
        if (!isSigner[msg.sender]) revert NotSigner();
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
    ) external onlySigner returns (uint256 proposalId) {
        require(_target != address(0), "Invalid target");
        
        proposalId = ++proposalCount;
        uint256 currentTime = block.timestamp;
        
        // Use default timelock if not specified
        uint256 timelock = _timelock == 0 ? DEFAULT_TIMELOCK : _timelock;
        // Use default expiration if not specified
        uint256 expiration = _expiration == 0 ? DEFAULT_EXPIRATION : _expiration;
        
        Proposal storage p = proposals[proposalId];
        p.id = proposalId;
        p.proposer = msg.sender;
        p.target = _target;
        p.value = _value;
        p.data = _data;
        p.executed = false;
        p.approvalCount = 1;
        p.timelock = timelock;
        p.createdAt = currentTime;
        p.expiresAt = currentTime + expiration;
        p.approvals[msg.sender] = true;
        
        activeProposalIds.push(proposalId);
        
        _registerInteraction(msg.sender);
        
        emit ProposalCreated(proposalId, msg.sender, _target, _value, timelock, p.expiresAt);
        emit ProposalApproved(proposalId, msg.sender, 1);
    }

    /// @notice Approves an existing proposal
    /// @param _proposalId ID of the proposal to approve
    function approve(uint256 _proposalId) external onlySigner {
        Proposal storage p = proposals[_proposalId];
        
        if (p.id == 0) revert InvalidProposal();
        if (p.executed) revert AlreadyExecuted();
        if (block.timestamp > p.expiresAt) revert ProposalExpired();
        if (p.approvals[msg.sender]) revert AlreadyApproved();
        
        p.approvals[msg.sender] = true;
        p.approvalCount += 1;
        
        _registerInteraction(msg.sender);
        
        emit ProposalApproved(_proposalId, msg.sender, p.approvalCount);
    }

    /// @notice Executes a proposal that has reached the approval threshold
    /// @dev Can be called by any address after reaching required approvals and timelock
    /// @param _proposalId ID of the proposal to execute
    function execute(uint256 _proposalId) external {
        Proposal storage p = proposals[_proposalId];
        
        if (p.id == 0) revert InvalidProposal();
        if (p.executed) revert AlreadyExecuted();
        if (block.timestamp > p.expiresAt) revert ProposalExpired();
        if (p.approvalCount < threshold) revert InsufficientApprovals();
        if (block.timestamp < p.createdAt + p.timelock) revert TimelockNotMet();
        
        p.executed = true;
        
        _removeFromActiveProposals(_proposalId);
        
        // Protection against delegatecall - block dangerous call patterns
        _validateCallSafety(p.data);
        
        // Convert stored bytes to calldata for execution
        bytes memory callData = p.data;
        (bool success, ) = p.target.call{value: p.value}(callData);
        if (!success) revert ExecutionFailed();
        
        _registerInteraction(msg.sender);
        
        emit ProposalExecuted(_proposalId, msg.sender);
    }

    /// @notice Cancels a proposal (only by the proposer)
    /// @param _proposalId ID of the proposal to cancel
    function cancel(uint256 _proposalId) external {
        Proposal storage p = proposals[_proposalId];
        
        if (p.id == 0) revert InvalidProposal();
        if (p.executed) revert AlreadyExecuted();
        if (msg.sender != p.proposer) revert NotProposer();
        
        p.executed = true;
        _removeFromActiveProposals(_proposalId);
        
        _registerInteraction(msg.sender);
        
        emit ProposalCancelled(_proposalId, msg.sender);
    }

    /// @notice Validates call data to prevent delegatecall and other dangerous operations
    /// @param _data The call data to validate
    function _validateCallSafety(bytes memory _data) internal pure {
        if (_data.length < 4) return; // Empty or too short, safe
        
        bytes4 selector = bytes4(_data);
        
        // Block delegatecall (0xb61d27f6) and callcode (0xa9059cbb is transfer, but we check for delegatecall)
        // Common delegatecall selectors:
        // - delegatecall: 0xb61d27f6 (delegatecall(address,bytes))
        // - callcode: 0x4f51f97b (deprecated but still dangerous)
        // - selfdestruct: 0x00f55d9d (selfdestruct(address))
        if (
            selector == 0xb61d27f6 || // delegatecall
            selector == 0x4f51f97b || // callcode (deprecated)
            selector == 0x00f55d9d    // selfdestruct
        ) {
            revert DelegatecallNotAllowed();
        }
        
        // Additional check: if data contains delegatecall opcode (0xf4) in first bytes
        // This catches attempts to use inline assembly or low-level calls
        for (uint256 i = 0; i < _data.length && i < 100; i++) {
            if (uint8(_data[i]) == 0xf4) { // DELEGATECALL opcode
                revert DelegatecallNotAllowed();
            }
        }
    }

    /// @notice Internal helper to create proposals with bytes memory data
    function _createProposal(
        address _target,
        uint256 _value,
        bytes memory _data,
        uint256 _timelock,
        uint256 _expiration
    ) internal returns (uint256) {
        // Convert bytes memory to calldata by creating a new proposal structure
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
        p.approvalCount = 1;
        p.timelock = timelock;
        p.createdAt = currentTime;
        p.expiresAt = currentTime + expiration;
        p.approvals[msg.sender] = true;
        
        activeProposalIds.push(proposalId);
        
        _registerInteraction(msg.sender);
        
        emit ProposalCreated(proposalId, msg.sender, _target, _value, timelock, p.expiresAt);
        emit ProposalApproved(proposalId, msg.sender, 1);
        
        return proposalId;
    }

    /// @notice Creates a proposal to add a new signer (governance via proposal)
    /// @param _signer Address of the new signer to add
    /// @return proposalId ID of the created proposal
    function proposeAddSigner(address _signer) external onlySigner returns (uint256 proposalId) {
        if (_signer == address(0)) revert NotASigner();
        if (isSigner[_signer]) revert AlreadySigner();
        
        // Encode the addSigner call
        bytes memory data = abi.encodeWithSignature("_executeAddSigner(address)", _signer);
        
        // Use critical timelock for administrative operations
        proposalId = _createProposal(address(this), 0, data, CRITICAL_TIMELOCK, DEFAULT_EXPIRATION);
    }

    /// @notice Creates a proposal to remove a signer (governance via proposal)
    /// @param _signer Address of the signer to remove
    /// @return proposalId ID of the created proposal
    function proposeRemoveSigner(address _signer) external onlySigner returns (uint256 proposalId) {
        if (!isSigner[_signer]) revert NotASigner();
        if (threshold > signers.length - 1) revert InvalidThreshold();
        
        // Encode the removeSigner call
        bytes memory data = abi.encodeWithSignature("_executeRemoveSigner(address)", _signer);
        
        // Use critical timelock for administrative operations
        proposalId = _createProposal(address(this), 0, data, CRITICAL_TIMELOCK, DEFAULT_EXPIRATION);
    }

    /// @notice Creates a proposal to change the threshold (governance via proposal)
    /// @param _newThreshold New threshold value
    /// @return proposalId ID of the created proposal
    function proposeSetThreshold(uint256 _newThreshold) external onlySigner returns (uint256 proposalId) {
        require(_newThreshold > 0 && _newThreshold <= signers.length, "Invalid threshold");
        
        // Encode the setThreshold call
        bytes memory data = abi.encodeWithSignature("_executeSetThreshold(uint256)", _newThreshold);
        
        // Use critical timelock for administrative operations
        proposalId = _createProposal(address(this), 0, data, CRITICAL_TIMELOCK, DEFAULT_EXPIRATION);
    }

    /// @notice Internal function to execute addSigner (called via proposal execution)
    /// @param _signer Address of the signer to add
    function _executeAddSigner(address _signer) external {
        require(msg.sender == address(this), "Only self-call allowed");
        if (_signer == address(0)) revert NotASigner();
        if (isSigner[_signer]) revert AlreadySigner();
        
        isSigner[_signer] = true;
        signers.push(_signer);
        
        emit SignerAdded(_signer, signers.length, threshold);
    }

    /// @notice Internal function to execute removeSigner (called via proposal execution)
    /// @param _signer Address of the signer to remove
    function _executeRemoveSigner(address _signer) external {
        require(msg.sender == address(this), "Only self-call allowed");
        if (!isSigner[_signer]) revert NotASigner();
        if (threshold > signers.length - 1) revert InvalidThreshold();
        
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

    /// @notice Internal function to execute setThreshold (called via proposal execution)
    /// @param _newThreshold New threshold value
    function _executeSetThreshold(uint256 _newThreshold) external {
        require(msg.sender == address(this), "Only self-call allowed");
        require(_newThreshold > 0 && _newThreshold <= signers.length, "Invalid threshold");
        
        uint256 oldThreshold = threshold;
        threshold = _newThreshold;
        
        emit ThresholdChanged(oldThreshold, _newThreshold);
    }

    /// @notice Returns detailed information about a proposal
    /// @param _proposalId ID of the proposal
    /// @return id ID of the proposal
    /// @return proposer Address of the proposer
    /// @return target Target address of the proposal
    /// @return value Value in wei of the proposal
    /// @return executed Whether it has been executed
    /// @return approvalCount Number of approvals
    /// @return timelock Timelock delay in seconds
    /// @return createdAt Timestamp when proposal was created
    /// @return expiresAt Timestamp when proposal expires
    /// @return executable Whether it can be executed now (checks approvals, timelock, expiration)
    function getProposal(uint256 _proposalId)
        external
        view
        returns (
            uint256 id,
            address proposer,
            address target,
            uint256 value,
            bool executed,
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
            p.approvalCount,
            p.timelock,
            p.createdAt,
            p.expiresAt,
            !p.executed && hasApprovals && timelockMet && notExpired
        );
    }

    /// @notice Checks if a signer has approved a specific proposal
    /// @param _proposalId ID of the proposal
    /// @param _signer Address of the signer
    /// @return true if approved, false otherwise
    function hasApproved(uint256 _proposalId, address _signer)
        external
        view
        returns (bool)
    {
        return proposals[_proposalId].approvals[_signer];
    }

    /// @notice Returns array with all active signers
    /// @return Array of signer addresses
    function getSigners() external view returns (address[] memory) {
        return signers;
    }

    /// @notice Returns IDs of all active (non-executed and non-expired) proposals
    /// @return Array with IDs of active proposals
    function getActiveProposals() external view returns (uint256[] memory) {
        uint256[] memory active = new uint256[](activeProposalIds.length);
        uint256 count = 0;
        uint256 currentTime = block.timestamp;
        
        for (uint256 i = 0; i < activeProposalIds.length; i++) {
            Proposal storage p = proposals[activeProposalIds[i]];
            if (!p.executed && currentTime <= p.expiresAt) {
                active[count] = activeProposalIds[i];
                count++;
            }
        }
        
        // Resize array to actual count
        uint256[] memory result = new uint256[](count);
        for (uint256 i = 0; i < count; i++) {
            result[i] = active[i];
        }
        
        return result;
    }

    /// @notice Returns the total number of signers
    /// @return Number of signers
    function getSignerCount() external view returns (uint256) {
        return signers.length;
    }

    /// @notice Returns how many times the caller has interacted with the contract
    /// @return Number of interactions
    function myInteractions() external view returns (uint256) {
        return interactionsCount[msg.sender];
    }

    /// @notice Checks if a proposal can be executed (all conditions met)
    /// @param _proposalId ID of the proposal
    /// @return true if proposal can be executed, false otherwise
    function canExecute(uint256 _proposalId) external view returns (bool) {
        Proposal storage p = proposals[_proposalId];
        if (p.id == 0 || p.executed) return false;
        
        uint256 currentTime = block.timestamp;
        return p.approvalCount >= threshold 
            && currentTime >= p.createdAt + p.timelock
            && currentTime <= p.expiresAt;
    }

    function _removeFromActiveProposals(uint256 _proposalId) internal {
        for (uint256 i = 0; i < activeProposalIds.length; i++) {
            if (activeProposalIds[i] == _proposalId) {
                activeProposalIds[i] = activeProposalIds[activeProposalIds.length - 1];
                activeProposalIds.pop();
                break;
            }
        }
    }

    receive() external payable {}
}
