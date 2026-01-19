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
        
        // Protection against delegatecall - check if data starts with delegatecall selector
        // delegatecall selector: 0xb61d27f6 or 0x4f51f97b (common patterns)
        if (p.data.length >= 4) {
            bytes4 selector = bytes4(p.data);
            // Block known delegatecall patterns
            if (selector == 0xb61d27f6 || selector == 0x4f51f97b) {
                revert DelegatecallNotAllowed();
            }
        }
        
        (bool success, ) = p.target.call{value: p.value}(p.data);
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
