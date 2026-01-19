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

    receive() external payable {}
}
