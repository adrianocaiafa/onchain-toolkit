// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {MultiSigV2_1} from "./MultiSig.sol";
import {Test} from "forge-std/Test.sol";

contract MultiSigV2_1Test is Test {
    MultiSigV2_1 multisig;
    
    address deployer;
    address signer1 = address(0x2);
    address signer2 = address(0x3);
    address signer3 = address(0x4);
    address nonSigner = address(0x5);
    address targetAddr = address(0x6);
    
    address[] signers;
    uint256 threshold = 2;

    function setUp() public {
        deployer = address(this);
        
        signers = new address[](3);
        signers[0] = signer1;
        signers[1] = signer2;
        signers[2] = signer3;
        
        multisig = new MultiSigV2_1(signers, threshold);
    }

    // ============ Constructor Tests ============

    function test_Constructor_SetsInitialState() public view {
        require(multisig.threshold() == threshold, "Threshold should be set correctly");
        require(multisig.getSignerCount() == 3, "Should have 3 signers");
        require(multisig.isSigner(signer1), "Signer1 should be a signer");
        require(multisig.isSigner(signer2), "Signer2 should be a signer");
        require(multisig.isSigner(signer3), "Signer3 should be a signer");
    }

    function test_Constructor_RevertsWithZeroSigners() public {
        address[] memory emptySigners = new address[](0);
        vm.expectRevert("Must have at least one signer");
        new MultiSigV2_1(emptySigners, 1);
    }

    function test_Constructor_RevertsWithInvalidThreshold() public {
        vm.expectRevert("Invalid threshold");
        new MultiSigV2_1(signers, 0);
        
        vm.expectRevert("Invalid threshold");
        new MultiSigV2_1(signers, 4);
    }

    // ============ Propose Tests ============

    function test_Propose_CreatesProposal() public {
        vm.prank(signer1);
        uint256 proposalId = multisig.propose(targetAddr, 0, "", 0, 0);
        
        require(proposalId == 1, "Should return proposal ID 1");
        
        (
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
        ) = multisig.getProposal(proposalId);
        
        require(id == 1, "ID should be 1");
        require(proposer == signer1, "Proposer should be signer1");
        require(target == targetAddr, "Target should match");
        require(value == 0, "Value should be 0");
        require(executed == false, "Should not be executed");
        require(cancelled == false, "Should not be cancelled");
        require(approvalCount == 1, "Should have 1 approval");
        require(timelock == multisig.DEFAULT_TIMELOCK(), "Should use default timelock");
        require(createdAt > 0, "Should have creation timestamp");
        require(expiresAt > createdAt, "Should have expiration timestamp");
        require(executable == false, "Should not be executable yet (timelock)");
    }

    function test_Propose_RevertsWhenNotSigner() public {
        vm.prank(nonSigner);
        vm.expectRevert(MultiSigV2_1.NotSigner.selector);
        multisig.propose(targetAddr, 0, "", 0, 0);
    }

    function test_Propose_RevertsWithInsufficientBalance() public {
        vm.deal(address(multisig), 1 ether);
        
        vm.prank(signer1);
        vm.expectRevert(MultiSigV2_1.InsufficientBalance.selector);
        multisig.propose(targetAddr, 2 ether, "", 0, 0);
    }

    function test_Propose_RevertsWithInvalidTimelock() public {
        vm.prank(signer1);
        vm.expectRevert(MultiSigV2_1.TimelockOutOfBounds.selector);
        multisig.propose(targetAddr, 0, "", 30 minutes, 0); // Below minimum
        
        vm.prank(signer1);
        vm.expectRevert(MultiSigV2_1.TimelockOutOfBounds.selector);
        multisig.propose(targetAddr, 0, "", 100 days, 0); // Above maximum
    }

    function test_Propose_RevertsWithInvalidExpiration() public {
        vm.prank(signer1);
        vm.expectRevert(MultiSigV2_1.ExpirationOutOfBounds.selector);
        multisig.propose(targetAddr, 0, "", 0, 12 hours); // Below minimum
        
        vm.prank(signer1);
        vm.expectRevert(MultiSigV2_1.ExpirationOutOfBounds.selector);
        multisig.propose(targetAddr, 0, "", 0, 400 days); // Above maximum
    }

    function test_Propose_RevertsWhenPaused() public {
        // First pause the contract via proposal
        vm.prank(signer1);
        uint256 pauseProposal = multisig.proposePause();
        
        vm.prank(signer2);
        multisig.approve(pauseProposal, 0);
        
        vm.warp(block.timestamp + multisig.CRITICAL_TIMELOCK() + 1);
        
        vm.prank(signer1);
        multisig.execute(pauseProposal);
        
        // Now try to propose
        vm.prank(signer1);
        vm.expectRevert();
        multisig.propose(targetAddr, 0, "", 0, 0);
    }

    // ============ Approve Tests ============

    function test_Approve_IncreasesApprovalCount() public {
        vm.prank(signer1);
        uint256 proposalId = multisig.propose(targetAddr, 0, "", 0, 0);
        
        vm.prank(signer2);
        multisig.approve(proposalId, 0);
        
        (,,,,,,uint256 approvalCount,,,,) = multisig.getProposal(proposalId);
        require(approvalCount == 2, "Should have 2 approvals");
    }

    function test_Approve_RevertsWithInvalidNonce() public {
        vm.prank(signer1);
        uint256 proposalId = multisig.propose(targetAddr, 0, "", 0, 0);
        
        vm.prank(signer2);
        vm.expectRevert(MultiSigV2_1.InvalidNonce.selector);
        multisig.approve(proposalId, 999); // Wrong nonce
    }

    function test_Approve_RevertsWhenAlreadyApproved() public {
        vm.prank(signer1);
        uint256 proposalId = multisig.propose(targetAddr, 0, "", 0, 0);
        
        vm.prank(signer1);
        vm.expectRevert(MultiSigV2_1.AlreadyApproved.selector);
        multisig.approve(proposalId, 0);
    }

    function test_Approve_RevertsWhenExpired() public {
        vm.prank(signer1);
        uint256 proposalId = multisig.propose(targetAddr, 0, "", 0, 1 days);
        
        vm.warp(block.timestamp + 1 days + 1);
        
        vm.prank(signer2);
        vm.expectRevert(MultiSigV2_1.ProposalExpired.selector);
        multisig.approve(proposalId, 0);
    }

    function test_Approve_RevertsWhenCancelled() public {
        vm.prank(signer1);
        uint256 proposalId = multisig.propose(targetAddr, 0, "", 0, 0);
        
        vm.prank(signer1);
        multisig.cancel(proposalId);
        
        vm.prank(signer2);
        vm.expectRevert(MultiSigV2_1.ProposalAlreadyCancelled.selector);
        multisig.approve(proposalId, 0);
    }

    // ============ Execute Tests ============

    function test_Execute_ExecutesProposal() public {
        vm.deal(address(multisig), 1 ether);
        vm.prank(signer1);
        uint256 proposalId = multisig.propose(targetAddr, 0.5 ether, "", 0, 0);
        
        vm.prank(signer2);
        multisig.approve(proposalId, 0);
        
        vm.warp(block.timestamp + multisig.DEFAULT_TIMELOCK() + 1);
        
        uint256 balanceBefore = targetAddr.balance;
        vm.prank(signer1);
        multisig.execute(proposalId);
        
        require(targetAddr.balance == balanceBefore + 0.5 ether, "Should transfer value");
        
        (,,,,bool executed,,,,,,) = multisig.getProposal(proposalId);
        require(executed == true, "Should be marked as executed");
    }

    function test_Execute_RevertsBeforeTimelock() public {
        vm.prank(signer1);
        uint256 proposalId = multisig.propose(targetAddr, 0, "", 0, 0);
        
        vm.prank(signer2);
        multisig.approve(proposalId, 0);
        
        vm.expectRevert(MultiSigV2_1.TimelockNotMet.selector);
        multisig.execute(proposalId);
    }

    function test_Execute_RevertsWhenExpired() public {
        vm.prank(signer1);
        uint256 proposalId = multisig.propose(targetAddr, 0, "", 0, 1 days);
        
        vm.prank(signer2);
        multisig.approve(proposalId, 0);
        
        vm.warp(block.timestamp + multisig.DEFAULT_TIMELOCK() + 1 days + 1);
        
        vm.expectRevert(MultiSigV2_1.ProposalExpired.selector);
        multisig.execute(proposalId);
    }

    function test_Execute_RevertsWhenCancelled() public {
        vm.prank(signer1);
        uint256 proposalId = multisig.propose(targetAddr, 0, "", 0, 0);
        
        vm.prank(signer1);
        multisig.cancel(proposalId);
        
        vm.expectRevert(MultiSigV2_1.ProposalAlreadyCancelled.selector);
        multisig.execute(proposalId);
    }

    function test_Execute_RevertsWithDelegatecall() public {
        vm.prank(signer1);
        bytes memory maliciousData = abi.encodeWithSignature("delegatecall(address,bytes)", address(0x1), "");
        uint256 proposalId = multisig.propose(address(0x1), 0, maliciousData, 0, 0);
        
        vm.prank(signer2);
        multisig.approve(proposalId, 0);
        
        vm.warp(block.timestamp + multisig.DEFAULT_TIMELOCK() + 1);
        
        vm.expectRevert(MultiSigV2_1.DelegatecallNotAllowed.selector);
        multisig.execute(proposalId);
    }

    // ============ Cancel Tests ============

    function test_Cancel_CancelsProposal() public {
        vm.prank(signer1);
        uint256 proposalId = multisig.propose(targetAddr, 0, "", 0, 0);
        
        vm.prank(signer1);
        multisig.cancel(proposalId);
        
        (,,,,bool executed, bool cancelled,,,,,) = multisig.getProposal(proposalId);
        require(cancelled == true, "Should be cancelled");
        require(executed == false, "Should not be executed");
    }

    function test_Cancel_RevertsWhenNotProposer() public {
        vm.prank(signer1);
        uint256 proposalId = multisig.propose(targetAddr, 0, "", 0, 0);
        
        vm.prank(signer2);
        vm.expectRevert(MultiSigV2_1.NotProposer.selector);
        multisig.cancel(proposalId);
    }

    // ============ Governance Proposals Tests ============

    function test_ProposeAddSigner_CreatesProposal() public {
        address newSigner = address(0x7);
        
        vm.prank(signer1);
        uint256 proposalId = multisig.proposeAddSigner(newSigner);
        
        require(proposalId > 0, "Should create proposal");
        
        (,,address target,,,,,uint256 timelock,,,) = multisig.getProposal(proposalId);
        require(target == address(multisig), "Target should be multisig contract");
        require(timelock == multisig.CRITICAL_TIMELOCK(), "Should use critical timelock");
    }

    function test_ProposeAddSigner_ExecutesSuccessfully() public {
        address newSigner = address(0x7);
        
        vm.prank(signer1);
        uint256 proposalId = multisig.proposeAddSigner(newSigner);
        
        vm.prank(signer2);
        multisig.approve(proposalId, 0);
        
        vm.warp(block.timestamp + multisig.CRITICAL_TIMELOCK() + 1);
        
        vm.prank(signer1);
        multisig.execute(proposalId);
        
        require(multisig.isSigner(newSigner), "New signer should be added");
        require(multisig.getSignerCount() == 4, "Should have 4 signers");
    }

    function test_ProposeRemoveSigner_ExecutesSuccessfully() public {
        vm.prank(signer1);
        uint256 proposalId = multisig.proposeRemoveSigner(signer3);
        
        vm.prank(signer2);
        multisig.approve(proposalId, 0);
        
        vm.warp(block.timestamp + multisig.CRITICAL_TIMELOCK() + 1);
        
        vm.prank(signer1);
        multisig.execute(proposalId);
        
        require(!multisig.isSigner(signer3), "Signer3 should be removed");
        require(multisig.getSignerCount() == 2, "Should have 2 signers");
    }

    function test_ProposeSetThreshold_ExecutesSuccessfully() public {
        vm.prank(signer1);
        uint256 proposalId = multisig.proposeSetThreshold(3);
        
        vm.prank(signer2);
        multisig.approve(proposalId, 0);
        
        vm.warp(block.timestamp + multisig.CRITICAL_TIMELOCK() + 1);
        
        vm.prank(signer1);
        multisig.execute(proposalId);
        
        require(multisig.threshold() == 3, "Threshold should be updated");
    }

    function test_ProposePause_ExecutesSuccessfully() public {
        vm.prank(signer1);
        uint256 proposalId = multisig.proposePause();
        
        vm.prank(signer2);
        multisig.approve(proposalId, 0);
        
        vm.warp(block.timestamp + multisig.CRITICAL_TIMELOCK() + 1);
        
        vm.prank(signer1);
        multisig.execute(proposalId);
        
        // Try to propose should fail
        vm.prank(signer1);
        vm.expectRevert();
        multisig.propose(targetAddr, 0, "", 0, 0);
    }

    function test_ProposeUnpause_ExecutesSuccessfully() public {
        // First pause
        vm.prank(signer1);
        uint256 pauseProposal = multisig.proposePause();
        vm.prank(signer2);
        multisig.approve(pauseProposal, 0);
        vm.warp(block.timestamp + multisig.CRITICAL_TIMELOCK() + 1);
        vm.prank(signer1);
        multisig.execute(pauseProposal);
        
        // Then unpause
        vm.prank(signer1);
        uint256 unpauseProposal = multisig.proposeUnpause();
        vm.prank(signer2);
        multisig.approve(unpauseProposal, 0);
        vm.warp(block.timestamp + multisig.CRITICAL_TIMELOCK() + 1);
        vm.prank(signer1);
        multisig.execute(unpauseProposal);
        
        // Now propose should work
        vm.prank(signer1);
        uint256 proposalId = multisig.propose(targetAddr, 0, "", 0, 0);
        require(proposalId > 0, "Should be able to propose after unpause");
    }

    // ============ View Functions Tests ============

    function test_GetActiveProposals_ReturnsOnlyActive() public {
        vm.prank(signer1);
        uint256 proposal1 = multisig.propose(targetAddr, 0, "", 0, 0);
        
        vm.prank(signer1);
        uint256 proposal2 = multisig.propose(targetAddr, 0, "", 0, 0);
        
        vm.prank(signer1);
        multisig.cancel(proposal2);
        
        uint256[] memory active = multisig.getActiveProposals();
        require(active.length == 1, "Should have 1 active proposal");
        require(active[0] == proposal1, "Should return proposal1");
    }

    function test_CanExecute_ReturnsCorrectStatus() public {
        vm.prank(signer1);
        uint256 proposalId = multisig.propose(targetAddr, 0, "", 0, 0);
        
        require(multisig.canExecute(proposalId) == false, "Should not be executable yet");
        
        vm.prank(signer2);
        multisig.approve(proposalId, 0);
        
        require(multisig.canExecute(proposalId) == false, "Still not executable (timelock)");
        
        vm.warp(block.timestamp + multisig.DEFAULT_TIMELOCK() + 1);
        
        require(multisig.canExecute(proposalId) == true, "Should be executable now");
    }

    function test_HasApproved_ReturnsCorrectStatus() public {
        vm.prank(signer1);
        uint256 proposalId = multisig.propose(targetAddr, 0, "", 0, 0);
        
        require(multisig.hasApproved(proposalId, signer1) == true, "Signer1 should have approved");
        require(multisig.hasApproved(proposalId, signer2) == false, "Signer2 should not have approved");
        
        vm.prank(signer2);
        multisig.approve(proposalId, 0);
        
        require(multisig.hasApproved(proposalId, signer2) == true, "Signer2 should have approved now");
    }
}
