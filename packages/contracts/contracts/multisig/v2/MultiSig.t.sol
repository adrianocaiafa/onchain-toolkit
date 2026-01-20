// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {MultiSigV2} from "./MultiSig.sol";
import {Test} from "forge-std/Test.sol";

contract MultiSigV2Test is Test {
    MultiSigV2 multisig;
    
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
        
        multisig = new MultiSigV2(signers, threshold);
    }

    // ============ Constructor Tests ============

    function test_Constructor_SetsInitialState() public view {
        require(multisig.threshold() == threshold, "Threshold should be set correctly");
        require(multisig.getSignerCount() == 3, "Should have 3 signers");
        require(multisig.isSigner(signer1), "Signer1 should be a signer");
        require(multisig.isSigner(signer2), "Signer2 should be a signer");
        require(multisig.isSigner(signer3), "Signer3 should be a signer");
    }

    function test_Constructor_NoOwner() public view {
        // V2 doesn't have owner, so we can't check for it
        // This test just verifies the contract was created successfully
        require(multisig.getSignerCount() > 0, "Should have signers");
    }

    function test_Constructor_RevertsWithZeroSigners() public {
        address[] memory emptySigners = new address[](0);
        vm.expectRevert("Must have at least one signer");
        new MultiSigV2(emptySigners, 1);
    }

    function test_Constructor_RevertsWithZeroThreshold() public {
        address[] memory testSigners = new address[](1);
        testSigners[0] = signer1;
        vm.expectRevert("Invalid threshold");
        new MultiSigV2(testSigners, 0);
    }

    function test_Constructor_RevertsWithThresholdGreaterThanSigners() public {
        address[] memory testSigners = new address[](2);
        testSigners[0] = signer1;
        testSigners[1] = signer2;
        vm.expectRevert("Invalid threshold");
        new MultiSigV2(testSigners, 3);
    }

    function test_Constructor_RevertsWithZeroAddressSigner() public {
        address[] memory testSigners = new address[](2);
        testSigners[0] = signer1;
        testSigners[1] = address(0);
        vm.expectRevert("Invalid signer address");
        new MultiSigV2(testSigners, 1);
    }

    function test_Constructor_RevertsWithDuplicateSigners() public {
        address[] memory testSigners = new address[](2);
        testSigners[0] = signer1;
        testSigners[1] = signer1;
        vm.expectRevert("Duplicate signer");
        new MultiSigV2(testSigners, 1);
    }

    // ============ Proposal Tests (Basic) ============

    function test_Propose_CreatesProposal() public {
        vm.prank(signer1);
        uint256 proposalId = multisig.propose(targetAddr, 0, "", 0, 0);
        
        require(proposalId == 1, "First proposal should have ID 1");
        
        (uint256 id, address proposer, address target, uint256 value, bool executed, uint256 approvalCount,,,,) = multisig.getProposal(proposalId);
        
        require(id == 1, "Proposal ID should be 1");
        require(proposer == signer1, "Proposer should be signer1");
        require(target == targetAddr, "Target should match");
        require(value == 0, "Value should be 0");
        require(!executed, "Proposal should not be executed");
        require(approvalCount == 1, "Should have 1 approval (from proposer)");
    }

    function test_Propose_RevertsIfNotSigner() public {
        vm.prank(nonSigner);
        vm.expectRevert(MultiSigV2.NotSigner.selector);
        multisig.propose(targetAddr, 0, "", 0, 0);
    }

    function test_Propose_RevertsWithZeroTarget() public {
        vm.prank(signer1);
        vm.expectRevert("Invalid target");
        multisig.propose(address(0), 0, "", 0, 0);
    }

    function test_Propose_UsesDefaultTimelock() public {
        vm.prank(signer1);
        uint256 proposalId = multisig.propose(targetAddr, 0, "", 0, 0);
        
        (,,,,,, uint256 timelock,,,) = multisig.getProposal(proposalId);
        require(timelock == multisig.DEFAULT_TIMELOCK(), "Should use default timelock");
    }

    function test_Propose_UsesCustomTimelock() public {
        uint256 customTimelock = 2 hours;
        vm.prank(signer1);
        uint256 proposalId = multisig.propose(targetAddr, 0, "", customTimelock, 0);
        
        (,,,,,, uint256 timelock,,,) = multisig.getProposal(proposalId);
        require(timelock == customTimelock, "Should use custom timelock");
    }

    function test_Propose_SetsExpiration() public {
        vm.prank(signer1);
        uint256 proposalId = multisig.propose(targetAddr, 0, "", 0, 0);
        
        (,,,,,,, uint256 createdAt, uint256 expiresAt,) = multisig.getProposal(proposalId);
        require(expiresAt > createdAt, "Expiration should be after creation");
        require(expiresAt == createdAt + multisig.DEFAULT_EXPIRATION(), "Should use default expiration");
    }

    // ============ Timelock Tests ============

    function test_Execute_RevertsBeforeTimelock() public {
        vm.prank(signer1);
        uint256 proposalId = multisig.propose(targetAddr, 0, "", 1 hours, 0);
        
        vm.prank(signer2);
        multisig.approve(proposalId);
        
        // Try to execute immediately (before timelock)
        vm.expectRevert(MultiSigV2.TimelockNotMet.selector);
        multisig.execute(proposalId);
    }

    function test_Execute_SucceedsAfterTimelock() public {
        vm.prank(signer1);
        uint256 proposalId = multisig.propose(targetAddr, 0, "", 1 hours, 0);
        
        vm.prank(signer2);
        multisig.approve(proposalId);
        
        // Advance time past timelock
        vm.warp(block.timestamp + 1 hours + 1);
        
        // Execute should succeed
        multisig.execute(proposalId);
        
        (,,,, bool executed,,,,,) = multisig.getProposal(proposalId);
        require(executed, "Proposal should be executed");
    }

    function test_Execute_WithZeroTimelock() public {
        vm.prank(signer1);
        uint256 proposalId = multisig.propose(targetAddr, 0, "", 0, 0);
        
        vm.prank(signer2);
        multisig.approve(proposalId);
        
        // With default timelock (1 hour), should still need to wait
        vm.expectRevert(MultiSigV2.TimelockNotMet.selector);
        multisig.execute(proposalId);
        
        // Advance time
        vm.warp(block.timestamp + 1 hours + 1);
        
        // Now should work
        multisig.execute(proposalId);
        
        (,,,, bool executed,,,,,) = multisig.getProposal(proposalId);
        require(executed, "Proposal should be executed");
    }

    // ============ Expiration Tests ============

    function test_Approve_RevertsIfExpired() public {
        vm.prank(signer1);
        uint256 proposalId = multisig.propose(targetAddr, 0, "", 0, 1 days);
        
        // Advance time past expiration
        vm.warp(block.timestamp + 1 days + 1);
        
        // Try to approve expired proposal
        vm.prank(signer2);
        vm.expectRevert(MultiSigV2.ProposalExpired.selector);
        multisig.approve(proposalId);
    }

    function test_Execute_RevertsIfExpired() public {
        vm.prank(signer1);
        uint256 proposalId = multisig.propose(targetAddr, 0, "", 0, 1 days);
        
        vm.prank(signer2);
        multisig.approve(proposalId);
        
        // Advance time past expiration
        vm.warp(block.timestamp + 1 days + 1);
        
        // Advance past timelock too
        vm.warp(block.timestamp + 1 hours);
        
        // Try to execute expired proposal
        vm.expectRevert(MultiSigV2.ProposalExpired.selector);
        multisig.execute(proposalId);
    }

    function test_GetActiveProposals_FiltersExpired() public {
        vm.prank(signer1);
        uint256 proposalId1 = multisig.propose(targetAddr, 0, "", 0, 1 days);
        
        vm.prank(signer2);
        uint256 proposalId2 = multisig.propose(targetAddr, 0, "", 0, 2 days);
        
        // Advance time past first proposal expiration
        vm.warp(block.timestamp + 1 days + 1);
        
        uint256[] memory active = multisig.getActiveProposals();
        require(active.length == 1, "Should have 1 active proposal");
        require(active[0] == proposalId2, "Should only have non-expired proposal");
    }

    // ============ Delegatecall Protection Tests ============

    function test_Execute_RevertsOnDelegatecall() public {
        // Create a proposal with delegatecall selector
        bytes memory maliciousData = abi.encodeWithSignature("delegatecall(address,bytes)", address(0x123), "");
        
        vm.prank(signer1);
        uint256 proposalId = multisig.propose(targetAddr, 0, maliciousData, 0, 0);
        
        vm.prank(signer2);
        multisig.approve(proposalId);
        
        vm.warp(block.timestamp + 1 hours + 1);
        
        vm.expectRevert(MultiSigV2.DelegatecallNotAllowed.selector);
        multisig.execute(proposalId);
    }

    function test_Execute_RevertsOnSelfdestruct() public {
        bytes memory maliciousData = abi.encodeWithSignature("selfdestruct(address)", address(0x123));
        
        vm.prank(signer1);
        uint256 proposalId = multisig.propose(targetAddr, 0, maliciousData, 0, 0);
        
        vm.prank(signer2);
        multisig.approve(proposalId);
        
        vm.warp(block.timestamp + 1 hours + 1);
        
        vm.expectRevert(MultiSigV2.DelegatecallNotAllowed.selector);
        multisig.execute(proposalId);
    }

    function test_Execute_AllowsNormalCalls() public {
        // Normal transfer call
        bytes memory normalData = abi.encodeWithSignature("transfer(address,uint256)", address(0x123), 100);
        
        vm.prank(signer1);
        uint256 proposalId = multisig.propose(targetAddr, 0, normalData, 0, 0);
        
        vm.prank(signer2);
        multisig.approve(proposalId);
        
        vm.warp(block.timestamp + 1 hours + 1);
        
        // Should not revert (even if target doesn't exist, it should fail with ExecutionFailed, not DelegatecallNotAllowed)
        vm.expectRevert(MultiSigV2.ExecutionFailed.selector);
        multisig.execute(proposalId);
    }

    // ============ Administrative Functions via Proposals ============

    function test_ProposeAddSigner_CreatesProposal() public {
        address newSigner = address(0x7);
        
        vm.prank(signer1);
        uint256 proposalId = multisig.proposeAddSigner(newSigner);
        
        require(proposalId == 1, "Should create proposal");
        
        (,,,,,, uint256 timelock,,,) = multisig.getProposal(proposalId);
        require(timelock == multisig.CRITICAL_TIMELOCK(), "Should use critical timelock");
    }

    function test_ProposeAddSigner_ExecutesSuccessfully() public {
        address newSigner = address(0x7);
        
        vm.prank(signer1);
        uint256 proposalId = multisig.proposeAddSigner(newSigner);
        
        vm.prank(signer2);
        multisig.approve(proposalId);
        
        // Advance past critical timelock
        vm.warp(block.timestamp + multisig.CRITICAL_TIMELOCK() + 1);
        
        vm.expectEmit(true, false, false, true);
        emit MultiSigV2.SignerAdded(newSigner, 4, threshold);
        
        multisig.execute(proposalId);
        
        require(multisig.isSigner(newSigner), "New signer should be added");
        require(multisig.getSignerCount() == 4, "Should have 4 signers");
    }

    function test_ProposeRemoveSigner_ExecutesSuccessfully() public {
        vm.prank(signer1);
        uint256 proposalId = multisig.proposeRemoveSigner(signer3);
        
        vm.prank(signer2);
        multisig.approve(proposalId);
        
        vm.warp(block.timestamp + multisig.CRITICAL_TIMELOCK() + 1);
        
        vm.expectEmit(true, false, false, true);
        emit MultiSigV2.SignerRemoved(signer3, 2, threshold);
        
        multisig.execute(proposalId);
        
        require(!multisig.isSigner(signer3), "Signer3 should be removed");
        require(multisig.getSignerCount() == 2, "Should have 2 signers");
    }

    function test_ProposeSetThreshold_ExecutesSuccessfully() public {
        uint256 newThreshold = 3;
        
        vm.prank(signer1);
        uint256 proposalId = multisig.proposeSetThreshold(newThreshold);
        
        vm.prank(signer2);
        multisig.approve(proposalId);
        
        vm.warp(block.timestamp + multisig.CRITICAL_TIMELOCK() + 1);
        
        vm.expectEmit(true, false, false, true);
        emit MultiSigV2.ThresholdChanged(threshold, newThreshold);
        
        multisig.execute(proposalId);
        
        require(multisig.threshold() == newThreshold, "Threshold should be updated");
    }

    function test_ProposeAddSigner_RevertsIfAlreadySigner() public {
        vm.prank(signer1);
        vm.expectRevert(MultiSigV2.AlreadySigner.selector);
        multisig.proposeAddSigner(signer1);
    }

    function test_ProposeRemoveSigner_RevertsIfInvalidThreshold() public {
        // Set threshold to 3 (all signers)
        vm.prank(signer1);
        uint256 thresholdProposal = multisig.proposeSetThreshold(3);
        vm.prank(signer2);
        multisig.approve(thresholdProposal);
        vm.warp(block.timestamp + multisig.CRITICAL_TIMELOCK() + 1);
        multisig.execute(thresholdProposal);
        
        // Now try to remove a signer (would leave only 2, but threshold is 3)
        vm.prank(signer1);
        vm.expectRevert(MultiSigV2.InvalidThreshold.selector);
        multisig.proposeRemoveSigner(signer3);
    }

    // ============ Cancel Tests (Only Proposer) ============

    function test_Cancel_OnlyProposerCanCancel() public {
        vm.prank(signer1);
        uint256 proposalId = multisig.propose(targetAddr, 0, "", 0, 0);
        
        // Proposer can cancel
        vm.prank(signer1);
        multisig.cancel(proposalId);
        
        (,,,, bool executed,,,,,) = multisig.getProposal(proposalId);
        require(executed, "Proposal should be marked as executed (cancelled)");
    }

    function test_Cancel_RevertsIfNotProposer() public {
        vm.prank(signer1);
        uint256 proposalId = multisig.propose(targetAddr, 0, "", 0, 0);
        
        // Non-proposer cannot cancel
        vm.prank(signer2);
        vm.expectRevert(MultiSigV2.NotProposer.selector);
        multisig.cancel(proposalId);
    }

    function test_Cancel_RevertsIfNonSigner() public {
        vm.prank(signer1);
        uint256 proposalId = multisig.propose(targetAddr, 0, "", 0, 0);
        
        vm.prank(nonSigner);
        vm.expectRevert(MultiSigV2.NotProposer.selector);
        multisig.cancel(proposalId);
    }

    // ============ Approval Tests ============

    function test_Approve_IncreasesApprovalCount() public {
        vm.prank(signer1);
        uint256 proposalId = multisig.propose(targetAddr, 0, "", 0, 0);
        
        vm.prank(signer2);
        multisig.approve(proposalId);
        
        (,,,,, uint256 approvalCount,,,,) = multisig.getProposal(proposalId);
        require(approvalCount == 2, "Should have 2 approvals");
    }

    function test_Approve_RevertsIfAlreadyApproved() public {
        vm.prank(signer1);
        uint256 proposalId = multisig.propose(targetAddr, 0, "", 0, 0);
        
        vm.prank(signer1);
        vm.expectRevert(MultiSigV2.AlreadyApproved.selector);
        multisig.approve(proposalId);
    }

    function test_Approve_RevertsIfNotSigner() public {
        vm.prank(signer1);
        uint256 proposalId = multisig.propose(targetAddr, 0, "", 0, 0);
        
        vm.prank(nonSigner);
        vm.expectRevert(MultiSigV2.NotSigner.selector);
        multisig.approve(proposalId);
    }

    // ============ Execute Tests ============

    function test_Execute_RevertsIfInsufficientApprovals() public {
        vm.prank(signer1);
        uint256 proposalId = multisig.propose(targetAddr, 0, "", 0, 0);
        
        // Only 1 approval, need 2
        vm.warp(block.timestamp + 1 hours + 1);
        
        vm.expectRevert(MultiSigV2.InsufficientApprovals.selector);
        multisig.execute(proposalId);
    }

    function test_Execute_SucceedsWithThresholdApprovals() public {
        vm.prank(signer1);
        uint256 proposalId = multisig.propose(targetAddr, 0, "", 0, 0);
        
        vm.prank(signer2);
        multisig.approve(proposalId);
        
        vm.warp(block.timestamp + 1 hours + 1);
        
        multisig.execute(proposalId);
        
        (,,,, bool executed,,,,,) = multisig.getProposal(proposalId);
        require(executed, "Proposal should be executed");
    }

    function test_Execute_CanBeCalledByAnyone() public {
        vm.prank(signer1);
        uint256 proposalId = multisig.propose(targetAddr, 0, "", 0, 0);
        
        vm.prank(signer2);
        multisig.approve(proposalId);
        
        vm.warp(block.timestamp + 1 hours + 1);
        
        // Non-signer can execute
        vm.prank(nonSigner);
        multisig.execute(proposalId);
        
        (,,,, bool executed,,,,,) = multisig.getProposal(proposalId);
        require(executed, "Proposal should be executed");
    }

    // ============ View Function Tests ============

    function test_GetProposal_ReturnsAllFields() public {
        vm.prank(signer1);
        uint256 proposalId = multisig.propose(targetAddr, 100, "0x1234", 2 hours, 5 days);
        
        (
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
        ) = multisig.getProposal(proposalId);
        
        require(id == proposalId, "ID should match");
        require(proposer == signer1, "Proposer should match");
        require(target == targetAddr, "Target should match");
        require(value == 100, "Value should match");
        require(!executed, "Should not be executed");
        require(approvalCount == 1, "Should have 1 approval");
        require(timelock == 2 hours, "Timelock should match");
        require(createdAt > 0, "CreatedAt should be set");
        require(expiresAt == createdAt + 5 days, "ExpiresAt should be correct");
        require(!executable, "Should not be executable yet (timelock not met)");
    }

    function test_CanExecute_ReturnsTrueWhenReady() public {
        vm.prank(signer1);
        uint256 proposalId = multisig.propose(targetAddr, 0, "", 0, 0);
        
        vm.prank(signer2);
        multisig.approve(proposalId);
        
        vm.warp(block.timestamp + 1 hours + 1);
        
        require(multisig.canExecute(proposalId), "Should be executable");
    }

    function test_CanExecute_ReturnsFalseBeforeTimelock() public {
        vm.prank(signer1);
        uint256 proposalId = multisig.propose(targetAddr, 0, "", 0, 0);
        
        vm.prank(signer2);
        multisig.approve(proposalId);
        
        // Before timelock
        require(!multisig.canExecute(proposalId), "Should not be executable");
    }

    function test_CanExecute_ReturnsFalseIfExpired() public {
        vm.prank(signer1);
        uint256 proposalId = multisig.propose(targetAddr, 0, "", 0, 1 days);
        
        vm.prank(signer2);
        multisig.approve(proposalId);
        
        vm.warp(block.timestamp + 1 days + 1 hours + 1);
        
        require(!multisig.canExecute(proposalId), "Should not be executable (expired)");
    }

    function test_HasApproved_ReturnsCorrectValue() public {
        vm.prank(signer1);
        uint256 proposalId = multisig.propose(targetAddr, 0, "", 0, 0);
        
        require(multisig.hasApproved(proposalId, signer1), "Signer1 should have approved");
        require(!multisig.hasApproved(proposalId, signer2), "Signer2 should not have approved");
        
        vm.prank(signer2);
        multisig.approve(proposalId);
        
        require(multisig.hasApproved(proposalId, signer2), "Signer2 should have approved now");
    }

    function test_GetSigners_ReturnsAllSigners() public {
        address[] memory allSigners = multisig.getSigners();
        require(allSigners.length == 3, "Should have 3 signers");
        require(allSigners[0] == signer1, "First signer should match");
        require(allSigners[1] == signer2, "Second signer should match");
        require(allSigners[2] == signer3, "Third signer should match");
    }

    function test_GetSignerCount_ReturnsCorrectCount() public view {
        require(multisig.getSignerCount() == 3, "Should have 3 signers");
    }

    // ============ Interaction Tracking Tests ============

    function test_MyInteractions_TracksCorrectly() public {
        vm.startPrank(signer1);
        multisig.propose(targetAddr, 0, "", 0, 0);
        uint256 interactions1 = multisig.myInteractions();
        require(interactions1 >= 1, "Should track interactions");
        
        multisig.propose(targetAddr, 0, "", 0, 0);
        uint256 interactions2 = multisig.myInteractions();
        require(interactions2 > interactions1, "Should increment interactions");
        vm.stopPrank();
    }

    // ============ Edge Cases ============

    function test_Execute_RevertsIfAlreadyExecuted() public {
        vm.prank(signer1);
        uint256 proposalId = multisig.propose(targetAddr, 0, "", 0, 0);
        
        vm.prank(signer2);
        multisig.approve(proposalId);
        
        vm.warp(block.timestamp + 1 hours + 1);
        
        multisig.execute(proposalId);
        
        // Try to execute again
        vm.expectRevert(MultiSigV2.AlreadyExecuted.selector);
        multisig.execute(proposalId);
    }

    function test_Execute_RevertsIfInvalidProposal() public {
        vm.expectRevert(MultiSigV2.InvalidProposal.selector);
        multisig.execute(999);
    }

    function test_Cancel_RevertsIfAlreadyExecuted() public {
        vm.prank(signer1);
        uint256 proposalId = multisig.propose(targetAddr, 0, "", 0, 0);
        
        vm.prank(signer2);
        multisig.approve(proposalId);
        
        vm.warp(block.timestamp + 1 hours + 1);
        multisig.execute(proposalId);
        
        vm.prank(signer1);
        vm.expectRevert(MultiSigV2.AlreadyExecuted.selector);
        multisig.cancel(proposalId);
    }
}
