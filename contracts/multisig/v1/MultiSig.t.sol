// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {MultiSigV1} from "./MultiSig.sol";
import {Test} from "forge-std/Test.sol";

contract MultiSigTest is Test {
    MultiSigV1 multisig;
    
    address deployer;
    address owner = address(0x1);
    address signer1 = address(0x2);
    address signer2 = address(0x3);
    address signer3 = address(0x4);
    address nonSigner = address(0x5);
    address targetAddr = address(0x6);
    
    address[] signers;
    uint256 threshold = 2;

    function setUp() public {
        deployer = address(this); // The test contract is the deployer/owner
        
        signers = new address[](3);
        signers[0] = signer1;
        signers[1] = signer2;
        signers[2] = signer3;
        
        multisig = new MultiSigV1(signers, threshold);
    }

    // ============ Constructor Tests ============

    function test_Constructor_SetsInitialState() public view {
        require(multisig.threshold() == threshold, "Threshold should be set correctly");
        require(multisig.getSignerCount() == 3, "Should have 3 signers");
        require(multisig.isSigner(signer1), "Signer1 should be a signer");
        require(multisig.isSigner(signer2), "Signer2 should be a signer");
        require(multisig.isSigner(signer3), "Signer3 should be a signer");
    }

    function test_Constructor_RegistersOwnerInteraction() public view {
        // Owner is the deployer (address(this) in setUp)
        // This test checks the deployer's interactions
        // Note: myInteractions() is called from deployer's context, so it should work
        uint256 deployerInteractions = multisig.myInteractions();
        require(deployerInteractions >= 1, "Deployer should have at least 1 interaction");
    }

    function test_Constructor_RevertsWithZeroSigners() public {
        address[] memory emptySigners = new address[](0);
        vm.expectRevert("Must have at least one signer");
        new MultiSigV1(emptySigners, 1);
    }

    function test_Constructor_RevertsWithZeroThreshold() public {
        address[] memory testSigners = new address[](1);
        testSigners[0] = signer1;
        vm.expectRevert("Invalid threshold");
        new MultiSigV1(testSigners, 0);
    }

    function test_Constructor_RevertsWithThresholdGreaterThanSigners() public {
        address[] memory testSigners = new address[](2);
        testSigners[0] = signer1;
        testSigners[1] = signer2;
        vm.expectRevert("Invalid threshold");
        new MultiSigV1(testSigners, 3);
    }

    function test_Constructor_RevertsWithZeroAddressSigner() public {
        address[] memory testSigners = new address[](2);
        testSigners[0] = signer1;
        testSigners[1] = address(0);
        vm.expectRevert("Invalid signer address");
        new MultiSigV1(testSigners, 1);
    }

    function test_Constructor_RevertsWithDuplicateSigners() public {
        address[] memory testSigners = new address[](2);
        testSigners[0] = signer1;
        testSigners[1] = signer1;
        vm.expectRevert("Duplicate signer");
        new MultiSigV1(testSigners, 1);
    }

    // ============ Add Signer Tests ============

    function test_AddSigner_Success() public {
        address newSigner = address(0x7);
        
        vm.expectEmit(true, false, false, true);
        emit MultiSigV1.SignerAdded(newSigner, 4, threshold);
        
        multisig.addSigner(newSigner);
        
        require(multisig.isSigner(newSigner), "New signer should be added");
        require(multisig.getSignerCount() == 4, "Should have 4 signers now");
        
        address[] memory allSigners = multisig.getSigners();
        require(allSigners.length == 4, "GetSigners should return 4 signers");
    }

    function test_AddSigner_RevertsWhenNotOwner() public {
        vm.prank(nonSigner);
        vm.expectRevert(MultiSigV1.NotOwner.selector);
        multisig.addSigner(address(0x7));
    }

    function test_AddSigner_RevertsWithZeroAddress() public {
        vm.expectRevert(MultiSigV1.NotASigner.selector);
        multisig.addSigner(address(0));
    }

    function test_AddSigner_RevertsWhenAlreadySigner() public {
        vm.expectRevert(MultiSigV1.AlreadySigner.selector);
        multisig.addSigner(signer1);
    }

    function test_AddSigner_RegistersInteraction() public {
        address newSigner = address(0x7);
        uint256 interactionsBefore = multisig.myInteractions();
        multisig.addSigner(newSigner);
        uint256 interactionsAfter = multisig.myInteractions();
        require(interactionsAfter == interactionsBefore + 1, "Interaction should be registered");
    }

    // ============ Remove Signer Tests ============

    function test_RemoveSigner_Success() public {
        // First lower threshold to allow removal (if needed)
        // Threshold is 2, we have 3 signers, so we can remove one
        // But we need to set threshold to 2 first (it's already 2, so OK)
        
        vm.expectEmit(true, false, false, true);
        emit MultiSigV1.SignerRemoved(signer3, 2, threshold);
        
        multisig.removeSigner(signer3);
        
        require(!multisig.isSigner(signer3), "Signer3 should be removed");
        require(multisig.getSignerCount() == 2, "Should have 2 signers now");
    }

    function test_RemoveSigner_RevertsWhenNotOwner() public {
        // Lower threshold first
        multisig.setThreshold(1);
        
        vm.startPrank(nonSigner);
        vm.expectRevert(MultiSigV1.NotOwner.selector);
        multisig.removeSigner(signer1);
        vm.stopPrank();
    }

    function test_RemoveSigner_RevertsWhenNotASigner() public {
        vm.expectRevert(MultiSigV1.NotASigner.selector);
        multisig.removeSigner(nonSigner);
    }

    function test_RemoveSigner_RevertsWhenThresholdTooHigh() public {
        // Threshold is 2, signers are 3
        // To remove a signer, threshold must be <= signers.length - 1
        // If we set threshold to 3, we can't remove any signer (3 > 2)
        multisig.setThreshold(3);
        
        vm.expectRevert(MultiSigV1.InvalidThreshold.selector);
        multisig.removeSigner(signer3);
    }

    function test_RemoveSigner_RemovesFromArray() public {
        multisig.setThreshold(2);
        multisig.removeSigner(signer2);
        
        address[] memory remainingSigners = multisig.getSigners();
        require(remainingSigners.length == 2, "Should have 2 signers");
        require(remainingSigners[0] == signer1 || remainingSigners[1] == signer1, "Signer1 should remain");
        require(remainingSigners[0] == signer3 || remainingSigners[1] == signer3, "Signer3 should remain");
    }

    // ============ Set Threshold Tests ============

    function test_SetThreshold_Success() public {
        uint256 newThreshold = 3;
        
        vm.expectEmit(false, false, false, true);
        emit MultiSigV1.ThresholdChanged(threshold, newThreshold);
        
        multisig.setThreshold(newThreshold);
        
        require(multisig.threshold() == newThreshold, "Threshold should be updated");
    }

    function test_SetThreshold_RevertsWhenNotOwner() public {
        vm.startPrank(nonSigner);
        vm.expectRevert(MultiSigV1.NotOwner.selector);
        multisig.setThreshold(3);
        vm.stopPrank();
    }

    function test_SetThreshold_RevertsWithZero() public {
        vm.expectRevert("Invalid threshold");
        multisig.setThreshold(0);
    }

    function test_SetThreshold_RevertsWhenGreaterThanSigners() public {
        vm.expectRevert("Invalid threshold");
        multisig.setThreshold(4);
    }

    // ============ Propose Tests ============

    function test_Propose_Success() public {
        vm.prank(signer1);
        vm.expectEmit(true, true, false, true);
        emit MultiSigV1.ProposalCreated(1, signer1, targetAddr, 1 ether);
        
        vm.expectEmit(true, false, false, true);
        emit MultiSigV1.ProposalApproved(1, signer1, 1);
        
        uint256 proposalId = multisig.propose(targetAddr, 1 ether, "");
        
        require(proposalId == 1, "Proposal ID should be 1");
        
        (uint256 id, address proposer, address target, uint256 value, bool executed, uint256 approvalCount, bool canExecute) = 
            multisig.getProposal(proposalId);
        
        require(id == 1, "ID should be 1");
        require(proposer == signer1, "Proposer should be signer1");
        require(target == targetAddr, "Target should be targetAddr");
        require(value == 1 ether, "Value should be 1 ether");
        require(!executed, "Should not be executed");
        require(approvalCount == 1, "Should have 1 approval");
        require(!canExecute, "Should not be executable with 1 approval (threshold is 2)");
    }

    function test_Propose_RevertsWhenNotSigner() public {
        vm.prank(nonSigner);
        vm.expectRevert(MultiSigV1.NotSigner.selector);
        multisig.propose(targetAddr, 0, "");
    }

    function test_Propose_RevertsWithZeroAddressTarget() public {
        vm.prank(signer1);
        vm.expectRevert("Invalid target");
        multisig.propose(address(0), 0, "");
    }

    function test_Propose_AddsToActiveProposals() public {
        vm.prank(signer1);
        uint256 proposalId = multisig.propose(targetAddr, 0, "");
        
        uint256[] memory activeProposals = multisig.getActiveProposals();
        require(activeProposals.length == 1, "Should have 1 active proposal");
        require(activeProposals[0] == proposalId, "Should include the new proposal");
    }

    function test_Propose_AutoApprovesByProposer() public {
        vm.prank(signer1);
        uint256 proposalId = multisig.propose(targetAddr, 0, "");
        
        require(multisig.hasApproved(proposalId, signer1), "Proposer should have auto-approved");
    }

    function test_Propose_RegistersInteraction() public {
        vm.startPrank(signer1);
        uint256 interactionsBefore = multisig.myInteractions();
        multisig.propose(targetAddr, 0, "");
        uint256 interactionsAfter = multisig.myInteractions();
        vm.stopPrank();
        require(interactionsAfter == interactionsBefore + 1, "Interaction should be registered");
    }

    // ============ Approve Tests ============

    function test_Approve_Success() public {
        vm.prank(signer1);
        uint256 proposalId = multisig.propose(targetAddr, 0, "");
        
        vm.prank(signer2);
        vm.expectEmit(true, false, false, true);
        emit MultiSigV1.ProposalApproved(proposalId, signer2, 2);
        
        multisig.approve(proposalId);
        
        require(multisig.hasApproved(proposalId, signer2), "Signer2 should have approved");
        
        (,,,,, uint256 approvalCount, bool canExecute) = multisig.getProposal(proposalId);
        require(approvalCount == 2, "Should have 2 approvals");
        require(canExecute, "Should be executable now");
    }

    function test_Approve_RevertsWhenNotSigner() public {
        vm.prank(signer1);
        uint256 proposalId = multisig.propose(targetAddr, 0, "");
        
        vm.prank(nonSigner);
        vm.expectRevert(MultiSigV1.NotSigner.selector);
        multisig.approve(proposalId);
    }

    function test_Approve_RevertsWithInvalidProposal() public {
        vm.prank(signer1);
        vm.expectRevert(MultiSigV1.InvalidProposal.selector);
        multisig.approve(999);
    }

    function test_Approve_RevertsWhenAlreadyApproved() public {
        vm.prank(signer1);
        uint256 proposalId = multisig.propose(targetAddr, 0, "");
        
        vm.prank(signer1);
        vm.expectRevert(MultiSigV1.AlreadyApproved.selector);
        multisig.approve(proposalId);
    }

    function test_Approve_RevertsWhenAlreadyExecuted() public {
        vm.prank(signer1);
        uint256 proposalId = multisig.propose(targetAddr, 0, "");
        
        vm.prank(signer2);
        multisig.approve(proposalId);
        
        // Execute the proposal
        vm.deal(address(multisig), 0); // Ensure multisig has no ETH for this test
        vm.prank(signer1);
        multisig.execute(proposalId);
        
        // Try to approve executed proposal
        vm.prank(signer3);
        vm.expectRevert(MultiSigV1.AlreadyExecuted.selector);
        multisig.approve(proposalId);
    }

    // ============ Execute Tests ============

    function test_Execute_Success() public {
        // Deploy a mock contract that receives ETH
        MockTarget mockTarget = new MockTarget();
        
        vm.prank(signer1);
        uint256 proposalId = multisig.propose(address(mockTarget), 1 ether, "");
        
        vm.prank(signer2);
        multisig.approve(proposalId);
        
        vm.deal(address(multisig), 1 ether);
        
        vm.expectEmit(true, false, false, true);
        emit MultiSigV1.ProposalExecuted(proposalId, nonSigner);
        
        vm.prank(nonSigner); // Anyone can execute
        multisig.execute(proposalId);
        
        require(address(mockTarget).balance == 1 ether, "Target should receive ETH");
        
        (,,,, bool executed,,) = multisig.getProposal(proposalId);
        require(executed, "Proposal should be marked as executed");
        
        uint256[] memory activeProposals = multisig.getActiveProposals();
        require(activeProposals.length == 0, "Should have no active proposals");
    }

    function test_Execute_WithData() public {
        MockTarget mockTarget = new MockTarget();
        
        bytes memory data = abi.encodeWithSignature("setValue(uint256)", 42);
        vm.prank(signer1);
        uint256 proposalId = multisig.propose(address(mockTarget), 0, data);
        
        vm.prank(signer2);
        multisig.approve(proposalId);
        
        vm.prank(nonSigner);
        multisig.execute(proposalId);
        
        require(mockTarget.value() == 42, "Target should have value set to 42");
    }

    function test_Execute_RevertsWithInvalidProposal() public {
        vm.expectRevert(MultiSigV1.InvalidProposal.selector);
        multisig.execute(999);
    }

    function test_Execute_RevertsWhenAlreadyExecuted() public {
        MockTarget mockTarget = new MockTarget();
        
        vm.prank(signer1);
        uint256 proposalId = multisig.propose(address(mockTarget), 0, "");
        
        vm.prank(signer2);
        multisig.approve(proposalId);
        
        vm.prank(nonSigner);
        multisig.execute(proposalId);
        
        // Try to execute again
        vm.expectRevert(MultiSigV1.AlreadyExecuted.selector);
        multisig.execute(proposalId);
    }

    function test_Execute_RevertsWithInsufficientApprovals() public {
        vm.prank(signer1);
        uint256 proposalId = multisig.propose(targetAddr, 0, "");
        
        // Only 1 approval, threshold is 2
        vm.expectRevert(MultiSigV1.InsufficientApprovals.selector);
        multisig.execute(proposalId);
    }

    function test_Execute_RevertsOnFailure() public {
        RevertingTarget revertingTarget = new RevertingTarget();
        
        vm.prank(signer1);
        uint256 proposalId = multisig.propose(address(revertingTarget), 0, "");
        
        vm.prank(signer2);
        multisig.approve(proposalId);
        
        vm.expectRevert(MultiSigV1.ExecutionFailed.selector);
        multisig.execute(proposalId);
    }

    // ============ Cancel Tests ============

    function test_Cancel_ByProposer() public {
        vm.prank(signer1);
        uint256 proposalId = multisig.propose(targetAddr, 0, "");
        
        vm.expectEmit(true, false, false, true);
        emit MultiSigV1.ProposalCancelled(proposalId, signer1);
        
        vm.prank(signer1);
        multisig.cancel(proposalId);
        
        (,,,, bool executed,,) = multisig.getProposal(proposalId);
        require(executed, "Proposal should be marked as executed (cancelled)");
        
        uint256[] memory activeProposals = multisig.getActiveProposals();
        require(activeProposals.length == 0, "Should have no active proposals");
    }

    function test_Cancel_ByOwner() public {
        vm.prank(signer1);
        uint256 proposalId = multisig.propose(targetAddr, 0, "");
        
        vm.expectEmit(true, false, false, true);
        emit MultiSigV1.ProposalCancelled(proposalId, deployer);
        
        multisig.cancel(proposalId);
        
        (,,,, bool executed,,) = multisig.getProposal(proposalId);
        require(executed, "Proposal should be marked as executed (cancelled)");
    }

    function test_Cancel_RevertsWhenNotAuthorized() public {
        vm.prank(signer1);
        uint256 proposalId = multisig.propose(targetAddr, 0, "");
        
        vm.prank(nonSigner);
        vm.expectRevert("Not authorized to cancel");
        multisig.cancel(proposalId);
    }

    function test_Cancel_RevertsWithInvalidProposal() public {
        vm.expectRevert(MultiSigV1.InvalidProposal.selector);
        multisig.cancel(999);
    }

    function test_Cancel_RevertsWhenAlreadyExecuted() public {
        MockTarget mockTarget = new MockTarget();
        
        vm.prank(signer1);
        uint256 proposalId = multisig.propose(address(mockTarget), 0, "");
        
        vm.prank(signer2);
        multisig.approve(proposalId);
        
        vm.prank(nonSigner);
        multisig.execute(proposalId);
        
        vm.prank(signer1);
        vm.expectRevert(MultiSigV1.AlreadyExecuted.selector);
        multisig.cancel(proposalId);
    }

    // ============ View Function Tests ============

    function test_GetProposal_ReturnsCorrectData() public {
        vm.prank(signer1);
        uint256 proposalId = multisig.propose(targetAddr, 5 ether, hex"1234");
        
        (uint256 id, address proposer, address target, uint256 value, bool executed, uint256 approvalCount, bool canExecute) = 
            multisig.getProposal(proposalId);
        
        require(id == proposalId, "ID should match");
        require(proposer == signer1, "Proposer should match");
        require(target == targetAddr, "Target should match");
        require(value == 5 ether, "Value should match");
        require(!executed, "Should not be executed");
        require(approvalCount == 1, "Should have 1 approval");
        require(!canExecute, "Should not be executable with 1 approval");
    }

    function test_HasApproved_ReturnsTrueWhenApproved() public {
        vm.prank(signer1);
        uint256 proposalId = multisig.propose(targetAddr, 0, "");
        
        require(multisig.hasApproved(proposalId, signer1), "Signer1 should have approved");
        require(!multisig.hasApproved(proposalId, signer2), "Signer2 should not have approved");
    }

    function test_GetSigners_ReturnsAllSigners() public {
        address[] memory allSigners = multisig.getSigners();
        require(allSigners.length == 3, "Should return 3 signers");
    }

    function test_GetActiveProposals_ReturnsOnlyActive() public {
        vm.prank(signer1);
        uint256 proposalId1 = multisig.propose(targetAddr, 0, "");
        
        vm.prank(signer2);
        uint256 proposalId2 = multisig.propose(targetAddr, 0, "");
        
        uint256[] memory active = multisig.getActiveProposals();
        require(active.length == 2, "Should have 2 active proposals");
        
        // Execute one
        vm.prank(signer3);
        multisig.approve(proposalId1);
        
        MockTarget mockTarget = new MockTarget();
        vm.prank(signer1);
        uint256 proposalId3 = multisig.propose(address(mockTarget), 0, "");
        
        vm.prank(signer2);
        multisig.approve(proposalId1);
        
        vm.prank(nonSigner);
        multisig.execute(proposalId1);
        
        active = multisig.getActiveProposals();
        require(active.length == 2, "Should have 2 active proposals after execution");
    }

    function test_GetSignerCount_ReturnsCorrectCount() public view {
        require(multisig.getSignerCount() == 3, "Should return 3 signers");
    }

    function test_MyInteractions_TracksCorrectly() public {
        uint256 initial = multisig.myInteractions();
        
        // Add a signer
        multisig.addSigner(address(0x8));
        require(multisig.myInteractions() == initial + 1, "Should increment after addSigner");
        
        // Propose (as signer1, should register interaction for signer1)
        vm.prank(signer1);
        multisig.propose(targetAddr, 0, "");
        
        // Check that our interactions haven't changed (we're not signer1)
        require(multisig.myInteractions() == initial + 1, "Should not change when not caller");
        
        // Check signer1's interactions from signer1's perspective
        vm.prank(signer1);
        uint256 signer1Interactions = multisig.myInteractions();
        require(signer1Interactions > 0, "Signer1 should have interactions");
    }

    function test_Receive_FunctionAcceptsEther() public {
        vm.deal(address(this), 10 ether);
        (bool success, ) = address(multisig).call{value: 1 ether}("");
        require(success, "Should accept ETH");
        require(address(multisig).balance == 1 ether, "Should have 1 ether");
    }

    // ============ Edge Cases and Integration Tests ============

    function test_MultipleProposals_WorkIndependently() public {
        vm.prank(signer1);
        uint256 proposalId1 = multisig.propose(targetAddr, 1 ether, "");
        
        vm.prank(signer2);
        uint256 proposalId2 = multisig.propose(targetAddr, 2 ether, "");
        
        require(proposalId1 == 1, "First proposal should be ID 1");
        require(proposalId2 == 2, "Second proposal should be ID 2");
        
        // Approve both
        vm.prank(signer3);
        multisig.approve(proposalId1);
        
        vm.prank(signer1);
        multisig.approve(proposalId2);
        
        (,,,,, uint256 count1, bool exec1) = multisig.getProposal(proposalId1);
        (,,,,, uint256 count2, bool exec2) = multisig.getProposal(proposalId2);
        
        require(count1 == 2, "Proposal 1 should have 2 approvals");
        require(count2 == 2, "Proposal 2 should have 2 approvals");
        require(exec1, "Proposal 1 should be executable");
        require(exec2, "Proposal 2 should be executable");
    }

    function test_FullWorkflow_CreateApproveExecute() public {
        MockTarget mockTarget = new MockTarget();
        
        // Create proposal
        vm.prank(signer1);
        uint256 proposalId = multisig.propose(address(mockTarget), 1 ether, "");
        
        // Approve by second signer
        vm.prank(signer2);
        multisig.approve(proposalId);
        
        // Execute
        vm.deal(address(multisig), 1 ether);
        vm.prank(nonSigner);
        multisig.execute(proposalId);
        
        require(address(mockTarget).balance == 1 ether, "Target should receive ETH");
        require(multisig.getActiveProposals().length == 0, "No active proposals");
    }

    function test_ThresholdChange_AffectsExecutability() public {
        vm.startPrank(signer1);
        uint256 proposalId = multisig.propose(targetAddr, 0, "");
        vm.stopPrank();
        
        // With threshold 2, 1 approval is not enough
        (,,,,, uint256 count, bool canExecute) = multisig.getProposal(proposalId);
        require(count == 1, "Should have 1 approval");
        require(!canExecute, "Should not be executable");
        
        // Lower threshold to 1
        multisig.setThreshold(1);
        
        (,,,,, count, canExecute) = multisig.getProposal(proposalId);
        require(count == 1, "Should still have 1 approval");
        require(canExecute, "Should now be executable");
    }
}

// ============ Helper Contracts ============

contract MockTarget {
    uint256 public value;
    
    receive() external payable {}
    
    function setValue(uint256 _value) external {
        value = _value;
    }
}

contract RevertingTarget {
    receive() external payable {
        revert("Always reverts");
    }
}