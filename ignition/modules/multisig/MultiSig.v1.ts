import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

export default buildModule("MultiSigV1Module", (m) => {
  // Get accounts for signers
  // In a real deployment, you would pass specific addresses
  const accounts = m.getAccounts();
  
  // Example: Create a 2-of-3 multisig with 3 signers
  // Adjust signers and threshold based on your needs
  const signers = [
    accounts[0], // First account (deployer)
    accounts[1] || "0x0000000000000000000000000000000000000001", // Second account
    accounts[2] || "0x0000000000000000000000000000000000000002", // Third account
  ].filter((addr) => addr !== "0x0000000000000000000000000000000000000000"); // Filter out zero addresses

  const threshold = 2n; // Require 2 out of 3 signatures

  const multisig = m.contract("MultiSigV1", [signers, threshold]);

  return { multisig };
});
