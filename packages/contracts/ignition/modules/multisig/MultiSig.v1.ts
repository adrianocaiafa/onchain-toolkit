import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

export default buildModule("MultiSigV1Module", (m) => {
  // Define signer addresses
  // IMPORTANT: Replace these with your actual signer addresses before deploying
  // For production, use addresses from different wallets/keys for security
  const signers = [
    "0x0000000000000000000000000000000000000001", // Signer 1 - REPLACE THIS
    "0x0000000000000000000000000000000000000002", // Signer 2 - REPLACE THIS
    "0x0000000000000000000000000000000000000003", // Signer 3 - REPLACE THIS
  ];

  const threshold = 2n; // Require 2 out of 3 signatures

  const multisig = m.contract("MultiSigV1", [signers, threshold]);

  return { multisig };
});