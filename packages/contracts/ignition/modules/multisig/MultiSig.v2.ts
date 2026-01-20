import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

export default buildModule("MultiSigV2Module", (m) => {
  // Define signer addresses
  // IMPORTANT: Replace these with your actual signer addresses before deploying
  // For production, use addresses from different wallets/keys for security
  const signers = [
    "0x546065037dC7F3561B5a35FD6d58A86505A38533", // Signer 1
    "0x59d8Ae78da1CF666360b99de987bD49D71733054" // Signer 2
  ];

  const threshold = 2n; // Require 2 out of 2 signatures (2-of-2 multisig)

  const multisig = m.contract("MultiSigV2", [signers, threshold]);

  return { multisig };
});
  