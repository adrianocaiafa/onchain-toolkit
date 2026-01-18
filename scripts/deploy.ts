import { network } from "hardhat";

async function main() {
  const { ethers } = await network.connect();

  console.log("Deploying Counter contract...");

  const counter = await ethers.deployContract("Counter");

  await counter.waitForDeployment();

  const address = await counter.getAddress();
  console.log("Counter deployed at:", address);

  // Test initial value
  const initialValue = await counter.x();
  console.log("Initial value:", initialValue.toString());

  return counter;
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
