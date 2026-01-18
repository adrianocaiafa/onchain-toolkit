# Onchain Toolkit

A comprehensive development toolkit for building onchain protocols, featuring modular smart contract Proofs of Concept (POCs) designed to evolve into production-ready, robust contracts.

## Overview

The **Onchain Toolkit** is a curated collection of smart contract modules and utilities that serve as building blocks for blockchain applications. Each component starts as a well-tested Proof of Concept (POC) that can be iteratively refined into production-grade contracts suitable for deployment in real-world applications.

This toolkit is designed for developers who want to:
- **Rapidly prototype** onchain functionality
- **Build composable** smart contract systems
- **Integrate seamlessly** with frontend applications
- **Leverage battle-tested** patterns and utilities

## Philosophy

We believe in building incrementally—starting with working POCs that demonstrate core concepts, then progressively enhancing them with additional features, security improvements, and optimizations. Each POC in this toolkit is:

- **Well-documented** with clear intent and usage patterns
- **Thoroughly tested** using both Solidity and TypeScript test suites
- **Modular and composable** for easy integration
- **Production-oriented** with a clear path to hardening

## Architecture

Built on **Hardhat 3** with TypeScript support, this toolkit provides:

- **Foundry-compatible** Solidity tests for gas-efficient unit testing
- **Mocha & Ethers.js** integration tests for comprehensive coverage
- **Network simulation** for local development (including OP mainnet simulation)
- **Deployment modules** using Hardhat Ignition for easy contract deployment

## Use Cases

- Building decentralized applications (dApps) with React, Vue, or other frontend frameworks
- Prototyping new DeFi protocols and mechanisms
- Creating reusable onchain utilities for multiple projects
- Learning and experimenting with smart contract development patterns
- Developing production contracts with a solid foundation

## Getting Started

### Prerequisites

- Node.js (v18 or later)
- npm or yarn

### Installation

```bash
npm install
```

### Running Tests

Run all tests (Solidity + TypeScript):
```bash
npx hardhat test
```

Run only Solidity tests:
```bash
npx hardhat test solidity
```

Run only Mocha/TypeScript tests:
```bash
npx hardhat test mocha
```

### Deployment

This project includes deployment modules using Hardhat Ignition.

To deploy to a local simulated chain:
```bash
npx hardhat ignition deploy ignition/modules/Counter.ts
```

To deploy to Sepolia, you need an account with funds. Set the `SEPOLIA_PRIVATE_KEY` configuration variable:

Using `hardhat-keystore`:
```bash
npx hardhat keystore set SEPOLIA_PRIVATE_KEY
```

Then deploy to Sepolia:
```bash
npx hardhat ignition deploy --network sepolia ignition/modules/Counter.ts
```

## Project Structure

```
onchain-toolkit/
├── contracts/          # Solidity smart contracts (POCs)
├── test/              # Test suites (Foundry + Mocha)
├── scripts/           # Deployment and utility scripts
├── ignition/          # Hardhat Ignition deployment modules
└── hardhat.config.ts  # Hardhat configuration
```

## Contributing

Each POC added to this toolkit should include:
- Clear documentation of its purpose and functionality
- Comprehensive test coverage
- Usage examples and integration patterns
- Notes on potential production enhancements

## License

ISC

---

**Note**: This toolkit is in active development. Components may change as they evolve from POCs to production-ready contracts.
