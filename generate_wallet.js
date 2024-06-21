#!/usr/bin/env node

const { ethers } = require("ethers");

// Get the private key from command-line arguments
const args = process.argv.slice(2);

if (args.length === 0) {
  console.error("Usage: generateWallet <hex-private-key>");
  process.exit(1);
}

const privateKeyHex = args[0];

// Add '0x' prefix to the private key if it doesn't already have it
const privateKey = privateKeyHex.startsWith('0x') ? privateKeyHex : `0x${privateKeyHex}`;

try {
  // Create a wallet instance from the private key
  const wallet = new ethers.Wallet(privateKey);

  // Output the private key, public key, and address
  console.log(`Private Key: ${wallet.privateKey}`);
  console.log(`Address: ${wallet.address}`);
} catch (error) {
  console.error(`Invalid private key: ${error.message}`);
  process.exit(1);
}
