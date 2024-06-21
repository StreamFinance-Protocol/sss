// eth_key.js
const { ethers } = require("ethers");

// Generate a random Ethereum wallet
const wallet = ethers.Wallet.createRandom();

// Output the private key and public key
console.log(wallet.privateKey);
console.log(wallet.address);

//console.log(`Recovery Seed (Mnemonic): ${wallet.mnemonic.phrase}`);
