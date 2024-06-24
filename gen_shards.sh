#!/bin/bash

# Generate Ethereum keys
output=$(node eth_key.js)

# Extract the private key from the output
private_key=$(echo "$output" | sed -n '1p')

# Capture the public key from the second line of output
public_key=$(echo "$output" | sed -n '2p')

# Debug: Print the keys
#echo "Ethereum Private Key: $private_key"
echo "Ethereum Address: $public_key"

ENV_CONTENTS="HTTPS_PORT=8443
ETH_RPC=https://eth-mainnet.g.alchemy.com/v2/hh2NUpoXfMpEc2BlQbrR-978GzqVK8Vq
PORT=3000
DYDX_ADDRESS=${public_key}
DYDX_DEPOSIT_ADDRESS=0x8e8bd01b5a9eb272cc3892a2e40e64a716aa2a40
USDC_ADDRESS=0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48
DYDX_QUERY_ADDRESS=0x3FeD7bF5Bf3E738bc30fBe61B048fDcb82368545"

# Create the .env file and add the contents
echo "$ENV_CONTENTS" > "../.env"

# Print a success message
echo ".env file created with the specified contents."

# Check if private_key is not empty
if [ -z "$private_key" ]; then
    echo "Error: Private key not generated or found."
    echo "$output"  # Output the full response for debugging
    exit 1
fi

# Run the C program with the private key (strip the '0x' prefix for C compatibility)
./setup "${private_key:2}"
