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

export DYDX_ADDRESS=$public_key

# Check if private_key is not empty
if [ -z "$private_key" ]; then
    echo "Error: Private key not generated or found."
    echo "$output"  # Output the full response for debugging
    exit 1
fi

# Run the C program with the private key (strip the '0x' prefix for C compatibility)
./setup "${private_key:2}"
