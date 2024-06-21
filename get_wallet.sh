#!/bin/bash

# Ensure correct usage
if [ "$#" -ne 3 ]; then
  echo "Usage: $0 <shard1> <shard2> <shard3>"
  exit 1
fi

# Assign shards to variables
SHARD1=$1
SHARD2=$2
SHARD3=$3

echo "SHARD1: $SHARD1"
echo "SHARD2: $SHARD2"
echo "SHARD3: $SHARD3"

# Combine the shards using the 'combine' binary
HEX_KEY=$(./combine "$SHARD1" "$SHARD2" "$SHARD3" | grep "Restored secret:" | sed 's/Restored secret: //')

# Debug print for combined result
echo "Combined HEX_KEY: $HEX_KEY"

# Check if combine was successful
if [ $? -ne 0 ]; then
  echo "Error combining shards."
  exit 1
fi

# Ensure the hexadecimal key is not empty
if [ -z "$HEX_KEY" ]; then
  echo "Combine returned an empty string."
  exit 1
fi

# Call the Node.js script to process the hexadecimal private key
node ./generate_wallet.js "$HEX_KEY"
