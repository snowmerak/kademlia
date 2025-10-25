# Kademlia Example

Simple example demonstrating basic Kademlia DHT operations.

## What it does

This example creates a 3-node local network:
- **Node1** (port 9001) - Bootstrap node
- **Node2** (port 9002) - Joins via Node1
- **Node3** (port 9003) - Joins via Node1

Then demonstrates:
1. **Bootstrap**: Node2 and Node3 connect to the network via Node1
2. **PING**: Node2 sends a PING to Node1 to test connectivity
3. **Iterative Lookup**: Node3 searches for nodes close to Node2's ID
4. **Specific Node Lookup**: Node3 tries to find Node2 specifically

## How to run

```bash
cd example
go mod tidy
go run main.go
```

## Expected output

You should see:
- Node IDs (BLAKE3 hashed)
- Bootstrap success messages
- PING response with public key
- List of closest nodes found during iterative lookup
- Successful lookup of Node2 from Node3

## Cleanup

Temporary databases are automatically cleaned up when the program exits.
