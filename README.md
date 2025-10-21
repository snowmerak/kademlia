# Kademlia DHT

A Go implementation of the Kademlia Distributed Hash Table (DHT) with secure encrypted communication, flexible key exchange mechanisms, and extensible custom RPC handlers.

## Features

### Core Functionality
- **Kademlia DHT Protocol**: Complete implementation of the Kademlia distributed hash table algorithm
- **Post-Quantum Cryptography**: MLKEM1024 (ML-KEM/Kyber) for quantum-resistant key encapsulation
- **Encrypted Communication**: All node-to-node communication is encrypted using XChaCha20-Poly1305
- **Persistent Storage**: Uses CockroachDB Pebble for efficient key-value storage
- **Flexible Hashing**: Supports multiple hash algorithms (SHA-1, BLAKE3)
- **Custom RPC Handlers**: Extensible architecture for adding custom message types

### Network Operations
- **Bootstrap**: Connect to the network through known bootstrap nodes
- **Node Lookup**: Iterative lookup to find nodes closest to a target ID
- **PING/PONG**: Built-in health check mechanism
- **FIND_NODE**: Query for k-closest nodes to a target ID

## Installation

```bash
go get github.com/snowmerak/kademlia
```

## Quick Start

### Basic Example

```go
package main

import (
    "context"
    "log"
    
    "github.com/snowmerak/kademlia"
)

func main() {
    // Create router configuration
    config := kademlia.Config{
        KeyExchanger:   &kademlia.MLKEMKeyExchanger{},
        Hasher:         &kademlia.ExtendedIDHasher{}, // BLAKE3
        StorePath:      "./data",
        KBucketCount:   8,
        ListenAddrHost: "127.0.0.1",
        ListenAddrPort: 9001,
    }

    // Create and initialize router
    router, err := kademlia.NewRouter(config)
    if err != nil {
        log.Fatal(err)
    }
    
    if err := router.Initialize(false); err != nil {
        log.Fatal(err)
    }
    defer router.Close()

    // Bootstrap to network
    ctx := context.Background()
    bootstrapNode := &kademlia.Contact{
        ID:   []byte{/* bootstrap node ID */},
        Host: "127.0.0.1",
        Port: 9000,
    }
    
    if err := router.Bootstrap(ctx, []*kademlia.Contact{bootstrapNode}); err != nil {
        log.Fatal(err)
    }
    
    log.Println("Connected to Kademlia network!")
}
```

## Architecture

### Core Components

#### Router (`router.go`)
The main entry point for Kademlia operations. Manages:
- Node ID and routing table
- Session management
- RPC handlers (built-in and custom)
- Bootstrap and lookup operations

#### Session (`session.go`)
Handles encrypted peer-to-peer connections:
- Handshake protocol with key exchange
- Message encryption/decryption
- Request/response callback management
- Connection lifecycle

#### Key Exchange (`key_exchange.go`)
Provides post-quantum cryptographic key encapsulation:
- `MLKEMKeyExchanger`: MLKEM1024 (ML-KEM/Kyber) for quantum-resistant key establishment
- Implements 3-way handshake for mutual key encapsulation
- Extensible interface for custom key exchange mechanisms

#### Hashing (`hashed_id.go`)
Node ID generation and distance calculation:
- `LegacyIDHasher`: SHA-1 based (160-bit node IDs)
- `ExtendedIDHasher`: BLAKE3 based (256-bit node IDs, recommended)
- XOR distance metric for Kademlia

#### Storage (`store.go`)
Persistent key-value storage using Pebble:
- Node ID and key pair persistence
- Routing table bucket storage with optimized serialization
- Per-bucket locking for improved concurrency
- Contact-based bucket structure (removed legacy key-value pairs)

### Network Protocol

#### MLKEM Handshake (3-way)
```
Client                                    Server
  |                                          |
  |--- Step 1: Encapsulation Key ---------->|
  |    (NodeID, EncapKey, Port)              |
  |                                          |
  |                                     Encapsulate
  |                                     with client's key
  |                                          |
  |<-- Step 2: Encap Key + Cipher Text ------|
  |    (NodeID, EncapKey, CipherText, Port)  |
  |                                          |
Encapsulate with                             |
server's key                                 |
Decapsulate server's                         |
cipher text                                  |
  |                                          |
  |--- Step 3: Client Cipher Text --------->|
  |    (NodeID, CipherText, Port)            |
  |                                          |
  |                                     Decapsulate
  |                                     client's cipher text
  |                                          |
XOR both shared secrets          XOR both shared secrets
  |                                          |
```

Both client and server:
1. Encapsulate with peer's encapsulation key → generate cipher text + shared secret
2. Decapsulate peer's cipher text → obtain peer's shared secret
3. XOR both shared secrets → final session key

#### Message Format
All messages after handshake are encrypted:

**Built-in RPC (PING, FIND_NODE)**:
```
[4-byte RPC type][Protobuf payload with MessageID]
```

**Custom RPC**:
```
[4-byte RPC type][16-byte UUID messageID][Custom payload]
```

## Custom RPC Handlers

The library supports extensible custom RPC handlers for application-specific protocols.

### Implementing a Custom Handler

```go
package main

import (
    "encoding/binary"
    "log"
    
    "github.com/snowmerak/kademlia"
)

const (
    // Custom RPC types must be > 2 (1=PING, 2=FIND_NODE are reserved)
    RPCTypeCustomEcho uint32 = 100
)

// Create handler function
func createEchoHandler() kademlia.RPCHandler {
    return func(sess *kademlia.Session, payload []byte) ([]byte, error) {
        log.Printf("ECHO from %x: %s", sess.RemoteID(), string(payload))
        
        // Echo back the payload
        response := make([]byte, 4+len(payload))
        binary.BigEndian.PutUint32(response[:4], RPCTypeCustomEcho)
        copy(response[4:], payload)
        
        return response, nil
    }
}

func main() {
    // ... create router ...
    
    // Register custom handler
    if err := router.RegisterHandler(RPCTypeCustomEcho, createEchoHandler()); err != nil {
        log.Fatal(err)
    }
    
    // Send custom RPC
    ctx := context.Background()
    err = router.SendCustomRPC(
        ctx,
        targetNodeID,
        RPCTypeCustomEcho,
        []byte("Hello!"),
        func(data []byte, err error) {
            if err != nil {
                log.Printf("Error: %v", err)
                return
            }
            
            rpcType := binary.BigEndian.Uint32(data[:4])
            payload := data[4:]
            log.Printf("Response (type=%d): %s", rpcType, string(payload))
        },
    )
    
    // Unregister when done
    router.UnregisterHandler(RPCTypeCustomEcho)
}
```

### Custom Handler Rules
- RPC type must be `> 2` (1 and 2 are reserved for PING and FIND_NODE)
- Handler receives payload without RPC type and messageID (automatically handled)
- Response must include 4-byte RPC type prefix
- MessageID is automatically added to requests and matched to callbacks

## API Reference

### Router Methods

#### Network Operations
```go
// Bootstrap to network
Bootstrap(ctx context.Context, contacts []*Contact) error

// Perform iterative node lookup
IterativeFindNode(ctx context.Context, target []byte, k int) ([]*Contact, error)

// Send PING to node
SendPing(ctx context.Context, targetID []byte, callback func([]byte, error)) error

// Send FIND_NODE request
SendFindNode(ctx context.Context, targetID []byte, target []byte, callback func([]byte, error)) error
```

#### Custom RPC
```go
// Register custom handler
RegisterHandler(rpcType uint32, handler RPCHandler) error

// Unregister custom handler
UnregisterHandler(rpcType uint32)

// Check if handler exists
HasHandler(rpcType uint32) bool

// Send custom RPC
SendCustomRPC(ctx context.Context, targetID []byte, rpcType uint32, payload []byte, callback func([]byte, error)) error
```

#### Session Management
```go
// Get active session
GetSession(nodeID []byte) (*Session, bool)

// Connect to node
Connect(ctx context.Context, contact *Contact) (*Session, error)
```

#### Routing Table
```go
// Find node in routing table
FindNode(nodeID []byte) (*Contact, error)

// Find nearby nodes
FindNearbyNodes(target []byte, k int) ([]*Contact, error)

// Get all contacts
GetAllContacts() []*Contact
```

## Configuration

### Router Config
```go
type Config struct {
    KeyExchanger   KeyExchanger  // MLKEMKeyExchanger or custom
    Hasher         IDHasher      // LegacyIDHasher or ExtendedIDHasher
    StorePath      string        // Path for Pebble database
    KBucketCount   int           // Number of k-buckets (typically 8)
    ListenAddrHost string        // Listen address
    ListenAddrPort int           // Listen port
}
```

### Key Exchange Implementations
- `MLKEMKeyExchanger`: Uses MLKEM1024 (ML-KEM/Kyber) for post-quantum key encapsulation (default)
- Implements 3-way handshake for mutual authentication and key establishment
- Implement `KeyExchanger` interface for custom algorithms

### Hashing Implementations
- `LegacyIDHasher`: SHA-1 based node IDs (160-bit, 160 buckets)
- `ExtendedIDHasher`: BLAKE3 based node IDs (256-bit, 256 buckets, faster, recommended)
- Implement `IDHasher` interface for custom hash functions

## Examples

See the `example/` directory for complete examples:

### Run Basic Example
```bash
cd example
go run .
```

This demonstrates:
- Creating a 3-node network
- Bootstrap process
- PING/PONG
- Routing table queries
- Custom ECHO handler

### Run Custom Handler Example
```bash
cd example
go run . custom
```

Focused demonstration of custom RPC handler system.

## Project Structure

```
kademlia/
├── router.go              # Main router and routing table
├── session.go             # Encrypted session management
├── key_exchange.go        # Key exchange mechanisms
├── hashed_id.go          # Node ID hashing and distance
├── lookup.go             # Iterative lookup algorithms
├── rpc_handler.go        # RPC message routing
├── rpc_client.go         # RPC client functions
├── store.go              # Persistent storage
├── contact.go            # Contact structure
├── encryptio.go          # Encryption primitives
├── concurrent_map.go     # Thread-safe map
├── rpc/                  # Protocol buffer definitions
│   ├── rpc.proto
│   └── rpc.pb.go
└── example/              # Example programs
    ├── main.go
    └── custom_handler_example.go
```

## Dependencies

- `github.com/cockroachdb/pebble` - Key-value storage
- `crypto/mlkem` - Post-quantum MLKEM1024 (ML-KEM/Kyber) key encapsulation
- `golang.org/x/crypto` - XChaCha20-Poly1305 authenticated encryption
- `google.golang.org/protobuf` - Protocol buffers
- `lukechampine.com/blake3` - BLAKE3 hashing
- `github.com/google/uuid` - UUID generation

## Protocol Details

### Routing Table
- Each node maintains a routing table with k-buckets
- Each bucket contains up to k contacts
- Buckets are organized by XOR distance
- Intelligent eviction policy: unresponsive nodes are pinged before eviction
- Per-bucket locking ensures thread-safe concurrent operations
- Contacts stored directly in bucket structure (optimized serialization)

### Lookup Algorithm
1. Start with k closest known nodes
2. Query α nodes in parallel (α = 3)
3. Add returned nodes to shortlist
4. Repeat until k closest nodes queried
5. Return k closest nodes found

### Security
- **Post-Quantum Cryptography**: MLKEM1024 (ML-KEM/Kyber) for quantum-resistant key exchange
- **Authenticated Encryption**: XChaCha20-Poly1305 for all session data
- **3-Way Handshake**: Mutual key encapsulation ensures both parties contribute to session key
- **Unique Session Keys**: XOR combination of bidirectional shared secrets
- **Nonce Management**: Prevents replay attacks
- **Secure Logging**: Cryptographic material is never logged (only connection metadata)

## Performance Considerations

- **Concurrent Operations**: Sessions handle incoming messages concurrently
- **Connection Pooling**: Active sessions are cached and reused
- **Efficient Storage**: Pebble provides fast persistent storage with optimized serialization
- **Per-Bucket Locking**: Fine-grained locking improves concurrent routing table operations
- **Configurable k**: Adjust k-bucket size based on network scale

## Changelog

### Recent Updates (October 2025)

#### v1.1.0 - Storage and Routing Table Refactoring
**Major Changes:**
- **Optimized Bucket Storage**: Simplified `Bucket` structure to store contacts directly
  - Removed redundant `SetKey`/`SetValue` separation
  - Eliminated `Count` field to prevent synchronization issues
  - Cleaner serialization/deserialization logic

- **Improved Concurrency**: Per-bucket locking mechanism
  - Replaced global routing table lock with `ConcurrentMap` of per-bucket locks
  - Significantly improved concurrent node storage performance
  - Reduced lock contention in high-traffic scenarios

- **Enhanced Node Storage**: `StoreNode()` method improvements
  - Proper bucket persistence with `SaveBucket()` calls
  - Intelligent eviction: pings oldest node before replacement
  - Better error handling and logging

- **API Simplification**: Streamlined storage interface
  - `GetBucket()`: Returns complete bucket structure
  - `SaveBucket()`: Persists bucket changes
  - `LockBucket()`: Provides bucket-level locking
  - Removed: `AddNodeToBucket()`, `GetNodeFromBucket()`, `GetAllNodesInBucket()`, `RemoveNodeFromBucket()`

**Performance Impact:**
- ~30% reduction in code complexity (80 lines removed)
- Improved concurrent operations with per-bucket locking
- Reduced memory allocations from simplified data structures
- Eliminated redundant serialization/deserialization operations

**Breaking Changes:**
- Storage format changed: existing databases need migration
- Internal storage APIs modified (public Router API unchanged)

## License

See [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## References

- [Kademlia: A Peer-to-peer Information System Based on the XOR Metric](https://pdos.csail.mit.edu/~petar/papers/maymounkov-kademlia-lncs.pdf)
- [ML-KEM (FIPS 203): Module-Lattice-Based Key-Encapsulation Mechanism](https://csrc.nist.gov/pubs/fips/203/final)
- [Kyber: A CCA-secure module-lattice-based KEM](https://pq-crystals.org/kyber/)
- [XChaCha20-Poly1305](https://tools.ietf.org/html/draft-irtf-cfrg-xchacha)
