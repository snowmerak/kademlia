package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/snowmerak/kademlia"
)

// Custom RPC type (must be > 2)
const (
	RPCTypeCustomEcho uint32 = 100
)

// createEchoHandler creates a custom ECHO handler
func createEchoHandler() kademlia.RPCHandler {
	return func(sess *kademlia.Session, payload []byte) ([]byte, error) {
		log.Printf("[CustomHandler] ECHO request from %x: %s", sess.RemoteID(), string(payload))

		// Echo back the same payload
		response := make([]byte, 4+len(payload))
		binary.BigEndian.PutUint32(response[:4], RPCTypeCustomEcho)
		copy(response[4:], payload)

		return response, nil
	}
}

func main() {
	log.SetFlags(log.Ltime | log.Lshortfile)

	// Check for command-line argument
	if len(os.Args) > 1 && os.Args[1] == "custom" {
		customHandlerExample()
		return
	}
	
	basicExample()
}

func basicExample() {

	// Create temporary directories for each node's database
	tempDir, err := os.MkdirTemp("", "kademlia-example-*")
	if err != nil {
		log.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	log.Printf("Using temp directory: %s\n", tempDir)

	// Create 3 nodes
	node1, err := createNode(filepath.Join(tempDir, "node1"), "127.0.0.1", 9001, 8)
	if err != nil {
		log.Fatalf("Failed to create node1: %v", err)
	}
	defer node1.Close()

	node2, err := createNode(filepath.Join(tempDir, "node2"), "127.0.0.1", 9002, 8)
	if err != nil {
		log.Fatalf("Failed to create node2: %v", err)
	}
	defer node2.Close()

	node3, err := createNode(filepath.Join(tempDir, "node3"), "127.0.0.1", 9003, 8)
	if err != nil {
		log.Fatalf("Failed to create node3: %v", err)
	}
	defer node3.Close()

	// Wait for nodes to start listening
	time.Sleep(500 * time.Millisecond)

	log.Println("\n=== Node Information ===")
	log.Printf("Node1 ID: %x", node1.ID())
	log.Printf("Node2 ID: %x", node2.ID())
	log.Printf("Node3 ID: %x", node3.ID())

	// Node2 and Node3 bootstrap to Node1
	log.Println("\n=== Bootstrap Phase ===")
	ctx := context.Background()

	node1Contact := &kademlia.Contact{
		ID:   node1.ID(),
		Host: "127.0.0.1",
		Port: 9001,
	}

	if err := node2.Bootstrap(ctx, []*kademlia.Contact{node1Contact}); err != nil {
		log.Fatalf("Node2 bootstrap failed: %v", err)
	}
	log.Println("Node2 bootstrapped successfully")

	if err := node3.Bootstrap(ctx, []*kademlia.Contact{node1Contact}); err != nil {
		log.Fatalf("Node3 bootstrap failed: %v", err)
	}
	log.Println("Node3 bootstrapped successfully")

	// Wait a bit for connections to stabilize
	time.Sleep(1 * time.Second)

	// Test PING between nodes
	log.Println("=== Testing PING ===")
	pongCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	pingDone := make(chan bool, 1)
	err = node2.SendPing(pongCtx, node1.ID(), func(respData []byte, err error) {
		if err != nil {
			log.Printf("PING response error: %v", err)
		} else {
			log.Printf("PING response received from Node1!")
		}
		pingDone <- true
	})

	if err != nil {
		log.Printf("Failed to send PING: %v", err)
	} else {
		log.Printf("PING sent, waiting for response...")
		select {
		case <-pingDone:
			// Response received
		case <-time.After(2 * time.Second):
			log.Printf("PING response timeout")
		}
	}

	// Test network connectivity
	log.Println("=== Testing Network Connectivity ===")

	// Just verify sessions are established
	if sess, ok := node2.GetSession(node1.ID()); ok && !sess.IsClosed() {
		log.Printf("✓ Node2 has active session with Node1")
	} else {
		log.Printf("✗ Node2 has no active session with Node1")
	}

	if sess, ok := node3.GetSession(node1.ID()); ok && !sess.IsClosed() {
		log.Printf("✓ Node3 has active session with Node1")
	} else {
		log.Printf("✗ Node3 has no active session with Node1")
	}

	// Test routing table
	log.Println("=== Testing Routing Table ===")

	// Check if nodes are in each other's routing tables
	if contact, err := node2.FindNode(node1.ID()); err == nil {
		log.Printf("✓ Node2 has Node1 in routing table: %x", contact.ID)
	} else {
		log.Printf("✗ Node2 doesn't have Node1 in routing table")
	}

	if contact, err := node3.FindNode(node1.ID()); err == nil {
		log.Printf("✓ Node3 has Node1 in routing table: %x", contact.ID)
	} else {
		log.Printf("✗ Node3 doesn't have Node1 in routing table")
	}

	// Test Custom Handler (ECHO)
	log.Println("\n=== Testing Custom ECHO Handler ===")
	
	// Register ECHO handler on Node1
	if err := node1.RegisterHandler(RPCTypeCustomEcho, createEchoHandler()); err != nil {
		log.Printf("✗ Failed to register custom handler: %v", err)
	} else {
		log.Println("✓ Custom ECHO handler registered on Node1")
		
		testMessage := []byte("Hello from Node2!")
		log.Printf("Sending ECHO request: %s", string(testMessage))

		echoDone := make(chan bool)
		err = node2.SendCustomRPC(ctx, node1.ID(), RPCTypeCustomEcho, testMessage, func(data []byte, err error) {
			if err != nil {
				log.Printf("✗ ECHO failed: %v", err)
				echoDone <- false
				return
			}

			if len(data) < 4 {
				log.Printf("✗ Invalid ECHO response: too short")
				echoDone <- false
				return
			}

			rpcType := binary.BigEndian.Uint32(data[:4])
			payload := data[4:]

			if rpcType == RPCTypeCustomEcho && string(payload) == string(testMessage) {
				log.Printf("✓ ECHO response matches! Received: %s", string(payload))
				echoDone <- true
			} else {
				log.Printf("✗ ECHO mismatch: expected '%s', got '%s'", string(testMessage), string(payload))
				echoDone <- false
			}
		})

		if err != nil {
			log.Printf("✗ Failed to send ECHO: %v", err)
		} else {
			select {
			case success := <-echoDone:
				if !success {
					log.Println("✗ ECHO test failed")
				}
			case <-time.After(2 * time.Second):
				log.Println("✗ ECHO response timeout")
			}
		}
		
		// Unregister handler
		node1.UnregisterHandler(RPCTypeCustomEcho)
		log.Println("✓ Custom handler unregistered")
	}

	log.Println("\n=== Test Complete ===")
	log.Println("Press Ctrl+C to exit or waiting 5 seconds...")
	time.Sleep(5 * time.Second)
}

func createNode(dbPath, listenHost string, listenPort, kBucketCount int) (*kademlia.Router, error) {
	// Use ExtendedIDHasher (BLAKE3)
	hasher := &kademlia.ExtendedIDHasher{}

	// Use X25519 key exchange
	keyExchanger := &kademlia.MLKEMKeyExchanger{}

	// Create router with config
	config := kademlia.Config{
		KeyExchanger:   keyExchanger,
		Hasher:         hasher,
		StorePath:      dbPath,
		KBucketCount:   kBucketCount,
		ListenAddrHost: listenHost,
		ListenAddrPort: listenPort,
	}

	router, err := kademlia.NewRouter(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create router: %w", err)
	}

	// Initialize router (generates ID and key pair if not exists)
	if err := router.Initialize(false); err != nil {
		return nil, fmt.Errorf("failed to initialize router: %w", err)
	}

	return router, nil
}
