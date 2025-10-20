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
// RPCTypeCustomEcho is defined in main.go

// createEchoHandler is defined in main.go
func _unusedCreateEchoHandler() kademlia.RPCHandler {
	return func(sess *kademlia.Session, payload []byte) ([]byte, error) {
		log.Printf("[CustomHandler] ECHO request from %x: %s", sess.RemoteID(), string(payload))

		// Echo back the same payload
		response := make([]byte, 4+len(payload))
		binary.BigEndian.PutUint32(response[:4], RPCTypeCustomEcho)
		copy(response[4:], payload)

		return response, nil
	}
}

func customHandlerExample() {
	// Create temp directory for test
	tempDir, err := os.MkdirTemp("", "kademlia-custom-handler-")
	if err != nil {
		log.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	log.Printf("Using temp directory: %s\n", tempDir)

	// Create 2 nodes
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

	// Wait for nodes to start
	time.Sleep(500 * time.Millisecond)

	log.Println("\n=== Registering Custom Handler ===")
	
	// Register custom ECHO handler on Node1
	if err := node1.RegisterHandler(RPCTypeCustomEcho, createEchoHandler()); err != nil {
		log.Fatalf("Failed to register custom handler: %v", err)
	}
	log.Println("✓ Custom ECHO handler registered on Node1")

	// Node2 bootstrap to Node1
	log.Println("\n=== Bootstrap ===")
	ctx := context.Background()
	node1Contact := &kademlia.Contact{
		ID:   node1.ID(),
		Host: "127.0.0.1",
		Port: 9001,
	}
	if err := node2.Bootstrap(ctx, []*kademlia.Contact{node1Contact}); err != nil {
		log.Fatalf("Failed to bootstrap: %v", err)
	}
	log.Println("✓ Node2 bootstrapped to Node1")

	// Test custom RPC
	log.Println("\n=== Testing Custom ECHO RPC ===")
	
	testMessage := []byte("Hello from Node2!")
	log.Printf("Sending ECHO request: %s", string(testMessage))

	done := make(chan bool)
	err = node2.SendCustomRPC(ctx, node1.ID(), RPCTypeCustomEcho, testMessage, func(data []byte, err error) {
		if err != nil {
			log.Printf("❌ ECHO failed: %v", err)
			done <- false
			return
		}

		// Parse response
		if len(data) < 4 {
			log.Printf("❌ Invalid response: too short")
			done <- false
			return
		}

		rpcType := binary.BigEndian.Uint32(data[:4])
		payload := data[4:]

		log.Printf("✓ ECHO response received!")
		log.Printf("  RPC Type: %d", rpcType)
		log.Printf("  Payload: %s", string(payload))

		if string(payload) == string(testMessage) {
			log.Println("✓ Echo message matches!")
			done <- true
		} else {
			log.Printf("❌ Echo message mismatch: expected '%s', got '%s'", string(testMessage), string(payload))
			done <- false
		}
	})

	if err != nil {
		log.Fatalf("Failed to send custom RPC: %v", err)
	}

	// Wait for response
	select {
	case success := <-done:
		if success {
			log.Println("\n=== Custom Handler Test Passed ===")
		} else {
			log.Println("\n=== Custom Handler Test Failed ===")
			os.Exit(1)
		}
	case <-time.After(5 * time.Second):
		log.Println("\n❌ Test timeout")
		os.Exit(1)
	}

	log.Println("\n=== Unregistering Handler ===")
	node1.UnregisterHandler(RPCTypeCustomEcho)
	log.Println("✓ Custom handler unregistered")

	fmt.Println("\nPress Ctrl+C to exit or waiting 2 seconds...")
	time.Sleep(2 * time.Second)
}
