package kademlia

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"math/big"
	"sort"
	"sync"
)

const (
	// Alpha is the number of parallel lookups
	Alpha = 3
)

// xorDistance calculates the XOR distance between two node IDs
func xorDistance(a, b []byte) *big.Int {
	if len(a) != len(b) {
		return big.NewInt(0)
	}

	xor := make([]byte, len(a))
	for i := 0; i < len(a); i++ {
		xor[i] = a[i] ^ b[i]
	}

	distance := new(big.Int)
	distance.SetBytes(xor)
	return distance
}

// contactWithDistance wraps a contact with its distance to target
type contactWithDistance struct {
	contact  *Contact
	distance *big.Int
}

// IterativeFindNode performs iterative node lookup to find k closest nodes to targetID
func (r *Router) IterativeFindNode(ctx context.Context, targetID []byte, k int) ([]*Contact, error) {
	// 1. Get initial candidates from local routing table
	log.Printf("[Lookup] IterativeFindNode: searching for target %x with k=%d", targetID, k)
	shortlist, err := r.FindNearbyNodes(targetID, k)
	if err != nil {
		log.Printf("[Lookup] FindNearbyNodes returned error: %v", err)
		return nil, fmt.Errorf("no initial nodes in routing table: %w", err)
	}
	if len(shortlist) == 0 {
		log.Printf("[Lookup] FindNearbyNodes returned empty list")
		return nil, fmt.Errorf("no initial nodes in routing table")
	}

	log.Printf("[Lookup] Starting iterative lookup for target %x with %d initial nodes", targetID, len(shortlist))

	// Track queried nodes
	queried := make(map[string]bool)
	queriedMu := sync.Mutex{}

	// Helper to check if node was queried
	wasQueried := func(id []byte) bool {
		queriedMu.Lock()
		defer queriedMu.Unlock()
		return queried[string(id)]
	}

	// Helper to mark node as queried
	markQueried := func(id []byte) {
		queriedMu.Lock()
		defer queriedMu.Unlock()
		queried[string(id)] = true
	}

	// Sort shortlist by distance (optimized to calculate distances once)
	sortByDistance := func(contacts []*Contact) {
		// Pre-calculate all distances once
		distances := make([]contactWithDistance, len(contacts))
		for i, contact := range contacts {
			distances[i] = contactWithDistance{
				contact:  contact,
				distance: xorDistance(contact.ID, targetID),
			}
		}

		// Sort using pre-calculated distances
		sort.Slice(distances, func(i, j int) bool {
			return distances[i].distance.Cmp(distances[j].distance) < 0
		})

		// Copy back to original slice
		for i, d := range distances {
			contacts[i] = d.contact
		}
	}

	sortByDistance(shortlist)

	// Iterative lookup loop
	maxRounds := 10
	for round := 0; round < maxRounds; round++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		// Find α unqueried nodes closest to target
		toQuery := []*Contact{}
		for _, contact := range shortlist {
			if len(toQuery) >= Alpha {
				break
			}
			if !wasQueried(contact.ID) && !bytes.Equal(contact.ID, r.ID()) {
				toQuery = append(toQuery, contact)
				markQueried(contact.ID)
			}
		}

		// If no more nodes to query, we're done
		if len(toQuery) == 0 {
			log.Printf("[Lookup] No more nodes to query after round %d", round)
			break
		}

		log.Printf("[Lookup] Round %d: querying %d nodes", round, len(toQuery))

		// Query nodes in parallel
		var wg sync.WaitGroup
		newNodesCh := make(chan []*Contact, len(toQuery))

		for _, contact := range toQuery {
			wg.Add(1)
			go func(c *Contact) {
				defer wg.Done()

				// Use callback pattern for async response
				err := r.SendFindNode(ctx, c.ID, targetID, func(nodes []*Contact, err error) {
					if err != nil {
						log.Printf("[Lookup] FIND_NODE to %x failed: %v", c.ID, err)
						return
					}

					log.Printf("[Lookup] FIND_NODE to %x returned %d nodes", c.ID, len(nodes))
					newNodesCh <- nodes
				})
				
				if err != nil {
					log.Printf("[Lookup] Failed to send FIND_NODE to %x: %v", c.ID, err)
				}
			}(contact)
		}

		// Wait for all queries to complete
		go func() {
			wg.Wait()
			close(newNodesCh)
		}()

		// Collect new nodes
		newNodesCount := 0
		for nodes := range newNodesCh {
			for _, node := range nodes {
				// Skip self
				if bytes.Equal(node.ID, r.ID()) {
					continue
				}

				// Check if node already in shortlist
				exists := false
				for _, existing := range shortlist {
					if bytes.Equal(existing.ID, node.ID) {
						exists = true
						break
					}
				}

				if !exists {
					shortlist = append(shortlist, node)
					newNodesCount++

					// Store new node in routing table
					r.StoreNode(node)
				}
			}
		}

		log.Printf("[Lookup] Round %d: discovered %d new nodes, shortlist now has %d nodes",
			round, newNodesCount, len(shortlist))

		// Sort shortlist by distance and keep top k*2 (to have some buffer)
		sortByDistance(shortlist)
		if len(shortlist) > k*2 {
			shortlist = shortlist[:k*2]
		}

		// Check termination condition:
		// If the k closest nodes have all been queried, we're done
		closestK := shortlist
		if len(closestK) > k {
			closestK = closestK[:k]
		}

		allQueriedAndNoCloser := true
		for _, node := range closestK {
			if !wasQueried(node.ID) {
				allQueriedAndNoCloser = false
				break
			}
		}

		if allQueriedAndNoCloser && newNodesCount == 0 {
			log.Printf("[Lookup] Terminating: k closest nodes all queried and no new closer nodes found")
			break
		}
	}

	// Return k closest nodes
	sortByDistance(shortlist)
	if len(shortlist) > k {
		shortlist = shortlist[:k]
	}

	log.Printf("[Lookup] Completed: returning %d closest nodes", len(shortlist))
	return shortlist, nil
}

// BootstrapNode joins the network by connecting to bootstrap nodes
func (r *Router) Bootstrap(ctx context.Context, bootstrapNodes []*Contact) error {
	if len(bootstrapNodes) == 0 {
		return fmt.Errorf("no bootstrap nodes provided")
	}

	log.Printf("[Bootstrap] Starting with %d bootstrap nodes", len(bootstrapNodes))

	// 1. Connect to bootstrap nodes (they will be automatically stored in routing table)
	for _, node := range bootstrapNodes {
		if err := r.DialNode(node); err != nil {
			log.Printf("[Bootstrap] Failed to dial node %x: %v", node.ID, err)
			continue
		}
	}

	// 3. Perform iterative lookup for our own ID to populate routing table
	log.Printf("[Bootstrap] Performing self-lookup to populate routing table")
	nodes, err := r.IterativeFindNode(ctx, r.ID(), r.kBucketCount)
	if err != nil {
		return fmt.Errorf("self-lookup failed: %w", err)
	}

	log.Printf("[Bootstrap] Self-lookup completed, found %d nodes", len(nodes))

	// 4. Store discovered nodes
	for _, node := range nodes {
		r.StoreNode(node)
	}

	log.Printf("[Bootstrap] Bootstrap completed successfully")
	return nil
}

// LookupNode finds a specific node by ID
func (r *Router) LookupNode(ctx context.Context, targetID []byte) (*Contact, error) {
	// First check local routing table
	if contact, err := r.FindNode(targetID); err == nil {
		return contact, nil
	}

	// Not in local table, perform iterative lookup
	nodes, err := r.IterativeFindNode(ctx, targetID, 1)
	if err != nil {
		return nil, fmt.Errorf("iterative lookup failed: %w", err)
	}

	if len(nodes) == 0 {
		return nil, fmt.Errorf("node not found")
	}

	// Check if we found the exact node
	if bytes.Equal(nodes[0].ID, targetID) {
		return nodes[0], nil
	}

	return nil, fmt.Errorf("node not found, closest is %x", nodes[0].ID)
}
