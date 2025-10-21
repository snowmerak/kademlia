package kademlia

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"time"

	"github.com/cockroachdb/pebble"
)

const (
	DefaultKBucketCount = 20
)

type Config struct {
	KeyExchanger   KeyExchanger
	Hasher         IDHasher
	StorePath      string
	KBucketCount   int
	ListenAddrHost string
	ListenAddrPort int
}

// RPCHandler is a function that handles custom RPC requests
// It receives the session, raw payload (without RPC type prefix), and returns response data (with RPC type prefix) or error
type RPCHandler func(sess *Session, payload []byte) ([]byte, error)

type Router struct {
	id           []byte
	hasher       IDHasher
	keyExchanger KeyExchanger
	store        *Store
	tcpListener  *net.TCPListener
	kBucketCount int
	listenAddr   *net.TCPAddr

	sessions *ConcurrentMap[string, *Session]

	// Custom RPC handlers
	customHandlers *ConcurrentMap[uint32, RPCHandler]
}

func NewRouter(config Config) (*Router, error) {
	strg, err := NewStore(config.StorePath, config.KBucketCount)
	if err != nil {
		return nil, fmt.Errorf("failed to create store: %w", err)
	}

	tcpAddr := &net.TCPAddr{
		IP:   net.ParseIP(config.ListenAddrHost),
		Port: config.ListenAddrPort,
	}

	tcpLis, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to start TCP listener: %w", err)
	}

	r := &Router{
		hasher:         config.Hasher,
		keyExchanger:   config.KeyExchanger,
		store:          strg,
		tcpListener:    tcpLis,
		kBucketCount:   config.KBucketCount,
		listenAddr:     tcpAddr,
		sessions:       NewConcurrentMap[string, *Session](),
		customHandlers: NewConcurrentMap[uint32, RPCHandler](),
	}

	go func() {
		for {
			conn, err := tcpLis.AcceptTCP()
			if err != nil {
				continue
			}

			sess, err := AcceptSession(conn, r)
			if err != nil {
				conn.Close()
				continue
			}

			old, swapped := r.sessions.Swap(string(sess.RemoteID()), sess)
			if swapped && old != nil {
				old.Close()
			}

			// Start handling incoming RPC messages
			go sess.HandleIncoming()

			go func() {
				h, _, err := net.SplitHostPort(sess.RemoteAddr())
				if err != nil {
					log.Printf("[Router] Failed to parse remote address %s: %v", sess.RemoteAddr(), err)
					return
				}

				c := &Contact{
					ID:        sess.RemoteID(),
					PublicKey: sess.PublicKey(),
					Host:      h,
					Port:      sess.RemoteListenPort(),
				}

				log.Printf("[Router] Storing node %x in routing table (Host: %s, Port: %d)", c.ID, c.Host, c.Port)
				if err := r.StoreNode(c); err != nil {
					log.Printf("[Router] Failed to store node %x in routing table: %v", c.ID, err)
				} else {
					log.Printf("[Router] Successfully stored node %x in routing table", c.ID)
				}
			}()
		}
	}()

	return r, nil
}

func (r *Router) Close() error {
	return r.store.Close()
}

// RegisterHandler registers a custom RPC handler for the given RPC type
// The handler will be called when a message with the specified RPC type is received
// Returns an error if the RPC type is already used by built-in handlers (1, 2)
func (r *Router) RegisterHandler(rpcType uint32, handler RPCHandler) error {
	// Check if it's a reserved RPC type
	if rpcType == 1 || rpcType == 2 {
		return fmt.Errorf("RPC type %d is reserved for built-in handlers", rpcType)
	}

	r.customHandlers.Store(rpcType, handler)
	log.Printf("[Router] Registered custom handler for RPC type %d", rpcType)
	return nil
}

// UnregisterHandler removes a custom RPC handler
func (r *Router) UnregisterHandler(rpcType uint32) {
	r.customHandlers.Delete(rpcType)
	log.Printf("[Router] Unregistered custom handler for RPC type %d", rpcType)
}

// HasHandler checks if a custom handler is registered for the given RPC type
func (r *Router) HasHandler(rpcType uint32) bool {
	_, ok := r.customHandlers.Load(rpcType)
	return ok
}

func (r *Router) Initialize(force bool) error {
	id, err := r.store.GetNodeID()
	if !force && err != nil && !errors.Is(err, pebble.ErrNotFound) {
		return fmt.Errorf("failed to get node ID from store: %w", err)
	}

	privKey, err := r.store.GetPrivateKey()
	if !force && err != nil && !errors.Is(err, pebble.ErrNotFound) {
		return fmt.Errorf("failed to get private key from store: %w", err)
	}

	pubKey, err := r.store.GetPublicKey()
	if !force && err != nil && !errors.Is(err, pebble.ErrNotFound) {
		return fmt.Errorf("failed to get public key from store: %w", err)
	}

	if id != nil && privKey != nil && pubKey != nil && !force {
		r.id = id
		return nil
	}

	priveKey, pubKey, err := r.keyExchanger.GenerateNewKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate new key pair: %w", err)
	}

	hashedID := r.hasher.Hash(pubKey)

	if err := r.store.SetNodeID(hashedID); err != nil {
		return fmt.Errorf("failed to save node ID to store: %w", err)
	}

	r.id = hashedID

	if err := r.store.SetPrivateKey(priveKey); err != nil {
		return fmt.Errorf("failed to save private key to store: %w", err)
	}

	if err := r.store.SetPublicKey(pubKey); err != nil {
		return fmt.Errorf("failed to save public key to store: %w", err)
	}

	return nil
}

func (r *Router) ID() []byte {
	id := make([]byte, len(r.id))
	copy(id, r.id)
	return id
}

func (r *Router) PublicKey() ([]byte, error) {
	pubKey, err := r.store.GetPublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get public key from store: %w", err)
	}

	return pubKey, nil
}

// EncapsulateSecret generates cipher text from peer's encapsulation key
// Used by client to create cipher text to send to server
func (r *Router) EncapsulateSecret(peerEncapsulationKey []byte) (cipherText []byte, sharedSecret []byte, err error) {
	cipherText, sharedSecret, err = r.keyExchanger.Encapsulate(peerEncapsulationKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encapsulate: %w", err)
	}

	return cipherText, sharedSecret, nil
}

// DecapsulateSecret extracts shared secret from cipher text
// Used by server to derive shared secret from received cipher text
func (r *Router) DecapsulateSecret(cipherText []byte) ([]byte, error) {
	decapsulationKey, err := r.store.GetPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get decapsulation key from store: %w", err)
	}

	sharedSecret, err := r.keyExchanger.Decapsulate(decapsulationKey, cipherText)
	if err != nil {
		return nil, fmt.Errorf("failed to decapsulate: %w", err)
	}

	return sharedSecret, nil
}

func (r *Router) FindNode(targetID []byte) (*Contact, error) {
	idx := r.hasher.GetBucketIndex(r.id, targetID)
	if idx < 0 {
		return nil, fmt.Errorf("invalid bucket index")
	}

	contacts, err := r.store.GetBucket(int64(idx))
	if err != nil {
		return nil, fmt.Errorf("failed to get bucket from store: %w", err)
	}

	if len(contacts.Contacts) == 0 {
		return nil, fmt.Errorf("no contacts in bucket")
	}

	for _, data := range contacts.Contacts {
		if bytes.Equal(data.ID, targetID) {
			return data, nil
		}
	}

	return nil, fmt.Errorf("node not found in bucket")
}

func (r *Router) StoreNode(c *Contact) error {
	idx := r.hasher.GetBucketIndex(r.id, c.ID)
	if idx < 0 {
		return fmt.Errorf("invalid bucket index")
	}

	unlock := r.store.LockBucket(int64(idx))
	defer unlock()

	contacts, err := r.store.GetBucket(int64(idx))
	if err != nil && !errors.Is(err, pebble.ErrNotFound) {
		return fmt.Errorf("failed to get bucket from store: %w", err)
	}

	if contacts == nil {
		contacts = &Bucket{
			Index:    int64(idx),
			Contacts: []*Contact{},
		}
	}

	switch {
	case len(contacts.Contacts) < r.kBucketCount:
		contacts.Contacts = append(contacts.Contacts, c)
	default:
		func() {
			first := contacts.Contacts[0]
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()

			shifted := false
			if err := r.SendPing(ctx, first.ID, func(b []byte, err error) {
				if err != nil {
					contacts.Contacts = append(contacts.Contacts[1:], c)
					shifted = true
					log.Printf("[Router] Bucket full, evicted unresponsive node %x, added node %x", first.ID, c.ID)
					return
				}
			}); err != nil {
				if !shifted {
					contacts.Contacts = append(contacts.Contacts[1:], c)
					log.Printf("[Router] Bucket full, evicted unresponsive node %x due to error, added node %x", first.ID, c.ID)
				}
				return
			}
		}()
	}

	if err := r.store.SaveBucket(contacts); err != nil {
		return fmt.Errorf("failed to save bucket to store: %w", err)
	}

	return nil
}

func (r *Router) FindNearbyNodes(targetID []byte, count int) ([]*Contact, error) {
	idx := r.hasher.GetBucketIndex(r.id, targetID)

	// If looking for ourselves (idx < 0), search all buckets
	if idx < 0 {
		log.Printf("[Router] FindNearbyNodes: target is self, searching all buckets for %d nodes", count)
		result := []*Contact{}
		maxIndex := r.hasher.MaxIDLength()
		for bucketIdx := 0; bucketIdx < maxIndex && len(result) < count; bucketIdx++ {
			contacts, err := r.store.GetBucket(int64(bucketIdx))
			if err != nil {
				return nil, fmt.Errorf("failed to get bucket from store: %w", err)
			}

			for _, data := range contacts.Contacts {
				if len(result) >= count {
					break
				}

				result = append(result, data)
			}
		}
		log.Printf("[Router] FindNearbyNodes: found %d nodes in all buckets", len(result))
		return result, nil
	}

	log.Printf("[Router] FindNearbyNodes: looking for %d nodes near target %x, starting at bucket %d", count, targetID, idx)
	originIdx := idx

	result := []*Contact{}
	for idx >= 0 && len(result) < count {
		contacts, err := r.store.GetBucket(int64(idx))
		if err != nil {
			return nil, fmt.Errorf("failed to get bucket from store: %w", err)
		}

		for _, data := range contacts.Contacts {
			if len(result) >= count {
				break
			}

			result = append(result, data)
		}

		idx--
	}

	if len(result) < count {
		idx = originIdx + 1
		maxIndex := r.hasher.MaxIDLength()
		for len(result) < count && idx < maxIndex {
			contacts, err := r.store.GetBucket(int64(idx))
			if err != nil {
				return nil, fmt.Errorf("failed to get bucket from store: %w", err)
			}

			for _, data := range contacts.Contacts {
				if len(result) >= count {
					break
				}

				result = append(result, data)
			}

			idx++
		}
	}

	log.Printf("[Router] FindNearbyNodes: found %d nodes", len(result))
	return result, nil
}

func (r *Router) DialNode(c *Contact) error {
	addr := net.JoinHostPort(c.Host, strconv.Itoa(c.Port))
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to resolve TCP address: %w", err)
	}

	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		return fmt.Errorf("failed to dial TCP address: %w", err)
	}

	sess, err := InitiateSession(conn, r)
	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to initiate session: %w", err)
	}

	old, swapped := r.sessions.Swap(string(sess.RemoteID()), sess)
	if swapped && old != nil {
		old.Close()
	}

	// Start handling incoming RPC messages
	go sess.HandleIncoming()

	// Small delay to ensure HandleIncoming is ready
	time.Sleep(10 * time.Millisecond)

	// Store the contact in routing table
	bucketIdx := r.hasher.GetBucketIndex(r.id, c.ID)
	log.Printf("[Router] Storing node %x in routing table at bucket %d (Host: %s, Port: %d)", c.ID, bucketIdx, c.Host, c.Port)
	if err := r.StoreNode(c); err != nil {
		log.Printf("[Router] Failed to store node %x in routing table: %v", c.ID, err)
	} else {
		log.Printf("[Router] Successfully stored node %x in routing table", c.ID)
	}

	return nil
}

func (r *Router) GetSession(peerID []byte) (*Session, bool) {
	sess, ok := r.sessions.Load(string(peerID))
	return sess, ok
}

// GetOrCreateSession returns existing session or creates new one by dialing the node
func (r *Router) GetOrCreateSession(nodeID []byte) (*Session, error) {
	// Try to get existing session
	if sess, ok := r.GetSession(nodeID); ok {
		if !sess.IsClosed() {
			return sess, nil
		}
		// Session is closed, remove it
		r.sessions.Delete(string(nodeID))
	}

	// No session exists, need to dial
	// Find contact info from store
	contact, err := r.FindNode(nodeID)
	if err != nil {
		return nil, fmt.Errorf("node %x not found in routing table: %w", nodeID, err)
	}

	// Dial the contact
	if err := r.DialNode(contact); err != nil {
		return nil, fmt.Errorf("failed to dial node %x: %w", nodeID, err)
	}

	// Get the newly created session
	sess, ok := r.GetSession(nodeID)
	if !ok {
		return nil, fmt.Errorf("session not found after dial")
	}

	return sess, nil
}
