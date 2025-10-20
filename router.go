package kademlia

import (
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"

	"github.com/cockroachdb/pebble"
)

type Config struct {
	KeyExchanger   KeyExchanger
	Hasher         IDHasher
	StorePath      string
	KBucketCount   int
	ListenAddrHost string
	ListenAddrPort int
}

type Router struct {
	id           []byte
	hasher       IDHasher
	keyExchanger KeyExchanger
	store        *Store
	tcpListener  *net.TCPListener
	kBucketCount int
	listenAddr   *net.TCPAddr

	sessions *ConcurrentMap[string, *Session]
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
		hasher:       config.Hasher,
		keyExchanger: config.KeyExchanger,
		store:        strg,
		tcpListener:  tcpLis,
		kBucketCount: config.KBucketCount,
		listenAddr:   tcpAddr,
		sessions:     NewConcurrentMap[string, *Session](),
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
				idx := r.hasher.GetBucketIndex(r.id, sess.RemoteID())
				if idx < 0 {
					log.Printf("[Router] Invalid bucket index for node %x", sess.RemoteID())
					return
				}

				h, p, err := net.SplitHostPort(sess.RemoteAddr())
				if err != nil {
					log.Printf("[Router] Failed to parse remote address %s: %v", sess.RemoteAddr(), err)
					return
				}
				u, err := strconv.ParseInt(p, 10, 32)
				if err != nil {
					log.Printf("[Router] Failed to parse port %s: %v", p, err)
					return
				}

				c := &Contact{
					ID:        sess.RemoteID(),
					PublicKey: sess.PublicKey(),
					Host:      h,
					Port:      int(u),
				}

				r.store.AddNodeToBucket(idx, sess.RemoteID(), c.Marshal())
			}()
		}
	}()

	return r, nil
}

func (r *Router) Close() error {
	return r.store.Close()
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

func (r *Router) Handshake(peerPublicKey []byte) ([]byte, error) {
	privKey, err := r.store.GetPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get private key from store: %w", err)
	}

	sharedSecret, err := r.keyExchanger.ComputeSharedSecret(privKey, peerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to compute shared secret: %w", err)
	}

	return sharedSecret, nil
}

func (r *Router) FindNode(targetID []byte) (*Contact, error) {
	idx := r.hasher.GetBucketIndex(r.id, targetID)
	if idx < 0 {
		return nil, fmt.Errorf("invalid bucket index")
	}

	data, err := r.store.GetNodeFromBucket(idx, targetID)
	if err != nil {
		return nil, fmt.Errorf("failed to find node in store: %w", err)
	}

	c := &Contact{}
	if err := c.Unmarshal(data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal contact: %w", err)
	}

	return c, nil
}

func (r *Router) StoreNode(c *Contact) error {
	data := c.Marshal()
	idx := r.hasher.GetBucketIndex(r.id, c.ID)
	if idx < 0 {
		return fmt.Errorf("invalid bucket index")
	}

	removed, err := r.store.AddNodeToBucket(idx, c.ID, data)
	if err != nil {
		return fmt.Errorf("failed to store contact in store: %w", err)
	}
	_ = removed

	return nil
}

func (r *Router) FindNearbyNodes(targetID []byte, count int) ([]*Contact, error) {
	idx := r.hasher.GetBucketIndex(r.id, targetID)
	if idx < 0 {
		return nil, fmt.Errorf("invalid bucket index")
	}

	log.Printf("[Router] FindNearbyNodes: looking for %d nodes near target %x, starting at bucket %d", count, targetID, idx)
	originIdx := idx

	result := []*Contact{}
	for idx >= 0 && len(result) < count {
		contactsData, err := r.store.GetAllNodesInBucket(idx)
		if err != nil {
			return nil, fmt.Errorf("failed to get nodes from bucket: %w", err)
		}

		for _, data := range contactsData {
			if len(result) >= count {
				break
			}

			c := &Contact{}
			if err := c.Unmarshal(data); err != nil {
				return nil, fmt.Errorf("failed to unmarshal contact: %w", err)
			}

			result = append(result, c)
		}

		idx--
	}

	if len(result) < count {
		idx = originIdx + 1
		maxIndex := r.hasher.MaxIDLength()
		for len(result) < count && idx < maxIndex {
			contactsData, err := r.store.GetAllNodesInBucket(idx)
			if err != nil {
				return nil, fmt.Errorf("failed to get nodes from bucket: %w", err)
			}

			for _, data := range contactsData {
				if len(result) >= count {
					break
				}

				c := &Contact{}
				if err := c.Unmarshal(data); err != nil {
					return nil, fmt.Errorf("failed to unmarshal contact: %w", err)
				}

				result = append(result, c)
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

	// Store the contact in routing table
	log.Printf("[Router] Storing node %x in routing table (Host: %s, Port: %d)", c.ID, c.Host, c.Port)
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
