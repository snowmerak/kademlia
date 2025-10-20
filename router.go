package kademlia

import (
	"fmt"
)

type Config struct {
	KeyExchanger KeyExchanger
	Hasher       IDHasher
	StorePath    string
	KBucketCount int
}

type Router struct {
	id           []byte
	hasher       IDHasher
	keyExchanger KeyExchanger
	store        *Store
}

func NewRouter(id []byte, config Config) (*Router, error) {
	strg, err := NewStore(config.StorePath, config.KBucketCount)
	if err != nil {
		return nil, fmt.Errorf("failed to create store: %w", err)
	}

	return &Router{
		id:           id,
		hasher:       config.Hasher,
		keyExchanger: config.KeyExchanger,
		store:        strg,
	}, nil
}

func (r *Router) Close() error {
	return r.store.Close()
}

func (r *Router) Initialize(force bool) error {
	id, err := r.store.GetNodeID()
	if err != nil {
		return fmt.Errorf("failed to get node ID from store: %w", err)
	}

	privKey, err := r.store.GetPrivateKey()
	if err != nil {
		return fmt.Errorf("failed to get private key from store: %w", err)
	}

	pubKey, err := r.store.GetPublicKey()
	if err != nil {
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

	if err := r.store.AddNodeToBucket(idx, c.ID, data); err != nil {
		return fmt.Errorf("failed to store contact in store: %w", err)
	}

	return nil
}

func (r *Router) FindNearbyNodes(targetID []byte, count int) ([]*Contact, error) {
	idx := r.hasher.GetBucketIndex(r.id, targetID)
	if idx < 0 {
		return nil, fmt.Errorf("invalid bucket index")
	}

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

	return result, nil
}
