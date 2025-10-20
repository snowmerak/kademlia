package kademlia

import "fmt"

type Config struct {
	KeyExchanger KeyExchanger
	Hasher       IDHasher
	StorePath    string
}

type Router struct {
	id           []byte
	hasher       IDHasher
	keyExchanger KeyExchanger
	store        *Store
}

func NewRouter(id []byte, config Config) (*Router, error) {
	strg, err := NewStore(config.StorePath)
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
