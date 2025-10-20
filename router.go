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
