package kademlia

import (
	"fmt"

	"github.com/cockroachdb/pebble"
)

type Store struct {
	store *pebble.DB
}

func NewStore(dbPath string) (*Store, error) {
	db, err := pebble.Open(dbPath, &pebble.Options{})
	if err != nil {
		return nil, fmt.Errorf("failed to open Pebble DB: %w", err)
	}

	return &Store{store: db}, nil
}

func (s *Store) Close() error {
	return s.store.Close()
}

func (s *Store) Put(key, value []byte) error {
	if err := s.store.Set(key, value, pebble.Sync); err != nil {
		return fmt.Errorf("failed to put value into store: %w", err)
	}

	return nil
}

func (s *Store) Get(key []byte) ([]byte, error) {
	value, closer, err := s.store.Get(key)
	if err != nil {
		return nil, fmt.Errorf("failed to get value from store: %w", err)
	}
	defer closer.Close()

	return value, nil
}

func (s *Store) Delete(key []byte) error {
	if err := s.store.Delete(key, pebble.Sync); err != nil {
		return fmt.Errorf("failed to delete value from store: %w", err)
	}

	return nil
}

func (s *Store) Has(key []byte) (bool, error) {
	_, _, err := s.store.Get(key)
	if err != nil {
		if err == pebble.ErrNotFound {
			return false, nil
		}
		return false, fmt.Errorf("failed to check existence of key in store: %w", err)
	}

	return true, nil
}

const privateKeyKey = "dh:private_key"

func (s *Store) SetPrivateKey(value []byte) error {
	return s.Put([]byte(privateKeyKey), value)
}

func (s *Store) GetPrivateKey() ([]byte, error) {
	return s.Get([]byte(privateKeyKey))
}

const publicKeyKey = "dh:public_key"

func (s *Store) SetPublicKey(value []byte) error {
	return s.Put([]byte(publicKeyKey), value)
}

func (s *Store) GetPublicKey() ([]byte, error) {
	return s.Get([]byte(publicKeyKey))
}

const idKey = "node:id"

func (s *Store) SetNodeID(value []byte) error {
	return s.Put([]byte(idKey), value)
}

func (s *Store) GetNodeID() ([]byte, error) {
	return s.Get([]byte(idKey))
}
