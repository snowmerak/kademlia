package certificates

import (
	"encoding/base64"
	"fmt"

	"github.com/cockroachdb/pebble"
)

const (
	StoredPublicKeyPrefix = "certificates:stored_public_key:"
	LatestPublicKeySuffix = ":latest"
)

func (s *Store) StorePublicKey(spk *StoredPublicKey) error {
	id := spk.GetID()
	formatedID := base64.URLEncoding.EncodeToString(id)
	lockUnlock := s.keyLock.Lock(formatedID)
	defer lockUnlock()

	marshaledPublicKey, err := spk.publicKey.MarshalBinary()
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}

	blockID, err := spk.GetPublicKey().ID()
	if err != nil {
		return fmt.Errorf("failed to get public key ID: %w", err)
	}

	key := make([]byte, 0, len(StoredPublicKeyPrefix)+len(formatedID)+1+len(blockID))
	key = append(key, []byte(StoredPublicKeyPrefix)...)
	key = append(key, []byte(formatedID)...)
	key = append(key, ':')
	key = append(key, blockID...)
	if err := s.db.Set(key, marshaledPublicKey, nil); err != nil {
		return fmt.Errorf("failed to store public key: %w", err)
	}

	return nil
}

func (s *Store) UpdateLatestPublicKeyReference(id []byte, newBlockID []byte) error {
	formatedID := base64.URLEncoding.EncodeToString(id)
	lockUnlock := s.keyLock.Lock(formatedID)
	defer lockUnlock()

	key := make([]byte, 0, len(StoredPublicKeyPrefix)+len(formatedID)+len(LatestPublicKeySuffix))
	key = append(key, []byte(StoredPublicKeyPrefix)...)
	key = append(key, []byte(formatedID)...)
	key = append(key, []byte(LatestPublicKeySuffix)...)
	if err := s.db.Set(key, newBlockID, nil); err != nil {
		return fmt.Errorf("failed to update latest public key reference: %w", err)
	}

	return nil
}

func (s *Store) GetLatestPublicKeyReference(id []byte) ([]byte, error) {
	formatedID := base64.URLEncoding.EncodeToString(id)
	lockUnlock := s.keyLock.RLock(formatedID)
	defer lockUnlock()

	key := make([]byte, 0, len(StoredPublicKeyPrefix)+len(formatedID)+len(LatestPublicKeySuffix))
	key = append(key, []byte(StoredPublicKeyPrefix)...)
	key = append(key, []byte(formatedID)...)
	key = append(key, []byte(LatestPublicKeySuffix)...)
	value, closer, err := s.db.Get(key)
	if err != nil {
		return nil, fmt.Errorf("failed to get latest public key reference: %w", err)
	}
	defer closer.Close()

	result := make([]byte, len(value))
	copy(result, value)

	return result, nil
}

func (s *Store) GetStoredPublicKey(id, blockID []byte) (*StoredPublicKey, error) {
	formatedID := base64.URLEncoding.EncodeToString(id)
	lockUnlock := s.keyLock.RLock(formatedID)
	defer lockUnlock()

	key := make([]byte, 0, len(StoredPublicKeyPrefix)+len(formatedID)+1+len(blockID))
	key = append(key, []byte(StoredPublicKeyPrefix)...)
	key = append(key, []byte(formatedID)...)
	key = append(key, ':')
	key = append(key, blockID...)
	value, closer, err := s.db.Get(key)
	if err != nil {
		return nil, fmt.Errorf("failed to get stored public key: %w", err)
	}
	defer closer.Close()

	spk := NewEmptyStoredPublicKey()
	if err := spk.publicKey.UnmarshalBinary(value); err != nil {
		return nil, fmt.Errorf("failed to unmarshal stored public key: %w", err)
	}

	return spk, nil
}

func (s *Store) DeleteStoredPublicKey(id []byte) error {
	formatedID := base64.URLEncoding.EncodeToString(id)
	lockUnlock := s.keyLock.Lock(formatedID)
	defer lockUnlock()

	key := make([]byte, 0, len(StoredPublicKeyPrefix)+len(formatedID))
	key = append(key, []byte(StoredPublicKeyPrefix)...)
	key = append(key, []byte(formatedID)...)
	iter, err := s.db.NewIter(&pebble.IterOptions{
		LowerBound: key,
		UpperBound: append(key, 0xFF),
	})
	if err != nil {
		return fmt.Errorf("failed to create iterator for deleting stored public key: %w", err)
	}
	defer iter.Close()

	for iter.First(); iter.Valid(); iter.Next() {
		if err := s.db.Delete(iter.Key(), nil); err != nil {
			return fmt.Errorf("failed to delete stored public key: %w", err)
		}
	}

	return nil
}
