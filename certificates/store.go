package certificates

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/cockroachdb/pebble"
	"github.com/snowmerak/satellite-network/shared/store"
)

type StoredPublicKey struct {
	previousHash []byte
	publicKey    *Public
	signatures   map[string][]byte
	createdAt    time.Time
}

func NewStoredPublicKey(pub *Public, createdAt time.Time) *StoredPublicKey {
	return &StoredPublicKey{
		publicKey:  pub,
		signatures: make(map[string][]byte),
		createdAt:  createdAt,
	}
}

func (sp *StoredPublicKey) SetPreviousHash(hash []byte) {
	sp.previousHash = hash
}

func (sp *StoredPublicKey) GetPreviousHash() []byte {
	h := make([]byte, len(sp.previousHash))
	copy(h, sp.previousHash)
	return h
}

func (sp *StoredPublicKey) GetCreatedAt() time.Time {
	return sp.createdAt
}

func (sp *StoredPublicKey) AddSignature(key string, signature []byte) (bool, error) {
	if _, exists := sp.signatures[key]; exists {
		return false, nil
	}

	sp.signatures[key] = signature
	return true, nil
}

func (sp *StoredPublicKey) GetPublicKey() *Public {
	return sp.publicKey
}

func (sp *StoredPublicKey) GetSignatures() map[string][]byte {
	return sp.signatures
}

func (sp *StoredPublicKey) MarshalBinary() ([]byte, error) {
	pubBytes, err := sp.publicKey.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	totalLen := 4 + len(pubBytes) + 4 + len(sp.previousHash)
	for key, sig := range sp.signatures {
		totalLen += 4 + len(key) + 4 + len(sig)
	}

	result := make([]byte, totalLen)
	binary.BigEndian.PutUint32(result[:4], uint32(len(pubBytes)))
	copy(result[4:4+len(pubBytes)], pubBytes)

	offset := 4 + len(pubBytes)
	binary.BigEndian.PutUint32(result[offset:offset+4], uint32(len(sp.previousHash)))
	offset += 4
	copy(result[offset:offset+len(sp.previousHash)], sp.previousHash)
	offset += len(sp.previousHash)

	keys := make([]string, 0, len(sp.signatures))
	for key := range sp.signatures {
		keys = append(keys, key)
	}
	for _, key := range keys {
		sig := sp.signatures[key]
		binary.BigEndian.PutUint32(result[offset:offset+4], uint32(len(key)))
		offset += 4
		copy(result[offset:offset+len(key)], []byte(key))
		offset += len(key)

		binary.BigEndian.PutUint32(result[offset:offset+4], uint32(len(sig)))
		offset += 4
		copy(result[offset:offset+len(sig)], sig)
		offset += len(sig)
	}

	return result, nil
}

func (sp *StoredPublicKey) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return fmt.Errorf("data too short to unmarshal StoredPublicKey")
	}

	pubLen := binary.BigEndian.Uint32(data[:4])
	if len(data) < int(4+pubLen) {
		return fmt.Errorf("data too short to unmarshal public key")
	}

	pubBytes := data[4 : 4+pubLen]
	pub := &Public{}
	if err := pub.UnmarshalBinary(pubBytes); err != nil {
		return fmt.Errorf("failed to unmarshal public key: %w", err)
	}

	sp.publicKey = pub

	offset := int(4 + pubLen)
	if len(data[offset:]) < 4 {
		return fmt.Errorf("data too short to unmarshal previous hash length")
	}
	prevHashLen := binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	if len(data[offset:]) < int(prevHashLen) {
		return fmt.Errorf("data too short to unmarshal previous hash")
	}
	sp.previousHash = make([]byte, prevHashLen)
	copy(sp.previousHash, data[offset:offset+int(prevHashLen)])
	offset += int(prevHashLen)

	sp.signatures = make(map[string][]byte)
	for offset < len(data) {
		if len(data[offset:]) < 4 {
			return fmt.Errorf("data too short to unmarshal signature key length")
		}
		keyLen := binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4

		if len(data[offset:]) < int(keyLen) {
			return fmt.Errorf("data too short to unmarshal signature key")
		}
		key := string(data[offset : offset+int(keyLen)])
		offset += int(keyLen)

		if len(data[offset:]) < 4 {
			return fmt.Errorf("data too short to unmarshal signature length")
		}
		sigLen := binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4

		if len(data[offset:]) < int(sigLen) {
			return fmt.Errorf("data too short to unmarshal signature")
		}
		sig := make([]byte, sigLen)
		copy(sig, data[offset:offset+int(sigLen)])
		offset += int(sigLen)

		sp.signatures[key] = sig
	}

	return nil
}

type Store struct {
	db *pebble.DB
}

func NewStore(store *store.Store) (*Store, error) {
	return &Store{
		db: store.GetDB(),
	}, nil
}
