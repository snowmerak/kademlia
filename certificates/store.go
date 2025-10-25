package certificates

import (
	"encoding/binary"
	"fmt"
)

type StoredPublicKey struct {
	publicKey  *Public
	signatures map[string][]byte
}

func NewStoredPublicKey(pub *Public) *StoredPublicKey {
	return &StoredPublicKey{
		publicKey:  pub,
		signatures: make(map[string][]byte),
	}
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

	totalLen := 4 + len(pubBytes)
	for key, sig := range sp.signatures {
		totalLen += 4 + len(key) + 4 + len(sig)
	}

	result := make([]byte, totalLen)
	binary.BigEndian.PutUint32(result[:4], uint32(len(pubBytes)))
	copy(result[4:4+len(pubBytes)], pubBytes)

	offset := 4 + len(pubBytes)
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
		return fmt.Errorf("data too short to unmarshal StoredData")
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
	sp.signatures = make(map[string][]byte)

	offset := int(4 + pubLen)
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
		sig := data[offset : offset+int(sigLen)]
		offset += int(sigLen)

		sp.signatures[key] = sig
	}

	return nil
}
