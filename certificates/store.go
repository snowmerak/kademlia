package certificates

import (
	"encoding/binary"
	"fmt"
)

type StoredData struct {
	publicKey  *Public
	signatures map[string][]byte
}

func NewStoredData(pub *Public) *StoredData {
	return &StoredData{
		publicKey:  pub,
		signatures: make(map[string][]byte),
	}
}

func (sd *StoredData) AddSignature(key string, signature []byte) (bool, error) {
	if _, exists := sd.signatures[key]; exists {
		return false, nil
	}

	sd.signatures[key] = signature
	return true, nil
}

func (sd *StoredData) GetPublicKey() *Public {
	return sd.publicKey
}

func (sd *StoredData) GetSignatures() map[string][]byte {
	return sd.signatures
}

func (sd *StoredData) MarshalBinary() ([]byte, error) {
	pubBytes, err := sd.publicKey.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	totalLen := 4 + len(pubBytes)
	for key, sig := range sd.signatures {
		totalLen += 4 + len(key) + 4 + len(sig)
	}

	result := make([]byte, totalLen)
	binary.BigEndian.PutUint32(result[:4], uint32(len(pubBytes)))
	copy(result[4:4+len(pubBytes)], pubBytes)

	offset := 4 + len(pubBytes)
	keys := make([]string, 0, len(sd.signatures))
	for key := range sd.signatures {
		keys = append(keys, key)
	}
	for _, key := range keys {
		sig := sd.signatures[key]
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

func (sd *StoredData) UnmarshalBinary(data []byte) error {
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

	sd.publicKey = pub
	sd.signatures = make(map[string][]byte)

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

		sd.signatures[key] = sig
	}

	return nil
}
