package kademlia

import (
	"crypto/sha1"

	"lukechampine.com/blake3"
)

type IDHasher interface {
	Hash(data []byte) []byte
}

type LegacyIDHasher struct{}

func (h *LegacyIDHasher) Hash(data []byte) []byte {
	hashed := sha1.Sum(data)
	return hashed[:]
}

type ExtendedIDHasher struct{}

func (h *ExtendedIDHasher) Hash(data []byte) []byte {
	hashed := blake3.Sum256(data)
	return hashed[:]
}
