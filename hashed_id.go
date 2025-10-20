package kademlia

import (
	"crypto/sha1"
	"encoding/binary"
	"math/bits"

	"lukechampine.com/blake3"
)

type IDHasher interface {
	Hash(data []byte) []byte
	GetBucketIndex(myID, otherID []byte) int
	MaxIDLength() int
}

type LegacyIDHasher struct{}

func (h *LegacyIDHasher) Hash(data []byte) []byte {
	hashed := sha1.Sum(data)
	return hashed[:]
}

func (h *LegacyIDHasher) GetBucketIndex(myID, otherID []byte) int {
	var distance [20]byte
	var lz int

	for i := 0; i < 20; i++ {
		distance[i] = myID[i] ^ otherID[i]
	}

	b0 := binary.BigEndian.Uint64(distance[0:8])
	if b0 != 0 {
		lz = bits.LeadingZeros64(b0)
	} else {
		b1 := binary.BigEndian.Uint64(distance[8:16])
		if b1 != 0 {
			lz = 64 + bits.LeadingZeros64(b1)
		} else {
			b2 := binary.BigEndian.Uint32(distance[16:20])
			if b2 != 0 {
				lz = 128 + bits.LeadingZeros32(b2)
			} else {
				return -1
			}
		}
	}

	bucketIndex := 159 - lz

	return bucketIndex
}

func (h *LegacyIDHasher) MaxIDLength() int {
	return 160
}

type ExtendedIDHasher struct{}

func (h *ExtendedIDHasher) Hash(data []byte) []byte {
	hashed := blake3.Sum256(data)
	return hashed[:]
}

func (h *ExtendedIDHasher) GetBucketIndex(myID, otherID []byte) int {
	var distance [32]byte
	var lz int

	for i := 0; i < 32; i++ {
		distance[i] = myID[i] ^ otherID[i]
	}

	b0 := binary.BigEndian.Uint64(distance[0:8])
	if b0 != 0 {
		lz = bits.LeadingZeros64(b0)
	} else {
		b1 := binary.BigEndian.Uint64(distance[8:16])
		if b1 != 0 {
			lz = 64 + bits.LeadingZeros64(b1)
		} else {
			b2 := binary.BigEndian.Uint64(distance[16:24])
			if b2 != 0 {
				lz = 128 + bits.LeadingZeros64(b2)
			} else {
				b3 := binary.BigEndian.Uint64(distance[24:32])
				if b3 != 0 {
					lz = 192 + bits.LeadingZeros64(b3)
				} else {
					return -1
				}
			}
		}
	}

	bucketIndex := 255 - lz

	return bucketIndex
}

func (h *ExtendedIDHasher) MaxIDLength() int {
	return 256
}
