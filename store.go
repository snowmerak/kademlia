package kademlia

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/cockroachdb/pebble"
)

type Store struct {
	store        *pebble.DB
	bucketLock   *sync.RWMutex
	kBucketCount int
}

func NewStore(dbPath string, kBucketCount int) (*Store, error) {
	db, err := pebble.Open(dbPath, &pebble.Options{})
	if err != nil {
		return nil, fmt.Errorf("failed to open Pebble DB: %w", err)
	}

	return &Store{
		store:        db,
		bucketLock:   &sync.RWMutex{},
		kBucketCount: kBucketCount,
	}, nil
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

type Bucket struct {
	Index    int64
	Count    int64
	SetKey   [][]byte
	SetValue [][]byte
}

func (b *Bucket) Marshal() []byte {
	buffer := bytes.NewBuffer(nil)
	temp := make([]byte, 8)

	binary.BigEndian.PutUint64(temp, uint64(b.Index))
	buffer.Write(temp)
	binary.BigEndian.PutUint64(temp, uint64(b.Count))
	buffer.Write(temp)

	count := min(len(b.SetKey), len(b.SetValue))
	binary.BigEndian.PutUint64(temp, uint64(count))
	buffer.Write(temp)

	for i := 0; i < count; i++ {
		keyLen := uint64(len(b.SetKey[i]))
		binary.BigEndian.PutUint64(temp, keyLen)
		buffer.Write(temp)
		buffer.Write(b.SetKey[i])

		valueLen := uint64(len(b.SetValue[i]))
		binary.BigEndian.PutUint64(temp, valueLen)
		buffer.Write(temp)
		buffer.Write(b.SetValue[i])
	}

	return buffer.Bytes()
}

func (b *Bucket) Unmarshal(data []byte) error {
	buffer := bytes.NewReader(data)
	temp := make([]byte, 8)

	if _, err := buffer.Read(temp); err != nil {
		return fmt.Errorf("failed to read bucket index: %w", err)
	}
	b.Index = int64(binary.BigEndian.Uint64(temp))

	if _, err := buffer.Read(temp); err != nil {
		return fmt.Errorf("failed to read bucket count: %w", err)
	}
	b.Count = int64(binary.BigEndian.Uint64(temp))

	if _, err := buffer.Read(temp); err != nil {
		return fmt.Errorf("failed to read bucket entry count: %w", err)
	}
	entryCount := int(binary.BigEndian.Uint64(temp))

	b.SetKey = make([][]byte, entryCount)
	b.SetValue = make([][]byte, entryCount)

	for i := 0; i < entryCount; i++ {
		if _, err := buffer.Read(temp); err != nil {
			return fmt.Errorf("failed to read key length: %w", err)
		}
		keyLen := int(binary.BigEndian.Uint64(temp))
		b.SetKey[i] = make([]byte, keyLen)
		if _, err := buffer.Read(b.SetKey[i]); err != nil {
			return fmt.Errorf("failed to read key data: %w", err)
		}
		if _, err := buffer.Read(temp); err != nil {
			return fmt.Errorf("failed to read value length: %w", err)
		}
		valueLen := int(binary.BigEndian.Uint64(temp))
		b.SetValue[i] = make([]byte, valueLen)
		if _, err := buffer.Read(b.SetValue[i]); err != nil {
			return fmt.Errorf("failed to read value data: %w", err)
		}
	}

	return nil
}

func (s *Store) AddNodeToBucket(bucketIndex int, nodeID []byte, data []byte) (*Contact, error) {
	s.bucketLock.Lock()
	defer s.bucketLock.Unlock()

	key := fmt.Sprintf("bucket:%d", bucketIndex)
	bucketData, err := s.Get([]byte(key))
	var bucket Bucket
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			bucket = Bucket{
				Index:    int64(bucketIndex),
				Count:    0,
				SetKey:   [][]byte{},
				SetValue: [][]byte{},
			}
		} else {
			return nil, fmt.Errorf("failed to get bucket data: %w", err)
		}
	} else {
		if err := bucket.Unmarshal(bucketData); err != nil {
			return nil, fmt.Errorf("failed to unmarshal bucket data: %w", err)
		}
	}

	bucket.SetKey = append(bucket.SetKey, nodeID)
	bucket.SetValue = append(bucket.SetValue, data)
	bucket.Count++

	removed := (*Contact)(nil)
	if bucket.Count > int64(s.kBucketCount) {
		bucket.Count = int64(s.kBucketCount)
		removedData := bucket.SetValue[0]
		removed = &Contact{}
		if err := removed.Unmarshal(removedData); err != nil {
			return nil, fmt.Errorf("failed to unmarshal removed contact: %w", err)
		}
		bucket.SetKey = bucket.SetKey[1:]
		bucket.SetValue = bucket.SetValue[1:]
	}

	if err := s.Put([]byte(key), bucket.Marshal()); err != nil {
		return nil, fmt.Errorf("failed to put updated bucket data: %w", err)
	}

	return removed, nil
}

func (s *Store) GetNodeFromBucket(bucketIndex int, nodeID []byte) ([]byte, error) {
	s.bucketLock.Lock()
	defer s.bucketLock.Unlock()

	key := fmt.Sprintf("bucket:%d", bucketIndex)
	bucketData, err := s.Get([]byte(key))
	if err != nil {
		return nil, fmt.Errorf("failed to get bucket data: %w", err)
	}

	var bucket Bucket
	if err := bucket.Unmarshal(bucketData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal bucket data: %w", err)
	}

	for i, id := range bucket.SetKey {
		if bytes.Equal(id, nodeID) {
			value := bucket.SetValue[i]

			bucket.SetKey = append(bucket.SetKey[:i], bucket.SetKey[i+1:]...)
			bucket.SetKey = append(bucket.SetKey, id)
			bucket.SetValue = append(bucket.SetValue[:i], bucket.SetValue[i+1:]...)
			bucket.SetValue = append(bucket.SetValue, value)

			return value, nil
		}
	}

	return nil, fmt.Errorf("node not found in bucket")
}

func (s *Store) GetAllNodesInBucket(bucketIndex int) ([][]byte, error) {
	s.bucketLock.Lock()
	defer s.bucketLock.Unlock()

	key := fmt.Sprintf("bucket:%d", bucketIndex)
	bucketData, err := s.Get([]byte(key))
	if err != nil {
		// If bucket doesn't exist, return empty slice (not an error)
		if errors.Is(err, pebble.ErrNotFound) {
			return [][]byte{}, nil
		}
		return nil, fmt.Errorf("failed to get bucket data: %w", err)
	}

	var bucket Bucket
	if err := bucket.Unmarshal(bucketData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal bucket data: %w", err)
	}

	return bucket.SetValue, nil
}

func (s *Store) RemoveNodeFromBucket(bucketIndex int, nodeID []byte) error {
	s.bucketLock.Lock()
	defer s.bucketLock.Unlock()

	key := fmt.Sprintf("bucket:%d", bucketIndex)
	bucketData, err := s.Get([]byte(key))
	if err != nil {
		return fmt.Errorf("failed to get bucket data: %w", err)
	}

	var bucket Bucket
	if err := bucket.Unmarshal(bucketData); err != nil {
		return fmt.Errorf("failed to unmarshal bucket data: %w", err)
	}

	for i, id := range bucket.SetKey {
		if bytes.Equal(id, nodeID) {
			bucket.SetKey = append(bucket.SetKey[:i], bucket.SetKey[i+1:]...)
			bucket.SetValue = append(bucket.SetValue[:i], bucket.SetValue[i+1:]...)
			bucket.Count--
			break
		}
	}

	if err := s.Put([]byte(key), bucket.Marshal()); err != nil {
		return fmt.Errorf("failed to put updated bucket data: %w", err)
	}

	return nil
}
