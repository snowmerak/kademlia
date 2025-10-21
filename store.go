package kademlia

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sync"

	"github.com/cockroachdb/pebble"
)

type Store struct {
	store        *pebble.DB
	bucketLock   *ConcurrentMap[int64, *sync.RWMutex]
	kBucketCount int
}

func NewStore(dbPath string, kBucketCount int) (*Store, error) {
	db, err := pebble.Open(dbPath, &pebble.Options{})
	if err != nil {
		return nil, fmt.Errorf("failed to open Pebble DB: %w", err)
	}

	return &Store{
		store:        db,
		bucketLock:   NewConcurrentMap[int64, *sync.RWMutex](),
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
	Contacts []*Contact
}

func (b *Bucket) Marshal() []byte {
	buffer := bytes.NewBuffer(nil)
	temp := make([]byte, 8)

	binary.BigEndian.PutUint64(temp, uint64(b.Index))
	buffer.Write(temp)
	binary.BigEndian.PutUint64(temp, uint64(b.Count))
	buffer.Write(temp)

	count := int64(len(b.Contacts))
	binary.BigEndian.PutUint64(temp, uint64(count))
	buffer.Write(temp)

	for _, contact := range b.Contacts {
		contactData := contact.Marshal()
		binary.BigEndian.PutUint64(temp, uint64(len(contactData)))
		buffer.Write(temp)
		buffer.Write(contactData)
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

	for i := 0; i < entryCount; i++ {
		if _, err := buffer.Read(temp); err != nil {
			return fmt.Errorf("failed to read contact length: %w", err)
		}
		contactLen := int(binary.BigEndian.Uint64(temp))

		contactData := make([]byte, contactLen)
		if _, err := buffer.Read(contactData); err != nil {
			return fmt.Errorf("failed to read contact data: %w", err)
		}

		contact := &Contact{}
		if err := contact.Unmarshal(contactData); err != nil {
			return fmt.Errorf("failed to unmarshal contact: %w", err)
		}

		b.Contacts = append(b.Contacts, contact)
	}

	return nil
}

func (s *Store) LockBucket(index int64) func() {
	m, _ := s.bucketLock.LoadOrStore(index, &sync.RWMutex{})
	m.Lock()

	return func() {
		m.Unlock()
	}
}

func (s *Store) GetBucket(index int64) (*Bucket, error) {
	data, err := s.Get([]byte(fmt.Sprintf("bucket:%d", index)))
	if err != nil {
		if err == pebble.ErrNotFound {
			return &Bucket{Index: index, Contacts: []*Contact{}}, nil
		}
		return nil, fmt.Errorf("failed to get bucket from store: %w", err)
	}

	bucket := &Bucket{}
	if err := bucket.Unmarshal(data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal bucket data: %w", err)
	}

	return bucket, nil
}

func (s *Store) SaveBucket(bucket *Bucket) error {
	data := bucket.Marshal()
	if err := s.Put([]byte(fmt.Sprintf("bucket:%d", bucket.Index)), data); err != nil {
		return fmt.Errorf("failed to save bucket to store: %w", err)
	}

	return nil
}
