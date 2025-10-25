package store

import (
	"runtime"

	"github.com/cockroachdb/pebble"
	"github.com/cockroachdb/pebble/vfs"
	"github.com/shirou/gopsutil/v3/mem"
)

const StoreInMemory = ":memory:"

type Store struct {
	db *pebble.DB
}

func getTotalMemory() (uint64, error) {
	v, err := mem.VirtualMemory()
	if err != nil {
		return 0, err
	}
	return v.Total, nil
}

func NewStore(dbPath string) (*Store, error) {
	opt := &pebble.Options{}

	// Auto-optimize based on runtime info
	totalMem, err := getTotalMemory()
	if err != nil {
		// Fallback to default values if unable to get memory info
		totalMem = 256 * 1024 * 1024 // Assume 256MB
	}

	cacheSize := totalMem / 100 // 1% of total memory
	if cacheSize < 64*1024*1024 {
		cacheSize = 64 * 1024 * 1024 // Minimum 64MB
	}
	opt.Cache = pebble.NewCache(int64(cacheSize))

	memTableSize := totalMem / 400 // 0.25% of total memory
	if memTableSize < 16*1024*1024 {
		memTableSize = 16 * 1024 * 1024 // Minimum 16MB
	}
	opt.MemTableSize = memTableSize

	numCPU := runtime.NumCPU()
	if numCPU > 1 {
		numCPU -= 1
	}
	opt.MaxConcurrentCompactions = func() int { return numCPU }

	if dbPath == StoreInMemory {
		opt.FS = vfs.NewMem()
		dbPath = "/inmemdb"
	}

	db, err := pebble.Open(dbPath, opt)
	if err != nil {
		return nil, err
	}

	return &Store{db: db}, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) Put(key, value []byte) error {
	return s.db.Set(key, value, pebble.Sync)
}

func (s *Store) Get(key []byte) ([]byte, error) {
	value, closer, err := s.db.Get(key)
	if err != nil {
		return nil, err
	}
	defer closer.Close()

	return value, nil
}

func (s *Store) Delete(key []byte) error {
	return s.db.Delete(key, pebble.Sync)
}

func (s *Store) Has(key []byte) (bool, error) {
	_, _, err := s.db.Get(key)
	if err != nil {
		if err == pebble.ErrNotFound {
			return false, nil
		}
		return false, err
	}

	return true, nil
}
