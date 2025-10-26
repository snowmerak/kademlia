package synx

import "sync"

type KeyLock struct {
	locks *Map[string, *sync.RWMutex]
}

func NewKeyLock() *KeyLock {
	return &KeyLock{
		locks: NewMap[string, *sync.RWMutex](),
	}
}

func (kl *KeyLock) getLock(key string) *sync.RWMutex {
	lock, _ := kl.locks.LoadOrStore(key, &sync.RWMutex{})
	return lock
}

func (kl *KeyLock) RLock(key string) func() {
	lock := kl.getLock(key)
	lock.RLock()
	return func() {
		lock.RUnlock()
	}
}

func (kl *KeyLock) Lock(key string) func() {
	lock := kl.getLock(key)
	lock.Lock()
	return func() {
		lock.Unlock()
	}
}

func (kl *KeyLock) Delete(key string) {
	kl.locks.Delete(key)
}
