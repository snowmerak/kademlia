package kademlia

import "sync"

type ConcurrentMap[K comparable, V any] struct {
	m sync.Map
}

func NewConcurrentMap[K comparable, V any]() *ConcurrentMap[K, V] {
	return &ConcurrentMap[K, V]{}
}

func (cm *ConcurrentMap[K, V]) Load(key K) (V, bool) {
	value, ok := cm.m.Load(key)
	if !ok {
		var zero V
		return zero, false
	}

	v, ok := value.(V)
	return v, ok
}

func (cm *ConcurrentMap[K, V]) Store(key K, value V) {
	cm.m.Store(key, value)
}

func (cm *ConcurrentMap[K, V]) Delete(key K) {
	cm.m.Delete(key)
}

func (cm *ConcurrentMap[K, V]) Swap(key K, newValue V) (oldValue V, loaded bool) {
	value, loaded := cm.m.Swap(key, newValue)
	if !loaded {
		var zero V
		return zero, false
	}

	v, ok := value.(V)
	if !ok {
		var zero V
		return zero, false
	}

	return v, true
}

func (cm *ConcurrentMap[K, V]) Range(f func(key K, value V) bool) {
	cm.m.Range(func(k, v any) bool {
		key, ok1 := k.(K)
		value, ok2 := v.(V)
		if !ok1 || !ok2 {
			return true
		}
		return f(key, value)
	})
}
