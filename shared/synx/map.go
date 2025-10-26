package synx

import "sync"

type Map[K comparable, V any] struct {
	m *sync.Map
}

func NewMap[K comparable, V any]() *Map[K, V] {
	return &Map[K, V]{
		m: &sync.Map{},
	}
}

func (sm *Map[K, V]) Load(key K) (V, bool) {
	value, ok := sm.m.Load(key)
	if !ok {
		var zero V
		return zero, false
	}

	v, ok := value.(V)
	return v, ok
}

func (sm *Map[K, V]) Store(key K, value V) {
	sm.m.Store(key, value)
}

func (sm *Map[K, V]) Delete(key K) {
	sm.m.Delete(key)
}

func (sm *Map[K, V]) Range(f func(key K, value V) bool) {
	sm.m.Range(func(k, v any) bool {
		key, ok1 := k.(K)
		value, ok2 := v.(V)
		if !ok1 || !ok2 {
			return false
		}
		return f(key, value)
	})
}

func (sm *Map[K, V]) LoadOrStore(key K, value V) (V, bool) {
	actual, loaded := sm.m.LoadOrStore(key, value)
	if loaded {
		v, ok := actual.(V)
		if !ok {
			sm.m.Store(key, value)
			return value, false
		}
		return v, true
	}
	return value, false
}

func (sm *Map[K, V]) LoadAndDelete(key K) (V, bool) {
	value, loaded := sm.m.LoadAndDelete(key)
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

func (sm *Map[K, V]) Clear() {
	sm.m.Clear()
}
