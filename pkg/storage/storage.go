package storage

import (
	"errors"
	"sync"
)

// Store defines the basic operations for a storage backend
type Store interface {
	// Get retrieves a value by key
	Get(collection, key string) (interface{}, error)

	// Set stores a value with the specified key
	Set(collection, key string, value interface{}) error

	// Delete removes a value by key
	Delete(collection, key string) error

	// List returns all keys in a collection
	List(collection string) ([]string, error)
}

// MemoryStore implements Store using an in-memory map
type MemoryStore struct {
	data  map[string]map[string]interface{}
	mutex sync.RWMutex
}

// NewMemoryStore creates a new in-memory store
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		data: make(map[string]map[string]interface{}),
	}
}

// Get retrieves a value by key
func (s *MemoryStore) Get(collection, key string) (interface{}, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	if coll, ok := s.data[collection]; ok {
		if val, ok := coll[key]; ok {
			return val, nil
		}
	}

	return nil, errors.New("key not found")
}

// Set stores a value with the specified key
func (s *MemoryStore) Set(collection, key string, value interface{}) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if _, ok := s.data[collection]; !ok {
		s.data[collection] = make(map[string]interface{})
	}

	s.data[collection][key] = value
	return nil
}

// Delete removes a value by key
func (s *MemoryStore) Delete(collection, key string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if coll, ok := s.data[collection]; ok {
		if _, exists := coll[key]; exists {
			delete(coll, key)
			return nil
		}
	}

	return errors.New("key not found")
}

// List returns all keys in a collection
func (s *MemoryStore) List(collection string) ([]string, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	if coll, ok := s.data[collection]; ok {
		keys := make([]string, 0, len(coll))
		for key := range coll {
			keys = append(keys, key)
		}
		return keys, nil
	}

	return []string{}, nil
}
