package storage

import (
	"errors"
	"fmt"
)

// StoreType represents the type of storage backend
type StoreType string

const (
	// Memory represents an in-memory store
	Memory StoreType = "memory"

	// Add more store types here as they are implemented
	// e.g. Redis StoreType = "redis"
	// e.g. SQL StoreType = "sql"
)

// Config holds configuration for the store
type Config struct {
	Type StoreType
	// Add more fields as needed for different store types
	// e.g. ConnectionString string
}

// NewStore creates a new store based on the provided configuration
func NewStore(config Config) (Store, error) {
	switch config.Type {
	case Memory:
		return NewMemoryStore(), nil
	// Add cases for other store types as they are implemented
	default:
		return nil, errors.New(fmt.Sprintf("unsupported store type: %s", config.Type))
	}
}

// DefaultConfig returns a default configuration (memory store)
func DefaultConfig() Config {
	return Config{
		Type: Memory,
	}
}
