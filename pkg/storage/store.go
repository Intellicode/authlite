package storage

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
