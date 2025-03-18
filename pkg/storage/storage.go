/*
Package storage provides a flexible storage interface for authlite.

The package is designed to support multiple storage backends through a common interface.
Currently, it includes an in-memory implementation, but it's structured to be extended
with other backends like Redis, SQL databases, etc.

Architecture:
- Store interface: Defines the operations any storage backend must implement
- Provider: Factory functions to create and configure different store types
- Implementations: Concrete implementations of the Store interface

Example usage:

	// Create a store with default configuration (in-memory)
	store, err := storage.NewStore(storage.DefaultConfig())
	if err != nil {
		log.Fatalf("Failed to create store: %v", err)
	}

	// Store a value
	err = store.Set("users", "user1", userData)

	// Retrieve a value
	data, err := store.Get("users", "user1")

	// List all keys in a collection
	keys, err := store.List("users")

	// Delete a value
	err = store.Delete("users", "user1")

To add a new storage backend:
1. Create a new file with your implementation of the Store interface
2. Add a new StoreType constant in provider.go
3. Update the NewStore function to handle the new store type
*/
package storage
