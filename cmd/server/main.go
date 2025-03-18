package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"

	v1 "github.com/tom/authlite/api/v1"
	"github.com/tom/authlite/internal/config"
	"github.com/tom/authlite/pkg/auth"
	"github.com/tom/authlite/pkg/oauth2"
	"github.com/tom/authlite/pkg/storage"
)

// In-memory session store implementation for demonstration
type memorySessionStore struct {
	store *storage.MemoryStore
}

func newMemorySessionStore() *memorySessionStore {
	return &memorySessionStore{
		store: storage.NewMemoryStore(),
	}
}

func (s *memorySessionStore) SaveSession(session *auth.Session) error {
	return s.store.Set("sessions", session.ID, session)
}

func (s *memorySessionStore) GetSession(id string) (*auth.Session, error) {
	val, err := s.store.Get("sessions", id)
	if err != nil {
		return nil, err
	}

	session, ok := val.(*auth.Session)
	if !ok {
		return nil, fmt.Errorf("invalid session type")
	}

	return session, nil
}

func (s *memorySessionStore) DeleteSession(id string) error {
	return s.store.Delete("sessions", id)
}

// UserInfoProvider implements the auth.UserInfoProvider interface
type UserInfoProvider struct {
	store *storage.MemoryStore
}

func newUserInfoProvider() *UserInfoProvider {
	provider := &UserInfoProvider{
		store: storage.NewMemoryStore(),
	}

	// Add a test user for demonstration
	provider.store.Set("users", "1", &auth.UserInfo{
		Subject:           "1",
		Name:              "Test User",
		Email:             "test@example.com",
		EmailVerified:     true,
		PreferredUsername: "testuser",
		Picture:           "https://example.com/avatar.jpg",
	})

	return provider
}

func (p *UserInfoProvider) GetUserInfo(userID string) (*auth.UserInfo, error) {
	val, err := p.store.Get("users", userID)
	if err != nil {
		return nil, err
	}

	userInfo, ok := val.(*auth.UserInfo)
	if !ok {
		return nil, fmt.Errorf("invalid user info type")
	}

	return userInfo, nil
}

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize session store
	sessionStore := newMemorySessionStore()

	// Initialize authenticator
	authenticator := auth.NewAuthenticator(sessionStore)
	log.Println("Authenticator initialized")

	// Initialize user info provider
	userInfoProvider := newUserInfoProvider()
	authenticator.SetUserInfoProvider(userInfoProvider)
	authenticator.SetIssuer(cfg.Issuer)

	// Initialize the OAuth2 provider
	provider := oauth2.NewProvider(cfg)
	log.Println("OAuth2 provider initialized")

	// Initialize the OIDC provider
	oidcProvider := oauth2.NewOIDCProvider(provider, cfg)
	oidcProvider.SetUserInfoProvider(userInfoProvider)
	log.Println("OIDC provider initialized")

	// Load signing key if available
	keyPath := os.Getenv("OIDC_SIGNING_KEY")
	if keyPath == "" {
		keyPath = "keys/private_key.pem" // Updated to match our generated file name
	}

	if _, err := os.Stat(keyPath); err == nil {
		keyData, err := ioutil.ReadFile(keyPath)
		if err != nil {
			log.Printf("Warning: Failed to read signing key: %v", err)
		} else {
			if err := oidcProvider.LoadSigningKey(keyData); err != nil {
				log.Printf("Warning: Failed to load signing key: %v", err)
			} else {
				log.Println("OIDC signing key loaded successfully")
			}
		}
	} else {
		log.Printf("Warning: OIDC signing key not found at %s", keyPath)
		log.Println("OIDC ID tokens will not be available without a signing key")
	}

	// Initialize API
	api := v1.NewAPI(provider, authenticator)
	api.SetOIDCProvider(oidcProvider)

	// Register HTTP handlers
	router := api.RegisterRoutes()

	// Add static file server for demo pages
	fs := http.FileServer(http.Dir("./web/static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	// Ensure keys directory exists
	if err := os.MkdirAll(filepath.Dir(keyPath), 0755); err != nil {
		log.Printf("Warning: Failed to create keys directory: %v", err)
	}

	// Mount API routes
	http.Handle("/", router)

	// Start HTTP server
	serverAddr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	log.Printf("Starting OAuth2/OIDC server on %s", serverAddr)
	log.Printf("OIDC Issuer: %s", cfg.Issuer)
	if err := http.ListenAndServe(serverAddr, nil); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
