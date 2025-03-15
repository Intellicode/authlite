package oauth2

import (
	"errors"
	"sync"
	"time"
)

// InMemoryTokenStore implements TokenStore interface using in-memory storage
type InMemoryTokenStore struct {
	accessTokens  map[string]*Token
	refreshTokens map[string]*Token
	mutex         sync.RWMutex
}

// NewInMemoryTokenStore creates a new in-memory token store
func NewInMemoryTokenStore() *InMemoryTokenStore {
	return &InMemoryTokenStore{
		accessTokens:  make(map[string]*Token),
		refreshTokens: make(map[string]*Token),
	}
}

// SaveToken saves a token to the store
func (s *InMemoryTokenStore) SaveToken(token *Token) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.accessTokens[token.AccessToken] = token
	if token.RefreshToken != "" {
		s.refreshTokens[token.RefreshToken] = token
	}

	return nil
}

// GetByAccessToken retrieves a token by access token
func (s *InMemoryTokenStore) GetByAccessToken(accessToken string) (*Token, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	token, ok := s.accessTokens[accessToken]
	if !ok {
		return nil, errors.New("token not found")
	}

	// Check if token is expired
	if time.Now().After(token.ExpiresAt) {
		return nil, errors.New("token expired")
	}

	return token, nil
}

// GetByRefreshToken retrieves a token by refresh token
func (s *InMemoryTokenStore) GetByRefreshToken(refreshToken string) (*Token, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	token, ok := s.refreshTokens[refreshToken]
	if !ok {
		return nil, errors.New("refresh token not found")
	}

	return token, nil
}

// RevokeToken revokes an access token
func (s *InMemoryTokenStore) RevokeToken(accessToken string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	token, ok := s.accessTokens[accessToken]
	if !ok {
		return errors.New("token not found")
	}

	delete(s.accessTokens, accessToken)
	if token.RefreshToken != "" {
		delete(s.refreshTokens, token.RefreshToken)
	}

	return nil
}

// InMemoryClientStore implements ClientStore interface using in-memory storage
type InMemoryClientStore struct {
	clients map[string]*Client
	mutex   sync.RWMutex
}

// NewInMemoryClientStore creates a new in-memory client store
func NewInMemoryClientStore() *InMemoryClientStore {
	store := &InMemoryClientStore{
		clients: make(map[string]*Client),
	}

	// Add a default test client
	store.clients["test_client"] = &Client{
		ID:           "test_client",
		Secret:       "test_secret",
		RedirectURIs: []string{"http://localhost:8080/callback"},
		GrantTypes:   []string{"authorization_code", "refresh_token", "client_credentials"},
		Scopes:       []string{"read", "write"},
		Public:       false,
	}

	return store
}

// GetClient retrieves a client by ID
func (s *InMemoryClientStore) GetClient(id string) (*Client, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	client, ok := s.clients[id]
	if !ok {
		return nil, errors.New("client not found")
	}

	return client, nil
}

// ValidateClient validates a client's ID and secret
func (s *InMemoryClientStore) ValidateClient(id, secret string) (*Client, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	client, ok := s.clients[id]
	if !ok {
		return nil, errors.New("client not found")
	}

	if !client.Public && client.Secret != secret {
		return nil, errors.New("invalid client secret")
	}

	return client, nil
}

// InMemoryUserStore implements UserStore interface using in-memory storage
type InMemoryUserStore struct {
	users map[string]*User
	mutex sync.RWMutex
}

// NewInMemoryUserStore creates a new in-memory user store
func NewInMemoryUserStore() *InMemoryUserStore {
	store := &InMemoryUserStore{
		users: make(map[string]*User),
	}

	// Add a default test user
	store.users["1"] = &User{
		ID:       "1",
		Username: "testuser",
		Password: "password", // In a real application, this would be hashed
		Name:     "Test User",
		Email:    "test@example.com",
	}

	return store
}

// GetUser retrieves a user by ID
func (s *InMemoryUserStore) GetUser(id string) (*User, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	user, ok := s.users[id]
	if !ok {
		return nil, errors.New("user not found")
	}

	return user, nil
}

// AuthenticateUser authenticates a user by username and password
func (s *InMemoryUserStore) AuthenticateUser(username, password string) (*User, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	// In a real application, you'd use a more efficient lookup
	for _, user := range s.users {
		if user.Username == username && user.Password == password {
			return user, nil
		}
	}

	return nil, errors.New("invalid credentials")
}

// InMemoryAuthCodeStore implements AuthCodeStore interface using in-memory storage
type InMemoryAuthCodeStore struct {
	codes map[string]*AuthorizationCode
	mutex sync.RWMutex
}

// NewInMemoryAuthCodeStore creates a new in-memory authorization code store
func NewInMemoryAuthCodeStore() *InMemoryAuthCodeStore {
	return &InMemoryAuthCodeStore{
		codes: make(map[string]*AuthorizationCode),
	}
}

// SaveCode saves an authorization code
func (s *InMemoryAuthCodeStore) SaveCode(code *AuthorizationCode) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.codes[code.Code] = code
	return nil
}

// GetCode retrieves an authorization code
func (s *InMemoryAuthCodeStore) GetCode(code string) (*AuthorizationCode, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	authCode, ok := s.codes[code]
	if !ok {
		return nil, errors.New("code not found")
	}

	// Check if code is expired
	if time.Now().After(authCode.ExpiresAt) {
		return nil, errors.New("code expired")
	}

	return authCode, nil
}

// RemoveCode removes an authorization code
func (s *InMemoryAuthCodeStore) RemoveCode(code string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if _, ok := s.codes[code]; !ok {
		return errors.New("code not found")
	}

	delete(s.codes, code)
	return nil
}
