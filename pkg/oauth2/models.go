package oauth2

import (
	"time"
)

// AuthorizationRequest represents an OAuth2 authorization request
type AuthorizationRequest struct {
	ClientID     string
	RedirectURI  string
	Scope        string
	State        string
	ResponseType string
}

// TokenRequest represents an OAuth2 token request
type TokenRequest struct {
	GrantType    string
	Code         string
	RedirectURI  string
	ClientID     string
	ClientSecret string
	RefreshToken string
	Scope        string
	Username     string
	Password     string
}

// Token represents an OAuth2 token response
type Token struct {
	AccessToken  string    `json:"access_token"`
	TokenType    string    `json:"token_type"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	ExpiresIn    int       `json:"expires_in"`
	Scope        string    `json:"scope,omitempty"`
	CreatedAt    time.Time `json:"-"`
	ExpiresAt    time.Time `json:"-"`
	UserID       string    `json:"-"`
	ClientID     string    `json:"-"`
}

// AuthorizationCode represents an authorization code
type AuthorizationCode struct {
	Code        string
	ClientID    string
	RedirectURI string
	UserID      string
	Scope       string
	ExpiresAt   time.Time
}

// Client represents an OAuth2 client application
type Client struct {
	ID           string
	Secret       string
	RedirectURIs []string
	GrantTypes   []string
	Scopes       []string
	Public       bool // Public clients don't have a secret (e.g. SPA, mobile apps)
}

// User represents a resource owner (end user)
type User struct {
	ID       string
	Username string
	Password string // This would be hashed in a real application
	Name     string
	Email    string
}

// TokenStore is the interface for managing tokens
type TokenStore interface {
	SaveToken(token *Token) error
	GetByAccessToken(accessToken string) (*Token, error)
	GetByRefreshToken(refreshToken string) (*Token, error)
	RevokeToken(accessToken string) error
}

// ClientStore is the interface for managing clients
type ClientStore interface {
	GetClient(id string) (*Client, error)
	ValidateClient(id, secret string) (*Client, error)
}

// UserStore is the interface for managing users
type UserStore interface {
	GetUser(id string) (*User, error)
	AuthenticateUser(username, password string) (*User, error)
}

// AuthCodeStore is the interface for managing authorization codes
type AuthCodeStore interface {
	SaveCode(code *AuthorizationCode) error
	GetCode(code string) (*AuthorizationCode, error)
	RemoveCode(code string) error
}
