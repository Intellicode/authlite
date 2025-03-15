package auth

import (
	"errors"
	"log"
	"net/http"
	"time"
)

// Session represents a user's authenticated session
type Session struct {
	ID        string
	UserID    string
	ExpiresAt time.Time
	// Adding OIDC-related claims to the session
	Claims map[string]interface{}
}

// SessionStore defines interface for session management
type SessionStore interface {
	SaveSession(session *Session) error
	GetSession(id string) (*Session, error)
	DeleteSession(id string) error
}

// UserInfo represents the standard OIDC user information
type UserInfo struct {
	Subject             string      `json:"sub"`
	Name                string      `json:"name,omitempty"`
	GivenName           string      `json:"given_name,omitempty"`
	FamilyName          string      `json:"family_name,omitempty"`
	MiddleName          string      `json:"middle_name,omitempty"`
	Nickname            string      `json:"nickname,omitempty"`
	PreferredUsername   string      `json:"preferred_username,omitempty"`
	Profile             string      `json:"profile,omitempty"`
	Picture             string      `json:"picture,omitempty"`
	Website             string      `json:"website,omitempty"`
	Email               string      `json:"email,omitempty"`
	EmailVerified       bool        `json:"email_verified,omitempty"`
	Gender              string      `json:"gender,omitempty"`
	Birthdate           string      `json:"birthdate,omitempty"`
	Zoneinfo            string      `json:"zoneinfo,omitempty"`
	Locale              string      `json:"locale,omitempty"`
	PhoneNumber         string      `json:"phone_number,omitempty"`
	PhoneNumberVerified bool        `json:"phone_number_verified,omitempty"`
	Address             interface{} `json:"address,omitempty"`
	UpdatedAt           int64       `json:"updated_at,omitempty"`
}

// UserInfoProvider defines an interface for retrieving OIDC user information
type UserInfoProvider interface {
	GetUserInfo(userID string) (*UserInfo, error)
}

// Authenticator manages user authentication
type Authenticator struct {
	sessionStore     SessionStore
	cookieName       string
	cookiePath       string
	secureCookie     bool
	userInfoProvider UserInfoProvider // Added for OIDC support
	issuer           string           // OIDC issuer URL
}

// NewAuthenticator creates a new authenticator
func NewAuthenticator(sessionStore SessionStore) *Authenticator {
	return &Authenticator{
		sessionStore: sessionStore,
		cookieName:   "authlite_session",
		cookiePath:   "/",
		secureCookie: true, // Should be determined by environment (HTTP vs HTTPS)
	}
}

// SetUserInfoProvider sets the user info provider for OIDC
func (a *Authenticator) SetUserInfoProvider(provider UserInfoProvider) {
	a.userInfoProvider = provider
}

// SetIssuer sets the OIDC issuer URL
func (a *Authenticator) SetIssuer(issuer string) {
	a.issuer = issuer
}

// Login creates a new session for the user and sets a session cookie
func (a *Authenticator) Login(w http.ResponseWriter, userID string) (*Session, error) {
	log.Printf("[Auth] Creating new login session for user: %s", userID)

	// Generate a new session
	session := &Session{
		ID:        generateRandomString(32),
		UserID:    userID,
		ExpiresAt: time.Now().Add(24 * time.Hour), // 24 hour session
		Claims:    make(map[string]interface{}),   // Initialize empty claims
	}

	// If we have a user info provider, populate OIDC claims
	if a.userInfoProvider != nil {
		userInfo, err := a.userInfoProvider.GetUserInfo(userID)
		if err == nil && userInfo != nil {
			// Add standard OIDC claims
			session.Claims["sub"] = userInfo.Subject
			if userInfo.Name != "" {
				session.Claims["name"] = userInfo.Name
			}
			if userInfo.Email != "" {
				session.Claims["email"] = userInfo.Email
				session.Claims["email_verified"] = userInfo.EmailVerified
			}
			// Add other claims as needed
		}
	}

	// Save the session
	if err := a.sessionStore.SaveSession(session); err != nil {
		log.Printf("[Auth] Failed to save session: %v", err)
		return nil, err
	}
	log.Printf("[Auth] Session saved successfully: %s", session.ID)

	// Set the cookie
	cookie := &http.Cookie{
		Name:     a.cookieName,
		Value:    session.ID,
		Path:     a.cookiePath,
		Expires:  session.ExpiresAt,
		HttpOnly: true,
		Secure:   a.secureCookie,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, cookie)
	log.Printf("[Auth] Set session cookie: %s=%s (expires: %s)",
		a.cookieName, session.ID, session.ExpiresAt.Format(time.RFC3339))

	return session, nil
}

// Logout invalidates the user's session
func (a *Authenticator) Logout(w http.ResponseWriter, r *http.Request) error {
	log.Printf("[Auth] Processing logout request")

	cookie, err := r.Cookie(a.cookieName)
	if err != nil {
		log.Printf("[Auth] No session cookie found during logout: %v", err)
		return nil // No session to logout
	}
	log.Printf("[Auth] Found session cookie for logout: %s", cookie.Value)

	// Delete the session from store
	if err := a.sessionStore.DeleteSession(cookie.Value); err != nil {
		log.Printf("[Auth] Error deleting session: %v", err)
		return err
	}
	log.Printf("[Auth] Session deleted successfully: %s", cookie.Value)

	// Invalidate the cookie
	expiredCookie := &http.Cookie{
		Name:     a.cookieName,
		Value:    "",
		Path:     a.cookiePath,
		Expires:  time.Now().Add(-1 * time.Hour),
		HttpOnly: true,
		Secure:   a.secureCookie,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, expiredCookie)
	log.Printf("[Auth] Session cookie invalidated")

	return nil
}

// GetUserSession returns the user's session from the request
func (a *Authenticator) GetUserSession(r *http.Request) (*Session, error) {
	log.Printf("[Auth] Getting user session from request")

	cookie, err := r.Cookie(a.cookieName)
	if err != nil {
		log.Printf("[Auth] No session cookie found: %v", err)
		return nil, errors.New("no session cookie")
	}
	log.Printf("[Auth] Found session cookie: %s", cookie.Value)

	session, err := a.sessionStore.GetSession(cookie.Value)
	if err != nil {
		log.Printf("[Auth] Failed to retrieve session: %v", err)
		return nil, err
	}
	log.Printf("[Auth] Session retrieved: %s for user %s", session.ID, session.UserID)

	// Check if the session is expired
	if time.Now().After(session.ExpiresAt) {
		log.Printf("[Auth] Session expired: %s (expired at %s)",
			session.ID, session.ExpiresAt.Format(time.RFC3339))
		a.sessionStore.DeleteSession(session.ID)
		return nil, errors.New("session expired")
	}

	log.Printf("[Auth] Valid session found for user: %s", session.UserID)
	return session, nil
}

// GetUserInfo retrieves OIDC user info for the authenticated user
func (a *Authenticator) GetUserInfo(userID string) (*UserInfo, error) {
	if a.userInfoProvider == nil {
		return nil, errors.New("no user info provider configured")
	}

	return a.userInfoProvider.GetUserInfo(userID)
}

// Helper function to generate a random string (simplified version)
// In a real application, use a crypto secure random generator
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)

	// In a real implementation, use crypto/rand
	for i := range result {
		result[i] = charset[time.Now().UnixNano()%int64(len(charset))]
		time.Sleep(1 * time.Nanosecond) // Ensure different values
	}

	return string(result)
}
