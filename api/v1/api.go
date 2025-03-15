package v1

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"

	"github.com/tom/authlite/internal/middleware"
	"github.com/tom/authlite/pkg/auth"
	"github.com/tom/authlite/pkg/oauth2"
)

// API represents the REST API for the OAuth2 provider
type API struct {
	provider      *oauth2.Provider
	oidcProvider  *oauth2.OIDCProvider
	authenticator *auth.Authenticator
}

// NewAPI creates a new API instance
func NewAPI(provider *oauth2.Provider, authenticator *auth.Authenticator) *API {
	return &API{
		provider:      provider,
		authenticator: authenticator,
	}
}

// SetOIDCProvider sets the OIDC provider for OpenID Connect support
func (api *API) SetOIDCProvider(provider *oauth2.OIDCProvider) {
	api.oidcProvider = provider
}

// RegisterRoutes registers all API routes with the given router
func (api *API) RegisterRoutes() http.Handler {
	mux := http.NewServeMux()

	// OAuth2 endpoints
	mux.HandleFunc("/oauth/authorize", api.handleAuthorize)
	mux.HandleFunc("/oauth/token", api.handleToken)

	// User authentication endpoints
	mux.HandleFunc("/login", api.handleLogin)
	mux.HandleFunc("/logout", api.handleLogout)

	// OIDC endpoints
	mux.HandleFunc("/.well-known/openid-configuration", api.handleOIDCDiscovery)
	mux.HandleFunc("/.well-known/jwks.json", api.handleJWKS)

	// Protected API endpoints
	protectedMux := http.NewServeMux()
	protectedMux.HandleFunc("/userinfo", api.handleUserInfo)

	// Apply authentication middleware to protected endpoints
	authMiddleware := middleware.RequireAuthentication(api.authenticator)
	mux.Handle("/userinfo", authMiddleware(protectedMux))

	return mux
}

// handleAuthorize handles OAuth2 authorization requests, using OIDC provider if available
func (api *API) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	if api.oidcProvider != nil {
		api.oidcProvider.HandleAuthorize(w, r)
	} else {
		api.provider.HandleAuthorize(w, r)
	}
}

// handleToken handles OAuth2 token requests, using OIDC provider if available
func (api *API) handleToken(w http.ResponseWriter, r *http.Request) {
	if api.oidcProvider != nil {
		api.oidcProvider.HandleToken(w, r)
	} else {
		api.provider.HandleToken(w, r)
	}
}

// handleOIDCDiscovery serves the OpenID Connect discovery document
func (api *API) handleOIDCDiscovery(w http.ResponseWriter, r *http.Request) {
	if api.oidcProvider == nil {
		http.Error(w, "OpenID Connect not configured", http.StatusNotFound)
		return
	}

	api.oidcProvider.HandleDiscovery(w, r)
}

// handleJWKS serves the JSON Web Key Set for OIDC
func (api *API) handleJWKS(w http.ResponseWriter, r *http.Request) {
	if api.oidcProvider == nil {
		http.Error(w, "OpenID Connect not configured", http.StatusNotFound)
		return
	}

	api.oidcProvider.HandleJWKS(w, r)
}

// handleUserInfo serves the UserInfo endpoint for OIDC
func (api *API) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	log.Printf("[API] UserInfo request received: %s %s", r.Method, r.URL.String())

	if api.oidcProvider != nil {
		api.oidcProvider.HandleUserInfo(w, r)
		return
	}

	// Fallback to standard user info if OIDC is not configured
	userID := middleware.GetUserID(r)
	log.Printf("[API] Returning user info for user ID: %s", userID)

	// In a real application, fetch user data from a user store
	userData := map[string]interface{}{
		"id":       userID,
		"username": "testuser",
		"name":     "Test User",
		"email":    "test@example.com",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(userData)
}

// handleLogin processes user login
func (api *API) handleLogin(w http.ResponseWriter, r *http.Request) {
	log.Printf("[API] Login request received: %s %s", r.Method, r.URL.String())

	if r.Method != http.MethodPost {
		log.Printf("[API] Login method not allowed: %s", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		log.Printf("[API] Login failed to parse form: %v", err)
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	log.Printf("[API] Login attempt for user: %s", username)

	// Simple user authentication (in a real app, this would use a user store)
	if username != "testuser" || password != "password" {
		log.Printf("[API] Login failed: Invalid credentials for user %s", username)
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	log.Printf("[API] Credentials verified for user: %s", username)

	// Create a session for the user
	session, err := api.authenticator.Login(w, "1") // Hard-coded user ID for demo
	if err != nil {
		log.Printf("[API] Error creating session: %v", err)
		http.Error(w, "Error creating session", http.StatusInternalServerError)
		return
	}

	log.Printf("[API] Session created successfully for user: %s, session ID: %s", username, session.ID)

	// Check for return URL from OAuth2 flow
	returnTo := r.URL.Query().Get("return_to")
	if returnTo != "" {
		log.Printf("[API] Redirecting to: %s after successful login", returnTo)

		// URL decode the returnTo if needed
		decodedURL, err := url.QueryUnescape(returnTo)
		if err != nil {
			log.Printf("[API] Warning: Failed to decode return URL: %v", err)
			// Use the original value if decoding fails
			decodedURL = returnTo
		}

		http.Redirect(w, r, decodedURL, http.StatusFound)
		return
	}

	// Respond with JSON
	log.Printf("[API] Sending JSON success response for login")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Login successful",
	})
}

// handleLogout handles user logout
func (api *API) handleLogout(w http.ResponseWriter, r *http.Request) {
	log.Printf("[API] Logout request received: %s %s", r.Method, r.URL.String())

	if err := api.authenticator.Logout(w, r); err != nil {
		log.Printf("[API] Error during logout: %v", err)
		http.Error(w, "Error during logout", http.StatusInternalServerError)
		return
	}

	log.Printf("[API] Logout successful")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Logout successful",
	})
}
