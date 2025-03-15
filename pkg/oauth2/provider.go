package oauth2

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"github.com/tom/authlite/internal/config"
)

// Provider implements the OAuth2 authorization server functionality
type Provider struct {
	config        *config.Config
	clientStore   ClientStore
	tokenStore    TokenStore
	userStore     UserStore
	authCodeStore AuthCodeStore
}

// NewProvider creates a new OAuth2 provider instance
func NewProvider(cfg *config.Config) *Provider {
	// This is a simplified implementation - in a real application, you'd inject these dependencies
	return &Provider{
		config:        cfg,
		clientStore:   NewInMemoryClientStore(),
		tokenStore:    NewInMemoryTokenStore(),
		userStore:     NewInMemoryUserStore(),
		authCodeStore: NewInMemoryAuthCodeStore(),
	}
}

// HandleAuthorize handles the OAuth2 authorization endpoint
func (p *Provider) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	log.Printf("[OAuth2] Authorization request received: %s %s", r.Method, r.URL.String())

	// Process only GET and POST requests
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		log.Printf("[OAuth2] Method not allowed: %s", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse and validate authorization request
	authReq, err := p.parseAuthorizationRequest(r)
	if err != nil {
		log.Printf("[OAuth2] Authorization request parsing failed: %v", err)
		p.renderError(w, err, http.StatusBadRequest)
		return
	}
	log.Printf("[OAuth2] Authorization request parsed successfully: client_id=%s, response_type=%s",
		authReq.ClientID, authReq.ResponseType)

	// Check if user is authenticated
	user, err := p.authenticateUser(r)
	if err != nil || user == nil {
		log.Printf("[OAuth2] User not authenticated, redirecting to login. Error: %v", err)
		// Redirect to login page with original request encoded
		http.Redirect(w, r, "/login?return_to="+r.RequestURI, http.StatusFound)
		return
	}
	log.Printf("[OAuth2] User authenticated: %s", user.ID)

	// Handle user consent if required
	if r.Method == http.MethodGet {
		log.Printf("[OAuth2] Showing consent page to user")
		// Show consent page
		p.renderConsentPage(w, authReq)
		return
	}

	// Process user consent from POST
	if err := r.ParseForm(); err != nil {
		log.Printf("[OAuth2] Failed to parse form data: %v", err)
		p.renderError(w, errors.New("invalid form data"), http.StatusBadRequest)
		return
	}

	// Check if user approved
	if r.FormValue("consent") != "approve" {
		log.Printf("[OAuth2] User denied consent")
		p.redirectWithError(w, authReq, "access_denied", "The user denied the request")
		return
	}
	log.Printf("[OAuth2] User approved consent")

	// Generate authorization code or token based on response_type
	switch authReq.ResponseType {
	case "code":
		log.Printf("[OAuth2] Handling authorization code flow")
		p.handleAuthorizationCode(w, authReq, user)
	case "token":
		log.Printf("[OAuth2] Handling implicit grant flow")
		p.handleImplicitGrant(w, authReq, user)
	default:
		log.Printf("[OAuth2] Unsupported response type: %s", authReq.ResponseType)
		p.redirectWithError(w, authReq, "unsupported_response_type", "Response type not supported")
	}
}

// HandleToken handles the OAuth2 token endpoint
func (p *Provider) HandleToken(w http.ResponseWriter, r *http.Request) {
	log.Printf("[OAuth2] Token request received: %s", r.URL.String())

	if r.Method != http.MethodPost {
		log.Printf("[OAuth2] Method not allowed: %s", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse token request
	if err := r.ParseForm(); err != nil {
		log.Printf("[OAuth2] Failed to parse form data: %v", err)
		p.tokenError(w, "invalid_request", "Could not parse form data")
		return
	}

	grantType := r.FormValue("grant_type")
	log.Printf("[OAuth2] Token request grant_type: %s", grantType)

	switch grantType {
	case "authorization_code":
		p.handleAuthorizationCodeGrant(w, r)
	case "refresh_token":
		p.handleRefreshTokenGrant(w, r)
	case "client_credentials":
		p.handleClientCredentialsGrant(w, r)
	case "password":
		p.handlePasswordGrant(w, r)
	default:
		log.Printf("[OAuth2] Unsupported grant type: %s", grantType)
		p.tokenError(w, "unsupported_grant_type", "Grant type not supported")
	}
}

// Placeholder methods to be implemented in a real application
func (p *Provider) parseAuthorizationRequest(r *http.Request) (*AuthorizationRequest, error) {
	log.Printf("[OAuth2] Parsing authorization request: %s", r.URL.String())

	if err := r.ParseForm(); err != nil {
		log.Printf("[OAuth2] Failed to parse form: %v", err)
		return nil, errors.New("invalid request format")
	}

	clientID := r.FormValue("client_id")
	if clientID == "" {
		log.Printf("[OAuth2] Missing client_id parameter")
		return nil, errors.New("client_id is required")
	}

	// Check if client exists
	client, err := p.clientStore.GetClient(clientID)
	if err != nil {
		log.Printf("[OAuth2] Client not found: %s", clientID)
		return nil, errors.New("invalid client")
	}

	responseType := r.FormValue("response_type")
	if responseType == "" {
		log.Printf("[OAuth2] Missing response_type parameter")
		return nil, errors.New("response_type is required")
	}

	// Validate redirect_uri
	redirectURI := r.FormValue("redirect_uri")
	if redirectURI == "" {
		// Use default redirect URI if defined for the client
		if len(client.RedirectURIs) > 0 {
			redirectURI = client.RedirectURIs[0]
		} else {
			log.Printf("[OAuth2] No redirect_uri provided and no default set for client")
			return nil, errors.New("redirect_uri is required")
		}
	}

	// TODO: Validate that the redirect_uri is allowed for this client

	scope := r.FormValue("scope")
	state := r.FormValue("state")

	log.Printf("[OAuth2] Authorization request parsed: client=%s, response_type=%s, redirect=%s",
		clientID, responseType, redirectURI)

	return &AuthorizationRequest{
		ClientID:     clientID,
		ResponseType: responseType,
		RedirectURI:  redirectURI,
		Scope:        scope,
		State:        state,
	}, nil
}

func (p *Provider) authenticateUser(r *http.Request) (*User, error) {
	log.Printf("[OAuth2] Authenticating user from request")

	// This is a placeholder implementation
	// In a real application, you would extract the session cookie
	// and use it to look up the authenticated user

	// For example:
	cookie, err := r.Cookie("authlite_session")
	if err != nil {
		log.Printf("[OAuth2] No session cookie found: %v", err)
		return nil, errors.New("no session cookie")
	}

	log.Printf("[OAuth2] Found session cookie: %s", cookie.Value)

	// TODO: Look up the user from the session store
	// For now, returning a dummy user for debugging
	return &User{
		ID:       "1",
		Username: "testuser",
	}, nil
}

func (p *Provider) renderConsentPage(w http.ResponseWriter, req *AuthorizationRequest) {
	// TODO: Implement
}

func (p *Provider) redirectWithError(w http.ResponseWriter, req *AuthorizationRequest, code, description string) {
	// TODO: Implement
}

func (p *Provider) handleAuthorizationCode(w http.ResponseWriter, req *AuthorizationRequest, user *User) {
	// TODO: Implement
}

func (p *Provider) handleImplicitGrant(w http.ResponseWriter, req *AuthorizationRequest, user *User) {
	// TODO: Implement
}

func (p *Provider) handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement
}

func (p *Provider) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement
}

func (p *Provider) handleClientCredentialsGrant(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement
}

func (p *Provider) handlePasswordGrant(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement
}

func (p *Provider) renderError(w http.ResponseWriter, err error, code int) {
	log.Printf("[OAuth2] Rendering error: %v (code: %d)", err, code)
	http.Error(w, err.Error(), code)
}

func (p *Provider) tokenError(w http.ResponseWriter, errorType, description string) {
	log.Printf("[OAuth2] Token error: %s - %s", errorType, description)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusBadRequest)

	response := map[string]string{
		"error":             errorType,
		"error_description": description,
	}

	json.NewEncoder(w).Encode(response)
}
