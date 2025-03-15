package oauth2

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/tom/authlite/internal/config"
	"github.com/tom/authlite/pkg/auth"
)

// OIDC standard scopes
const (
	ScopeOpenID  = "openid"
	ScopeProfile = "profile"
	ScopeEmail   = "email"
	ScopeAddress = "address"
	ScopePhone   = "phone"
)

// IDTokenClaims represents the claims in an OIDC ID token
type IDTokenClaims struct {
	jwt.RegisteredClaims
	Nonce            string                 `json:"nonce,omitempty"`
	AuthTime         int64                  `json:"auth_time,omitempty"`
	AccessTokenHash  string                 `json:"at_hash,omitempty"`
	CodeHash         string                 `json:"c_hash,omitempty"`
	AuthContextClass string                 `json:"acr,omitempty"`
	AuthMethods      []string               `json:"amr,omitempty"`
	UserInfo         map[string]interface{} `json:"-"`
}

// OIDCConfig holds the OpenID Connect configuration
type OIDCConfig struct {
	SigningKey      *rsa.PrivateKey // Key for signing ID tokens
	IDTokenLifetime int             // Lifetime of ID tokens in seconds
	Issuer          string          // OIDC issuer URL
	ClockSkew       int             // Allowed clock skew in seconds
	SupportedScopes []string        // Supported OIDC scopes
	JWKSCacheTTL    int             // JWKS cache time in seconds
	ACRValues       []string        // Authentication Context Class Reference values
}

// OIDCProvider extends the OAuth2 provider with OpenID Connect functionality
type OIDCProvider struct {
	*Provider
	Config           *OIDCConfig
	keyID            string
	userInfoProvider auth.UserInfoProvider
}

// NewOIDCProvider creates a new OpenID Connect provider
func NewOIDCProvider(provider *Provider, cfg *config.Config) *OIDCProvider {
	return &OIDCProvider{
		Provider: provider,
		Config: &OIDCConfig{
			IDTokenLifetime: 3600, // 1 hour by default
			Issuer:          cfg.Issuer,
			ClockSkew:       60,    // 1 minute by default
			JWKSCacheTTL:    86400, // 24 hours by default
			SupportedScopes: []string{
				ScopeOpenID,
				ScopeProfile,
				ScopeEmail,
				ScopeAddress,
				ScopePhone,
			},
		},
		keyID: "default-key-id", // In a real implementation, generate or configure this
	}
}

// SetUserInfoProvider sets the user info provider
func (p *OIDCProvider) SetUserInfoProvider(provider auth.UserInfoProvider) {
	p.userInfoProvider = provider
}

// LoadSigningKey loads an RSA private key from PEM encoded data
func (p *OIDCProvider) LoadSigningKey(pemData []byte) error {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return errors.New("failed to decode PEM block")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %v", err)
	}

	p.Config.SigningKey = privateKey
	return nil
}

// GenerateIDToken creates an OIDC ID token for a user
func (p *OIDCProvider) GenerateIDToken(userID, clientID, nonce string, scopes []string) (string, error) {
	log.Printf("[OIDC] Generating ID token for user %s, client %s", userID, clientID)

	// Get user information to include in the token
	var userClaims map[string]interface{}
	var sub string

	if p.userInfoProvider != nil {
		userInfo, err := p.userInfoProvider.GetUserInfo(userID)
		if err != nil {
			log.Printf("[OIDC] Failed to get user info: %v", err)
		} else {
			// Convert UserInfo to map for inclusion in token
			userClaims = make(map[string]interface{})
			sub = userInfo.Subject
			if sub == "" {
				sub = userID
			}

			// Add claims based on requested scopes
			for _, scope := range scopes {
				switch scope {
				case ScopeProfile:
					userClaims["name"] = userInfo.Name
					userClaims["given_name"] = userInfo.GivenName
					userClaims["family_name"] = userInfo.FamilyName
					userClaims["middle_name"] = userInfo.MiddleName
					userClaims["nickname"] = userInfo.Nickname
					userClaims["preferred_username"] = userInfo.PreferredUsername
					userClaims["profile"] = userInfo.Profile
					userClaims["picture"] = userInfo.Picture
					userClaims["website"] = userInfo.Website
					userClaims["gender"] = userInfo.Gender
					userClaims["birthdate"] = userInfo.Birthdate
					userClaims["zoneinfo"] = userInfo.Zoneinfo
					userClaims["locale"] = userInfo.Locale
					userClaims["updated_at"] = userInfo.UpdatedAt
				case ScopeEmail:
					userClaims["email"] = userInfo.Email
					userClaims["email_verified"] = userInfo.EmailVerified
				case ScopePhone:
					userClaims["phone_number"] = userInfo.PhoneNumber
					userClaims["phone_number_verified"] = userInfo.PhoneNumberVerified
				case ScopeAddress:
					userClaims["address"] = userInfo.Address
				}
			}
		}
	}

	if sub == "" {
		sub = userID // Fallback if no subject is available from user info
	}

	now := time.Now()
	expiresAt := now.Add(time.Duration(p.Config.IDTokenLifetime) * time.Second)

	// Create the token with claims
	claims := IDTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    p.Config.Issuer,
			Subject:   sub,
			Audience:  jwt.ClaimStrings{clientID},
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
		},
		AuthTime: now.Unix(),
		Nonce:    nonce,
	}

	// Add user info claims
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	// For each claim in userClaims, add it to the token
	for k, v := range userClaims {
		if v != nil && v != "" {
			token.Claims.(jwt.MapClaims)[k] = v
		}
	}

	// Set the key ID header
	token.Header["kid"] = p.keyID

	if p.Config.SigningKey == nil {
		return "", errors.New("signing key not configured")
	}

	// Sign the token
	signedToken, err := token.SignedString(p.Config.SigningKey)
	if err != nil {
		log.Printf("[OIDC] Failed to sign token: %v", err)
		return "", err
	}

	log.Printf("[OIDC] ID token generated successfully")
	return signedToken, nil
}

// HandleDiscovery serves the OIDC discovery document
func (p *OIDCProvider) HandleDiscovery(w http.ResponseWriter, r *http.Request) {
	log.Printf("[OIDC] Serving discovery document")

	// Construct the base URL from the issuer
	issuer := p.Config.Issuer

	discovery := map[string]interface{}{
		"issuer":                 issuer,
		"authorization_endpoint": fmt.Sprintf("%s/oauth/authorize", issuer),
		"token_endpoint":         fmt.Sprintf("%s/oauth/token", issuer),
		"userinfo_endpoint":      fmt.Sprintf("%s/userinfo", issuer),
		"jwks_uri":               fmt.Sprintf("%s/.well-known/jwks.json", issuer),
		"scopes_supported":       p.Config.SupportedScopes,
		"response_types_supported": []string{
			"code",
			"token",
			"id_token",
			"code token",
			"code id_token",
			"token id_token",
			"code token id_token",
		},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"claims_supported": []string{
			"iss", "sub", "aud", "exp", "iat", "auth_time",
			"name", "given_name", "family_name", "email", "email_verified",
			"picture", "profile",
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	json.NewEncoder(w).Encode(discovery)
}

// HandleJWKS serves the JWKS (JSON Web Key Set) document
func (p *OIDCProvider) HandleJWKS(w http.ResponseWriter, r *http.Request) {
	log.Printf("[OIDC] Serving JWKS document")

	if p.Config.SigningKey == nil {
		http.Error(w, "Signing key not configured", http.StatusInternalServerError)
		return
	}

	// Convert RSA public key to JWK
	publicKey := p.Config.SigningKey.Public()
	n := publicKey.(*rsa.PublicKey).N
	e := publicKey.(*rsa.PublicKey).E

	// Convert modulus and exponent to base64url encoding
	nBytes := n.Bytes()
	nBase64 := base64.RawURLEncoding.EncodeToString(nBytes)

	// Convert exponent to bytes and encode
	eBytes := make([]byte, 4)
	eBytes[0] = byte(e >> 24)
	eBytes[1] = byte(e >> 16)
	eBytes[2] = byte(e >> 8)
	eBytes[3] = byte(e)
	// Trim leading zeros
	i := 0
	for ; i < len(eBytes); i++ {
		if eBytes[i] != 0 {
			break
		}
	}
	eBase64 := base64.RawURLEncoding.EncodeToString(eBytes[i:])

	jwks := map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "RSA",
				"use": "sig",
				"kid": p.keyID,
				"alg": "RS256",
				"n":   nBase64,
				"e":   eBase64,
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	json.NewEncoder(w).Encode(jwks)
}

// HandleUserInfo handles the OIDC UserInfo endpoint
func (p *OIDCProvider) HandleUserInfo(w http.ResponseWriter, r *http.Request) {
	log.Printf("[OIDC] UserInfo request received")

	// Extract the access token from the Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || len(authHeader) < 8 || authHeader[:7] != "Bearer " {
		http.Error(w, "Invalid or missing authorization header", http.StatusUnauthorized)
		return
	}

	accessToken := authHeader[7:]

	// Validate the access token
	token, err := p.tokenStore.GetByAccessToken(accessToken)
	if err != nil {
		log.Printf("[OIDC] Invalid access token: %v", err)
		http.Error(w, "Invalid access token", http.StatusUnauthorized)
		return
	}

	// Check if token has appropriate scope (openid at minimum)
	hasOpenIDScope := false
	if token.Scope != "" {
		scopes := strings.Split(token.Scope, " ")
		for _, scope := range scopes {
			if scope == ScopeOpenID {
				hasOpenIDScope = true
				break
			}
		}
	}

	if !hasOpenIDScope {
		log.Printf("[OIDC] Access token missing openid scope")
		http.Error(w, "Token does not have openid scope", http.StatusForbidden)
		return
	}

	// Get user info
	if p.userInfoProvider == nil {
		log.Printf("[OIDC] UserInfo provider not configured")
		http.Error(w, "UserInfo not available", http.StatusInternalServerError)
		return
	}

	userInfo, err := p.userInfoProvider.GetUserInfo(token.UserID)
	if err != nil {
		log.Printf("[OIDC] Failed to retrieve user info: %v", err)
		http.Error(w, "Failed to retrieve user info", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(userInfo)
}

// Extended handleAuthorizationCode to support OIDC
func (p *OIDCProvider) handleAuthorizationCode(w http.ResponseWriter, req *AuthorizationRequest, user *User) {
	// Check if openid scope was requested
	isOIDCRequest := false
	scopes := parseScope(req.Scope)
	for _, scope := range scopes {
		if scope == ScopeOpenID {
			isOIDCRequest = true
			break
		}
	}

	// Generate authorization code
	code := generateRandomString(32)
	expiresAt := time.Now().Add(time.Duration(p.config.AuthCodeLifetime) * time.Second)

	authCode := &AuthorizationCode{
		Code:        code,
		ClientID:    req.ClientID,
		RedirectURI: req.RedirectURI,
		UserID:      user.ID,
		Scope:       req.Scope,
		ExpiresAt:   expiresAt,
	}

	if err := p.authCodeStore.SaveCode(authCode); err != nil {
		log.Printf("[OIDC] Failed to save authorization code: %v", err)
		p.renderError(w, err, http.StatusInternalServerError)
		return
	}

	// Create the redirect URL
	redirectURI := fmt.Sprintf("%s?code=%s", req.RedirectURI, code)
	if req.State != "" {
		redirectURI = fmt.Sprintf("%s&state=%s", redirectURI, req.State)
	}

	log.Printf("[OIDC] Authorization code generated, redirecting to: %s", redirectURI)

	http.Redirect(w, r, redirectURI, http.StatusFound)
}

// handleAuthorizationCodeGrant handles token requests with authorization_code grant type
func (p *OIDCProvider) handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request) {
	log.Printf("[OIDC] Processing authorization_code grant")

	// Parse the form for token request parameters
	if err := r.ParseForm(); err != nil {
		log.Printf("[OIDC] Failed to parse form: %v", err)
		p.tokenError(w, "invalid_request", "Could not parse form data")
		return
	}

	// Get required parameters
	code := r.FormValue("code")
	redirectURI := r.FormValue("redirect_uri")
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")

	// Validate the client
	client, err := p.clientStore.ValidateClient(clientID, clientSecret)
	if err != nil {
		log.Printf("[OIDC] Client authentication failed: %v", err)
		p.tokenError(w, "invalid_client", "Client authentication failed")
		return
	}

	// Validate and exchange the authorization code
	authCode, err := p.authCodeStore.GetCode(code)
	if err != nil {
		log.Printf("[OIDC] Invalid authorization code: %v", err)
		p.tokenError(w, "invalid_grant", "Invalid authorization code")
		return
	}

	// Verify the code belongs to this client and redirect URI matches
	if authCode.ClientID != clientID {
		log.Printf("[OIDC] Code was not issued to this client")
		p.tokenError(w, "invalid_grant", "Code was not issued to this client")
		return
	}

	if redirectURI != "" && redirectURI != authCode.RedirectURI {
		log.Printf("[OIDC] Redirect URI mismatch")
		p.tokenError(w, "invalid_grant", "Redirect URI mismatch")
		return
	}

	// Remove the used code
	if err := p.authCodeStore.RemoveCode(code); err != nil {
		log.Printf("[OIDC] Error removing used code: %v", err)
		// This is not fatal, continue
	}

	// Generate access token
	accessToken := generateRandomString(32)
	refreshToken := generateRandomString(32)

	now := time.Now()
	token := &Token{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		RefreshToken: refreshToken,
		ExpiresIn:    p.config.AccessTokenLifetime,
		Scope:        authCode.Scope,
		CreatedAt:    now,
		ExpiresAt:    now.Add(time.Duration(p.config.AccessTokenLifetime) * time.Second),
		UserID:       authCode.UserID,
		ClientID:     authCode.ClientID,
	}

	// Save the token
	if err := p.tokenStore.SaveToken(token); err != nil {
		log.Printf("[OIDC] Failed to save token: %v", err)
		p.tokenError(w, "server_error", "Failed to save token")
		return
	}

	// Check if this is an OIDC request (has openid scope)
	isOIDCRequest := false
	scopes := parseScope(authCode.Scope)
	for _, scope := range scopes {
		if scope == ScopeOpenID {
			isOIDCRequest = true
			break
		}
	}

	// Generate ID token for OIDC requests
	var idToken string
	if isOIDCRequest {
		nonce := r.FormValue("nonce") // Optional, may be empty
		idToken, err = p.GenerateIDToken(authCode.UserID, clientID, nonce, scopes)
		if err != nil {
			log.Printf("[OIDC] Failed to generate ID token: %v", err)
			// Continue without ID token if there was an error
		}
	}

	// Prepare the response
	response := map[string]interface{}{
		"access_token":  accessToken,
		"token_type":    "Bearer",
		"refresh_token": refreshToken,
		"expires_in":    p.config.AccessTokenLifetime,
	}

	if authCode.Scope != "" {
		response["scope"] = authCode.Scope
	}

	if idToken != "" {
		response["id_token"] = idToken
	}

	// Send the response
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(response)
}

// handleRefreshTokenGrant implements the refresh_token grant
func (p *OIDCProvider) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request) {
	// This function would be extended to support ID tokens when OpenID Connect is used
	p.Provider.handleRefreshTokenGrant(w, r)
}

// Parse space-delimited scope string
func parseScope(scope string) []string {
	// A simple implementation, in a real app you might want a more robust parser
	// This doesn't handle empty scopes or multiple spaces between scopes
	if scope == "" {
		return []string{}
	}
	return strings.Split(scope, " ")
}
