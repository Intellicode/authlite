# AuthLite API Documentation

This document provides a comprehensive reference for the AuthLite API endpoints, including OAuth2 and OpenID Connect (OIDC) functionality.

## Base URL

All API endpoints are relative to your AuthLite server base URL. By default, this is:

```
http://localhost:9000
```

## Authentication

Most endpoints require authentication. There are two primary methods:

1. **Session Cookie**: For browser-based authentication
2. **Bearer Token**: For API-based authentication

Protected endpoints will respond with HTTP 401 Unauthorized if authentication is missing or invalid.

## OAuth2 Endpoints

### Authorization Endpoint

Initiates the OAuth2 authorization flow.

- **URL**: `/oauth/authorize`
- **Method**: `GET`
- **Parameters**:
  - `client_id` (required): The client application's ID
  - `response_type` (required): Type of response desired (`code`, `token`)
  - `redirect_uri` (required): URI to redirect after authorization
  - `scope` (optional): Space-delimited list of requested scopes
  - `state` (recommended): Random string for CSRF protection
  - `nonce` (recommended for OIDC): Random string for replay protection
- **Response**: Redirects to the specified `redirect_uri` with an authorization code or access token
- **Example**:
  ```
  GET /oauth/authorize?client_id=test_client&response_type=code&redirect_uri=http://localhost:8080/callback&scope=read&state=xyz123
  ```

### Token Endpoint

Exchanges an authorization code for tokens or refreshes existing tokens.

- **URL**: `/oauth/token`
- **Method**: `POST`
- **Content-Type**: `application/x-www-form-urlencoded`
- **Parameters** (Authorization Code Grant):
  - `grant_type` (required): Must be `authorization_code`
  - `code` (required): The authorization code received from the authorize endpoint
  - `redirect_uri` (required): Must match the redirect URI used in the authorization request
  - `client_id` (required): The client application's ID
  - `client_secret` (required for confidential clients): The client application's secret
- **Parameters** (Refresh Token Grant):
  - `grant_type` (required): Must be `refresh_token`
  - `refresh_token` (required): A previously issued refresh token
  - `client_id` (required): The client application's ID
  - `client_secret` (required for confidential clients): The client application's secret
  - `scope` (optional): Space-delimited list of requested scopes
- **Parameters** (Client Credentials Grant):
  - `grant_type` (required): Must be `client_credentials`
  - `client_id` (required): The client application's ID
  - `client_secret` (required): The client application's secret
  - `scope` (optional): Space-delimited list of requested scopes
- **Parameters** (Password Grant):
  - `grant_type` (required): Must be `password`
  - `username` (required): Resource owner's username
  - `password` (required): Resource owner's password
  - `client_id` (required): The client application's ID
  - `client_secret` (required for confidential clients): The client application's secret
  - `scope` (optional): Space-delimited list of requested scopes
- **Response**: JSON object containing:
  - `access_token`: The access token
  - `token_type`: The type of token (usually "Bearer")
  - `expires_in`: Token lifetime in seconds
  - `refresh_token`: A refresh token (if applicable)
  - `scope`: Granted scopes (if different from requested)
  - `id_token`: OIDC ID token (if OpenID Connect flow)
- **Example Request**:

  ```
  POST /oauth/token
  Content-Type: application/x-www-form-urlencoded

  grant_type=authorization_code&code=AUTHORIZATION_CODE&redirect_uri=http://localhost:8080/callback&client_id=test_client&client_secret=test_secret
  ```

- **Example Response**:
  ```json
  {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "token_type": "Bearer",
    "expires_in": 3600,
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "scope": "read write"
  }
  ```

## User Authentication Endpoints

### Login

Authenticates a user and creates a session.

- **URL**: `/login`
- **Method**: `POST`
- **Content-Type**: `application/x-www-form-urlencoded`
- **Parameters**:
  - `username` (required): The user's username
  - `password` (required): The user's password
  - `return_to` (optional): URL to redirect to after successful login
- **Response**:
  - If `return_to` parameter is provided: Redirects to that URL
  - Otherwise: JSON object with success status
- **Example Request**:

  ```
  POST /login
  Content-Type: application/x-www-form-urlencoded

  username=testuser&password=password
  ```

- **Example Response**:
  ```json
  {
    "success": true,
    "message": "Login successful"
  }
  ```

### Logout

Terminates the current user session.

- **URL**: `/logout`
- **Method**: `GET` or `POST`
- **Response**: JSON object with success status
- **Example Response**:
  ```json
  {
    "success": true,
    "message": "Logout successful"
  }
  ```

## OpenID Connect Endpoints

### UserInfo Endpoint

Returns claims about the authenticated user.

- **URL**: `/userinfo`
- **Method**: `GET`
- **Authentication**: Bearer token with `openid` scope
- **Response**: JSON object containing user claims
- **Example Request**:
  ```
  GET /userinfo
  Authorization: Bearer ACCESS_TOKEN
  ```
- **Example Response**:
  ```json
  {
    "sub": "1",
    "name": "Test User",
    "email": "test@example.com",
    "email_verified": true,
    "preferred_username": "testuser",
    "picture": "https://example.com/avatar.jpg"
  }
  ```

### OpenID Connect Discovery Endpoint

Provides OIDC configuration metadata.

- **URL**: `/.well-known/openid-configuration`
- **Method**: `GET`
- **Response**: JSON object containing OIDC provider metadata
- **Example Response**:
  ```json
  {
    "issuer": "https://authlite.example.com",
    "authorization_endpoint": "https://authlite.example.com/oauth/authorize",
    "token_endpoint": "https://authlite.example.com/oauth/token",
    "userinfo_endpoint": "https://authlite.example.com/userinfo",
    "jwks_uri": "https://authlite.example.com/.well-known/jwks.json",
    "scopes_supported": ["openid", "profile", "email", "address", "phone"],
    "response_types_supported": [
      "code",
      "token",
      "id_token",
      "code token",
      "code id_token",
      "token id_token",
      "code token id_token"
    ],
    "subject_types_supported": ["public"],
    "id_token_signing_alg_values_supported": ["RS256"],
    "claims_supported": [
      "iss",
      "sub",
      "aud",
      "exp",
      "iat",
      "auth_time",
      "name",
      "given_name",
      "family_name",
      "email",
      "email_verified",
      "picture",
      "profile"
    ]
  }
  ```

### JSON Web Key Set (JWKS) Endpoint

Provides the public keys used to verify ID tokens.

- **URL**: `/.well-known/jwks.json`
- **Method**: `GET`
- **Response**: JSON object containing JWK set
- **Example Response**:
  ```json
  {
    "keys": [
      {
        "kty": "RSA",
        "use": "sig",
        "kid": "default-key-id",
        "alg": "RS256",
        "n": "uZiNVZtr6jWtYvS-TxD4rl8GicEa4Bt5ApcIYtOOeyQLteWUHZ6UzFBiTU...",
        "e": "AQAB"
      }
    ]
  }
  ```

## Error Responses

Errors are returned as JSON objects with the following structure:

- **OAuth2 Errors**:

  ```json
  {
    "error": "error_code",
    "error_description": "Human readable error description"
  }
  ```

- **API Errors**:

  ```
  HTTP/1.1 400 Bad Request
  Content-Type: text/plain

  Error message
  ```

Common OAuth2 error codes include:

- `invalid_request`: The request is missing a required parameter or is malformed
- `invalid_client`: Client authentication failed
- `invalid_grant`: The provided authorization grant is invalid
- `unauthorized_client`: The client is not authorized for the requested grant type
- `unsupported_grant_type`: The grant type is not supported by the authorization server
- `invalid_scope`: The requested scope is invalid or unknown
- `access_denied`: The resource owner denied the request

## Testing the API

You can use the following curl commands to test basic API functionality:

1. **Start OAuth2 Flow**:

   ```bash
   curl -v "http://localhost:9000/oauth/authorize?client_id=test_client&response_type=code&redirect_uri=http://localhost:8080/callback&state=xyz123"
   ```

2. **Login**:

   ```bash
   curl -v -c cookies.txt -X POST \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "username=testuser" \
     -d "password=password" \
     "http://localhost:9000/login?return_to=/oauth/authorize?client_id=test_client&response_type=code&redirect_uri=http://localhost:8080/callback&state=xyz123"
   ```

3. **Approve Authorization**:
   ```bash
   curl -v -b cookies.txt \
     -X POST \
     -d "consent=approve" \
     "http://localhost:9000/oauth/authorize?client_id=test_client&response_type=code&redirect_uri=http://localhost:8080/callback&state=xyz123"
   ```
