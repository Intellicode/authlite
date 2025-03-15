# AuthLite

AuthLite is a lightweight OAuth2 provider implementation in Go. It provides a complete OAuth2 authorization server that can be used to secure your APIs and applications.

## Features

- OAuth2 authorization server implementation
- Support for standard OAuth2 flows (authorization code, implicit, client credentials, password)
- Authentication and session management
- In-memory storage with interfaces for easy extension to persistent storage
- Simple API for integration

## Project Structure

The project follows the standard Go project layout:

```
authlite/
├── api/           # API definitions
│   └── v1/        # API version 1
├── cmd/           # Application entrypoints
│   └── server/    # OAuth2 server command
├── docs/          # Documentation
├── examples/      # Example usage
├── internal/      # Private application code
│   ├── config/    # Configuration handling
│   └── middleware/# HTTP middleware
├── pkg/           # Public library code
│   ├── auth/      # Authentication
│   ├── oauth2/    # OAuth2 implementation
│   └── storage/   # Storage interfaces
└── web/          # Web assets (templates, static files)
```

## Getting Started

### Prerequisites

- Go 1.16 or higher

### Installation

Clone the repository:

```bash
git clone https://github.com/tom/authlite.git
cd authlite
```

### Running the server

```bash
go run cmd/server/main.go
```

The server will start on `http://localhost:9000` by default.

## Using the OAuth2 Provider

### Register a client

For demonstration purposes, a test client is pre-registered with the following credentials:

- Client ID: `test_client`
- Client Secret: `test_secret`
- Redirect URI: `http://localhost:8080/callback`

### Authorization Code Flow

1. Redirect the user to the authorization endpoint:

```
http://localhost:9000/oauth/authorize?client_id=test_client&redirect_uri=http://localhost:8080/callback&response_type=code&scope=read
```

2. The user will be redirected to log in (use `testuser/password` for demo)
3. After authorization, the user will be redirected to the specified redirect URI with an authorization code
4. Exchange the authorization code for an access token:

```bash
curl -X POST http://localhost:9000/oauth/token \
  -d "grant_type=authorization_code" \
  -d "code=AUTHORIZATION_CODE" \
  -d "redirect_uri=http://localhost:8080/callback" \
  -d "client_id=test_client" \
  -d "client_secret=test_secret"
```

### Using the Access Token

Use the access token to access protected resources:

```bash
curl -H "Authorization: Bearer ACCESS_TOKEN" http://localhost:9000/userinfo
```

## Next Steps

- Implement persistent storage backends
- Add support for JWT tokens
- Add OpenID Connect extensions
- Implement additional security features (PKCE, etc.)

## License

This project is licensed under the MIT License - see the LICENSE file for details.
