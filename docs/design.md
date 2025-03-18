# AuthLite - Design Document

## Overview

AuthLite is a lightweight, extensible OAuth2/OpenID Connect (OIDC) provider implemented in Go. It provides a complete authentication and authorization solution that can be embedded into applications or deployed as a standalone service. AuthLite implements standard OAuth2 flows and OIDC extensions, offering a secure way to manage authentication for web and mobile applications.

## Architecture

AuthLite follows a modular design with clear separation of concerns, making it easy to extend and maintain. The architecture is composed of the following main components:

### Core Components

1. **OAuth2 Provider**

   - Implements standard OAuth2 flows (authorization code, implicit, client credentials, password)
   - Manages tokens, client applications, and authorization codes
   - Handles authorization and token endpoints

2. **OpenID Connect Provider**

   - Extends OAuth2 with identity functionality
   - Generates ID tokens as JWT
   - Provides UserInfo, Discovery, and JWKS endpoints

3. **Authentication System**

   - Manages user sessions
   - Handles login/logout operations
   - Maintains user information for OIDC claims

4. **Storage System**
   - Provides a pluggable storage interface
   - Supports multiple backend implementations (in-memory, database, etc.)
   - Manages persistence of auth codes, tokens, clients, and users

### API Layer

The API layer exposes HTTP endpoints for:

- OAuth2 authorization and token endpoints
- OIDC discovery and UserInfo endpoints
- User authentication (login/logout)

### Component Diagram

```
┌───────────────────────────────────────────────────────────┐
│                      API Layer (HTTP)                     │
└───────────┬───────────────────┬────────────┬─────────────┘
            │                   │            │
┌───────────▼───────┐ ┌─────────▼───────┐ ┌──▼──────────────┐
│  OAuth2 Provider  │ │ OIDC Provider   │ │ Authentication  │
└───────────┬───────┘ └─────────┬───────┘ │   System        │
            │                   │         └──────┬──────────┘
            │                   │                │
┌───────────▼───────────────────▼────────────────▼──────────┐
│                     Storage Interface                      │
└───────────┬───────────────────┬────────────┬─────────────┘
            │                   │            │
┌───────────▼───────┐ ┌─────────▼───────┐ ┌──▼──────────────┐
│  Memory Storage   │ │ Redis Storage   │ │  SQL Storage    │
│ (Implementation)  │ │ (Future)        │ │  (Future)       │
└───────────────────┘ └─────────────────┘ └─────────────────┘
```

## Data Models

### OAuth2 Models

1. **Client**

   - ID, Secret, RedirectURIs, GrantTypes, Scopes, PublicFlag

2. **Token**

   - AccessToken, RefreshToken, ExpiresAt, Scope, UserID, ClientID

3. **AuthorizationCode**

   - Code, ClientID, RedirectURI, UserID, Scope, ExpiresAt

4. **User**
   - ID, Username, Password, Profile Information

### OIDC Models

1. **UserInfo**

   - Standard OIDC claims (sub, name, email, etc.)

2. **IDToken**
   - JWT with standard claims and custom user claims

### Session Models

1. **Session**
   - ID, UserID, ExpiresAt, Claims

## Storage System

The storage system follows a clean interface design pattern:

1. **Store Interface**

   - Core operations: Get, Set, Delete, List
   - Operates on collections and keys

2. **Implementation: Memory Store**

   - In-memory implementation for testing and development

3. **Future Implementations**
   - Redis, SQL databases, etc.

## Authentication Flow

### Authorization Code Flow

```
┌─────────┐                                  ┌────────┐         ┌────────────┐
│  User   │                                  │ Client │         │ AuthLite   │
└────┬────┘                                  └───┬────┘         └─────┬──────┘
     │                                          │                     │
     │                                          │  Authorization      │
     │                                          │  Request            │
     │                                          │ ───────────────────>│
     │                                          │                     │
     │                                          │  Login Required     │
     │ <───────────────────────────────────────────────────────────────
     │                                          │                     │
     │  User Authentication                     │                     │
     │ ───────────────────────────────────────────────────────────────>
     │                                          │                     │
     │  Consent Request                         │                     │
     │ <───────────────────────────────────────────────────────────────
     │                                          │                     │
     │  User Consent                            │                     │
     │ ───────────────────────────────────────────────────────────────>
     │                                          │                     │
     │                                          │  Auth Code          │
     │                                          │ <───────────────────│
     │                                          │                     │
     │                                          │  Token Request      │
     │                                          │ ───────────────────>│
     │                                          │                     │
     │                                          │  Tokens             │
     │                                          │ <───────────────────│
     │                                          │                     │
```

## Implementation Details

### OAuth2 Provider

The OAuth2 Provider implements:

- Authorization request validation
- Token generation and validation
- Client authentication
- Grant type handlers (authorization_code, refresh_token, client_credentials, password)

### OIDC Extensions

The OIDC Provider adds:

- ID token generation with JWT signing
- UserInfo endpoint
- Discovery document (`/.well-known/openid-configuration`)
- JWKS endpoint for key distribution

### Authentication System

The Authentication System handles:

- Session creation and validation
- Cookie management
- User info retrieval

### Storage Abstraction

The Storage system provides:

- Collection-based organization (users, sessions, tokens)
- Key-value based operations
- Extensible backend support

## Security Considerations

1. **Token Security**

   - Short-lived access tokens
   - Refresh token rotation
   - JWT signing with RSA keys

2. **Session Security**

   - Secure and HttpOnly cookies
   - Session timeout
   - CSRF protection

3. **Client Authentication**

   - Client secret validation
   - Redirect URI validation
   - Grant type restrictions

4. **API Security**
   - Input validation
   - Rate limiting (to be implemented)
   - Proper error handling to prevent information disclosure

## Deployment Considerations

1. **TLS Requirements**

   - HTTPS is required for production deployment
   - Secure cookie settings

2. **Key Management**

   - RSA key generation and rotation
   - Secure key storage

3. **Scaling**
   - Stateless design for horizontal scaling
   - Support for distributed storage backends

## Future Enhancements

1. **Storage Backends**

   - Redis implementation
   - SQL database support
   - Distributed caching

2. **Advanced Security**

   - PKCE support for public clients
   - Token binding
   - Advanced threat detection

3. **Performance Optimizations**

   - Caching layer
   - Connection pooling
   - Optimized token validation

4. **Operational Features**
   - Admin API for client management
   - Metrics and monitoring
   - Audit logging

## Conclusion

AuthLite provides a robust and extensible OAuth2/OIDC implementation suitable for a variety of authentication needs. Its modular design allows for easy extension and customization while maintaining compatibility with the OAuth2 and OIDC standards.
