package middleware

import (
	"context"
	"net/http"

	"github.com/tom/authlite/pkg/auth"
)

// Key type for storing values in context
type contextKey string

// UserIDKey is the key for user ID in the context
const UserIDKey contextKey = "user_id"

// RequireAuthentication middleware ensures the request is authenticated
func RequireAuthentication(authenticator *auth.Authenticator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			session, err := authenticator.GetUserSession(r)
			if err != nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Store user ID in context for use in handlers
			ctx := context.WithValue(r.Context(), UserIDKey, session.UserID)

			// Call the next handler with the updated context
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetUserID retrieves user ID from the request context
func GetUserID(r *http.Request) string {
	userID, ok := r.Context().Value(UserIDKey).(string)
	if !ok {
		return ""
	}
	return userID
}

// OptionalAuthentication middleware that doesn't require authentication but adds user info to context if available
func OptionalAuthentication(authenticator *auth.Authenticator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			session, err := authenticator.GetUserSession(r)
			if err == nil && session != nil {
				// Store user ID in context for use in handlers
				ctx := context.WithValue(r.Context(), UserIDKey, session.UserID)
				r = r.WithContext(ctx)
			}

			// Call the next handler with the updated context
			next.ServeHTTP(w, r)
		})
	}
}
