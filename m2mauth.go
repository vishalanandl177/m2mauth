// Package m2mauth provides a batteries-included toolkit for Machine-to-Machine
// authentication in Go. It supports OAuth 2.0 Client Credentials, mTLS, API keys,
// and JWT validation — covering both outbound (client) and inbound (server) auth.
//
// Core interfaces:
//   - Authenticator: attaches credentials to outbound HTTP requests
//   - Validator: validates credentials on inbound HTTP requests
//   - TokenSource: provides access tokens with automatic caching/refresh
//   - SecretProvider: abstracts secret retrieval (env, file, vault)
package m2mauth

import (
	"context"
	"net/http"
	"time"
)

// Version is the library version.
const Version = "0.1.0"

// Authenticator attaches credentials to an outbound HTTP request.
// Implementations include OAuth 2.0 client credentials, mTLS, and API keys.
type Authenticator interface {
	// Authenticate modifies the request to include authentication credentials.
	Authenticate(ctx context.Context, req *http.Request) error
}

// Validator validates authentication on an inbound HTTP request and returns
// the verified claims. Implementations include JWT validation, API key lookup,
// and mTLS certificate verification.
type Validator interface {
	// Validate checks the request for valid authentication and returns claims.
	Validate(ctx context.Context, req *http.Request) (*Claims, error)
}

// TokenSource provides access tokens, handling caching and refresh internally.
type TokenSource interface {
	// Token returns a valid access token, refreshing if necessary.
	Token(ctx context.Context) (*Token, error)
}

// SecretProvider abstracts secret retrieval from different backends.
type SecretProvider interface {
	// GetSecret retrieves a secret value by key.
	GetSecret(ctx context.Context, key string) (string, error)
}

// Token represents an acquired access token from an authorization server.
type Token struct {
	// AccessToken is the token string.
	AccessToken string

	// TokenType is typically "Bearer".
	TokenType string

	// ExpiresAt is when the token expires.
	ExpiresAt time.Time

	// Scopes are the granted scopes.
	Scopes []string

	// Raw holds the full token response for advanced use.
	Raw map[string]any
}

// Valid reports whether the token is non-empty and not yet expired.
func (t *Token) Valid() bool {
	return t != nil && t.AccessToken != "" && time.Now().Before(t.ExpiresAt)
}

// Claims represents validated identity information extracted from an
// authenticated request (JWT, certificate, API key, etc.).
type Claims struct {
	// Subject identifies the authenticated service or entity.
	Subject string

	// Issuer is the token issuer (e.g., auth server URL).
	Issuer string

	// Audience contains the intended recipients.
	Audience []string

	// Scopes are the granted permissions.
	Scopes []string

	// IssuedAt is when the credential was issued.
	IssuedAt time.Time

	// ExpiresAt is when the credential expires.
	ExpiresAt time.Time

	// Extra holds additional claims not covered by the standard fields.
	Extra map[string]any
}

// HasScope reports whether the claims include the given scope.
func (c *Claims) HasScope(scope string) bool {
	for _, s := range c.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// HasAllScopes reports whether the claims include all the given scopes.
func (c *Claims) HasAllScopes(scopes ...string) bool {
	have := make(map[string]struct{}, len(c.Scopes))
	for _, s := range c.Scopes {
		have[s] = struct{}{}
	}
	for _, s := range scopes {
		if _, ok := have[s]; !ok {
			return false
		}
	}
	return true
}

type claimsContextKey struct{}

// ContextWithClaims returns a new context carrying the given claims.
func ContextWithClaims(ctx context.Context, claims *Claims) context.Context {
	return context.WithValue(ctx, claimsContextKey{}, claims)
}

// ClaimsFromContext extracts claims from a context, if present.
func ClaimsFromContext(ctx context.Context) (*Claims, bool) {
	c, ok := ctx.Value(claimsContextKey{}).(*Claims)
	return c, ok
}
