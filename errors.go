package m2mauth

import (
	"errors"
	"fmt"
)

// Sentinel errors for common authentication failures.
var (
	ErrTokenExpired      = errors.New("m2mauth: token expired")
	ErrTokenNotYetValid  = errors.New("m2mauth: token not yet valid")
	ErrInvalidAudience   = errors.New("m2mauth: invalid audience")
	ErrInvalidIssuer     = errors.New("m2mauth: invalid issuer")
	ErrInsufficientScope = errors.New("m2mauth: insufficient scope")
	ErrMissingToken      = errors.New("m2mauth: missing token")
	ErrInvalidToken      = errors.New("m2mauth: invalid token")
	ErrInvalidSignature  = errors.New("m2mauth: invalid signature")
	ErrCertExpired       = errors.New("m2mauth: certificate expired")
	ErrCertNotTrusted    = errors.New("m2mauth: certificate not trusted")
	ErrSecretNotFound    = errors.New("m2mauth: secret not found")
	ErrTokenRevoked      = errors.New("m2mauth: token revoked")
	ErrInvalidAPIKey     = errors.New("m2mauth: invalid api key")
	ErrMissingAPIKey     = errors.New("m2mauth: missing api key")
	ErrTokenFetchFailed  = errors.New("m2mauth: token fetch failed")
)

// AuthError wraps an underlying error with authentication-specific context.
type AuthError struct {
	// Op is the operation that failed (e.g., "token_fetch", "jwt_validate", "cert_load").
	Op string

	// Kind categorizes the error (e.g., "credential", "network", "validation").
	Kind string

	// Err is the underlying error.
	Err error

	// Retryable indicates whether the operation can be retried.
	Retryable bool
}

func (e *AuthError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("m2mauth %s [%s]: %v", e.Op, e.Kind, e.Err)
	}
	return fmt.Sprintf("m2mauth %s [%s]", e.Op, e.Kind)
}

func (e *AuthError) Unwrap() error {
	return e.Err
}

// IsRetryable reports whether the given error represents a retryable failure.
func IsRetryable(err error) bool {
	var ae *AuthError
	if errors.As(err, &ae) {
		return ae.Retryable
	}
	return false
}
