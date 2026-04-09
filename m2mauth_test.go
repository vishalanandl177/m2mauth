package m2mauth

import (
	"context"
	"testing"
	"time"
)

func TestToken_Valid(t *testing.T) {
	// Valid token.
	tok := &Token{AccessToken: "abc", ExpiresAt: time.Now().Add(time.Hour)}
	if !tok.Valid() {
		t.Error("expected token to be valid")
	}

	// Expired token.
	tok2 := &Token{AccessToken: "abc", ExpiresAt: time.Now().Add(-time.Hour)}
	if tok2.Valid() {
		t.Error("expected expired token to be invalid")
	}

	// Empty access token.
	tok3 := &Token{AccessToken: "", ExpiresAt: time.Now().Add(time.Hour)}
	if tok3.Valid() {
		t.Error("expected empty token to be invalid")
	}

	// Nil token.
	var tok4 *Token
	if tok4.Valid() {
		t.Error("expected nil token to be invalid")
	}
}

func TestClaims_HasScope(t *testing.T) {
	c := &Claims{Scopes: []string{"read:users", "write:orders"}}

	if !c.HasScope("read:users") {
		t.Error("expected HasScope to find read:users")
	}
	if c.HasScope("admin:all") {
		t.Error("expected HasScope to not find admin:all")
	}
}

func TestClaims_HasAllScopes(t *testing.T) {
	c := &Claims{Scopes: []string{"read:users", "write:orders", "delete:items"}}

	if !c.HasAllScopes("read:users", "write:orders") {
		t.Error("expected HasAllScopes to find both scopes")
	}
	if c.HasAllScopes("read:users", "admin:all") {
		t.Error("expected HasAllScopes to return false when one scope is missing")
	}
	if !c.HasAllScopes() {
		t.Error("expected HasAllScopes with no args to return true")
	}
}

func TestContextWithClaims_And_ClaimsFromContext(t *testing.T) {
	claims := &Claims{Subject: "svc-test", Scopes: []string{"read"}}
	ctx := ContextWithClaims(context.Background(), claims)

	got, ok := ClaimsFromContext(ctx)
	if !ok {
		t.Fatal("expected claims in context")
	}
	if got.Subject != "svc-test" {
		t.Errorf("expected subject svc-test, got %q", got.Subject)
	}
}

func TestClaimsFromContext_Missing(t *testing.T) {
	_, ok := ClaimsFromContext(context.Background())
	if ok {
		t.Error("expected no claims in empty context")
	}
}

func TestAuthError_Error(t *testing.T) {
	err := &AuthError{Op: "token_fetch", Kind: "network", Err: ErrTokenFetchFailed}
	msg := err.Error()
	if msg != "m2mauth token_fetch [network]: m2mauth: token fetch failed" {
		t.Errorf("unexpected error message: %s", msg)
	}

	// Without underlying error.
	err2 := &AuthError{Op: "validate", Kind: "credential"}
	msg2 := err2.Error()
	if msg2 != "m2mauth validate [credential]" {
		t.Errorf("unexpected error message: %s", msg2)
	}
}

func TestAuthError_Unwrap(t *testing.T) {
	err := &AuthError{Op: "test", Kind: "test", Err: ErrTokenExpired}
	if err.Unwrap() != ErrTokenExpired {
		t.Error("expected Unwrap to return underlying error")
	}
}

func TestIsRetryable(t *testing.T) {
	retryable := &AuthError{Op: "fetch", Kind: "network", Err: nil, Retryable: true}
	if !IsRetryable(retryable) {
		t.Error("expected retryable error to return true")
	}

	nonRetryable := &AuthError{Op: "fetch", Kind: "credential", Err: nil, Retryable: false}
	if IsRetryable(nonRetryable) {
		t.Error("expected non-retryable error to return false")
	}

	// Non-AuthError.
	if IsRetryable(ErrTokenExpired) {
		t.Error("expected non-AuthError to return false")
	}
}
