package apikey

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/vishalanandl177/m2mauth"
	"github.com/vishalanandl177/m2mauth/authlog"
	"github.com/vishalanandl177/m2mauth/secrets"
)

func TestAuthenticator_Header(t *testing.T) {
	auth, err := New(WithKey("sk_test_123"))
	if err != nil {
		t.Fatal(err)
	}

	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/data", nil)
	if err := auth.Authenticate(context.Background(), req); err != nil {
		t.Fatal(err)
	}

	if got := req.Header.Get("X-API-Key"); got != "sk_test_123" {
		t.Errorf("expected X-API-Key=sk_test_123, got %q", got)
	}
}

func TestAuthenticator_CustomHeader(t *testing.T) {
	auth, err := New(WithKey("mykey"), WithHeaderName("X-Custom-Auth"))
	if err != nil {
		t.Fatal(err)
	}

	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/data", nil)
	auth.Authenticate(context.Background(), req)

	if got := req.Header.Get("X-Custom-Auth"); got != "mykey" {
		t.Errorf("expected X-Custom-Auth=mykey, got %q", got)
	}
}

func TestAuthenticator_BearerHeader(t *testing.T) {
	auth, err := New(WithKey("token123"), WithLocation(BearerHeader))
	if err != nil {
		t.Fatal(err)
	}

	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/data", nil)
	auth.Authenticate(context.Background(), req)

	if got := req.Header.Get("Authorization"); got != "Bearer token123" {
		t.Errorf("expected 'Bearer token123', got %q", got)
	}
}

func TestAuthenticator_QueryParam(t *testing.T) {
	auth, err := New(WithKey("qkey"), WithLocation(QueryParam), WithParamName("key"))
	if err != nil {
		t.Fatal(err)
	}

	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/data", nil)
	auth.Authenticate(context.Background(), req)

	if got := req.URL.Query().Get("key"); got != "qkey" {
		t.Errorf("expected query param key=qkey, got %q", got)
	}
}

func TestNew_RequiresKeyOrProvider(t *testing.T) {
	_, err := New()
	if err == nil {
		t.Fatal("expected error when no key or provider is set")
	}
}

func TestAuthenticator_WithSecretProvider(t *testing.T) {
	sp := secrets.NewStaticProvider(map[string]string{"api_key": "dynamic-key-123"})
	auth, err := New(WithSecretProvider(sp, "api_key"))
	if err != nil {
		t.Fatal(err)
	}

	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/data", nil)
	if err := auth.Authenticate(context.Background(), req); err != nil {
		t.Fatal(err)
	}

	if got := req.Header.Get("X-API-Key"); got != "dynamic-key-123" {
		t.Errorf("expected dynamic-key-123, got %q", got)
	}
}

func TestAuthenticator_SecretProviderError(t *testing.T) {
	sp := secrets.NewStaticProvider(map[string]string{}) // empty, will fail
	auth, err := New(WithSecretProvider(sp, "missing_key"))
	if err != nil {
		t.Fatal(err)
	}

	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/data", nil)
	err = auth.Authenticate(context.Background(), req)
	if err == nil {
		t.Fatal("expected error from secret provider")
	}
	var authErr *m2mauth.AuthError
	if !errors.As(err, &authErr) {
		t.Errorf("expected AuthError, got %T", err)
	}
}

func TestAuthenticator_WithOptions(t *testing.T) {
	auth, err := New(
		WithKey("test"),
		WithEventHandler(authlog.NopHandler()),
		WithServiceName("test-svc"),
	)
	if err != nil {
		t.Fatal(err)
	}

	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/data", nil)
	if err := auth.Authenticate(context.Background(), req); err != nil {
		t.Fatal(err)
	}
}
