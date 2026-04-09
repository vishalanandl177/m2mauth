package apikey

import (
	"context"
	"net/http"
	"testing"
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
