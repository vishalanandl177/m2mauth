package oauth2

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/vishalanandl177/m2mauth/internal/testutil"
	"github.com/vishalanandl177/m2mauth/retry"
)

func TestClient_Token(t *testing.T) {
	srv := testutil.NewMockTokenServer(3600, "read:users write:orders")
	defer srv.Close()

	client, err := New(srv.URL, "test-client",
		WithClientSecret("test-secret"),
		WithAudience("https://api.example.com"),
		WithScopes("read:users"),
	)
	if err != nil {
		t.Fatal(err)
	}

	tok, err := client.Token(context.Background())
	if err != nil {
		t.Fatalf("Token() error: %v", err)
	}
	if tok.AccessToken == "" {
		t.Fatal("expected non-empty access token")
	}
	if tok.TokenType != "Bearer" {
		t.Errorf("expected Bearer, got %s", tok.TokenType)
	}
	if !tok.Valid() {
		t.Error("expected token to be valid")
	}
}

func TestClient_TokenCaching(t *testing.T) {
	srv := testutil.NewMockTokenServer(3600, "read:users")
	defer srv.Close()

	client, err := New(srv.URL, "test-client",
		WithClientSecret("test-secret"),
	)
	if err != nil {
		t.Fatal(err)
	}

	// Wrap to count fetches - we'll check the token is the same on second call.
	tok1, err := client.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	tok2, err := client.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// Cached: should be same token.
	if tok1.AccessToken != tok2.AccessToken {
		t.Error("expected cached token to be returned")
	}
}

func TestClient_Authenticate(t *testing.T) {
	srv := testutil.NewMockTokenServer(3600, "read:users")
	defer srv.Close()

	client, err := New(srv.URL, "test-client", WithClientSecret("secret"))
	if err != nil {
		t.Fatal(err)
	}

	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/users", nil)
	if err := client.Authenticate(context.Background(), req); err != nil {
		t.Fatal(err)
	}

	auth := req.Header.Get("Authorization")
	if auth == "" {
		t.Fatal("expected Authorization header")
	}
	if len(auth) < 8 || auth[:7] != "Bearer " {
		t.Fatalf("expected Bearer token, got %q", auth)
	}
}

func TestClient_ConcurrentAccess(t *testing.T) {
	srv := testutil.NewMockTokenServer(3600, "read:users")
	defer srv.Close()

	client, err := New(srv.URL, "test-client", WithClientSecret("secret"))
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	errs := make(chan error, 50)
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := client.Token(context.Background())
			if err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent Token() error: %v", err)
	}
}

func TestClient_RevokeToken(t *testing.T) {
	srv := testutil.NewMockTokenServer(3600, "read:users")
	defer srv.Close()

	client, err := New(srv.URL, "test-client", WithClientSecret("secret"))
	if err != nil {
		t.Fatal(err)
	}

	tok1, _ := client.Token(context.Background())
	client.RevokeToken()
	tok2, _ := client.Token(context.Background())

	if tok1.AccessToken == tok2.AccessToken {
		t.Error("expected different token after revocation")
	}
}

func TestClient_RetryPolicy(t *testing.T) {
	// This test just ensures retry config is accepted.
	srv := testutil.NewMockTokenServer(3600, "read:users")
	defer srv.Close()

	p := retry.NewPolicy(retry.WithMaxRetries(2), retry.WithBaseDelay(time.Millisecond))
	client, err := New(srv.URL, "test-client",
		WithClientSecret("secret"),
		WithRetryPolicy(p),
	)
	if err != nil {
		t.Fatal(err)
	}

	tok, err := client.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken == "" {
		t.Fatal("expected token")
	}
}

func TestNew_Validation(t *testing.T) {
	_, err := New("", "client")
	if err == nil {
		t.Fatal("expected error for empty token URL")
	}

	_, err = New("https://auth.example.com/token", "")
	if err == nil {
		t.Fatal("expected error for empty client ID")
	}
}

func TestNew_HTTPSEnforcement(t *testing.T) {
	// Non-HTTPS, non-localhost should fail
	_, err := New("http://auth.example.com/token", "client", WithClientSecret("secret"))
	if err == nil {
		t.Fatal("expected error for non-HTTPS token URL")
	}

	// localhost should be allowed
	srv := testutil.NewMockTokenServer(3600, "read:users")
	defer srv.Close()
	_, err = New(srv.URL, "client", WithClientSecret("secret"))
	if err != nil {
		t.Fatalf("expected localhost to be allowed, got: %v", err)
	}
}

func TestClient_WithSecretProvider(t *testing.T) {
	srv := testutil.NewMockTokenServer(3600, "read:users")
	defer srv.Close()

	sp := &staticSecret{val: "provider-secret"}
	client, err := New(srv.URL, "test-client",
		WithSecretProvider(sp, "client_secret"),
	)
	if err != nil {
		t.Fatal(err)
	}

	tok, err := client.Token(context.Background())
	if err != nil {
		t.Fatalf("Token() error: %v", err)
	}
	if tok.AccessToken == "" {
		t.Fatal("expected non-empty token")
	}
}

type staticSecret struct{ val string }

func (s *staticSecret) GetSecret(_ context.Context, _ string) (string, error) {
	return s.val, nil
}

func TestClient_WithAllOptions(t *testing.T) {
	srv := testutil.NewMockTokenServer(3600, "read:users")
	defer srv.Close()

	_, err := New(srv.URL, "test-client",
		WithClientSecret("secret"),
		WithExpiryBuffer(10*time.Second),
		WithHTTPClient(http.DefaultClient),
		WithEventHandler(nil),
		WithServiceName("my-svc"),
	)
	if err != nil {
		t.Fatal(err)
	}
}

func TestClient_TokenServerError(t *testing.T) {
	// Create a server that returns 500
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	client, err := New(srv.URL, "test-client", WithClientSecret("secret"))
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Token(context.Background())
	if err == nil {
		t.Fatal("expected error from 500 response")
	}
}

func TestClient_AuthenticateFailure(t *testing.T) {
	// Server that returns 401
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	client, err := New(srv.URL, "test-client", WithClientSecret("bad-secret"))
	if err != nil {
		t.Fatal(err)
	}

	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/users", nil)
	err = client.Authenticate(context.Background(), req)
	if err == nil {
		t.Fatal("expected error when token fetch fails")
	}
}

func TestClient_InvalidTokenURL(t *testing.T) {
	_, err := New("://bad-url", "client", WithClientSecret("secret"))
	if err == nil {
		t.Fatal("expected error for invalid URL")
	}
}

func TestClient_TokenBadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("not-json"))
	}))
	defer srv.Close()

	client, err := New(srv.URL, "test-client", WithClientSecret("secret"))
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Token(context.Background())
	if err == nil {
		t.Fatal("expected error from bad JSON response")
	}
}

func TestClient_EmptyAccessToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"","token_type":"Bearer","expires_in":3600}`))
	}))
	defer srv.Close()

	client, err := New(srv.URL, "test-client", WithClientSecret("secret"))
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Token(context.Background())
	if err == nil {
		t.Fatal("expected error for empty access_token")
	}
}

func TestClient_SecretProviderError(t *testing.T) {
	srv := testutil.NewMockTokenServer(3600, "read")
	defer srv.Close()

	sp := &failingSecret{}
	client, err := New(srv.URL, "test-client", WithSecretProvider(sp, "key"))
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Token(context.Background())
	if err == nil {
		t.Fatal("expected error from secret provider")
	}
}

type failingSecret struct{}

func (f *failingSecret) GetSecret(_ context.Context, _ string) (string, error) {
	return "", fmt.Errorf("vault unavailable")
}

func TestClient_NetworkError(t *testing.T) {
	// Use a URL that will fail to connect
	client, err := New("http://127.0.0.1:1/token", "test-client", WithClientSecret("secret"))
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Token(context.Background())
	if err == nil {
		t.Fatal("expected network error")
	}
}
