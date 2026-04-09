package oauth2

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
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
	var fetchCount atomic.Int32
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
	_ = fetchCount
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
