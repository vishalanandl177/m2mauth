package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vishalanandl177/m2mauth"
)

// mockAuth is a simple Authenticator for testing.
type mockAuth struct {
	token string
	err   error
}

func (m *mockAuth) Authenticate(_ context.Context, req *http.Request) error {
	if m.err != nil {
		return m.err
	}
	req.Header.Set("Authorization", "Bearer "+m.token)
	return nil
}

func TestRoundTripper(t *testing.T) {
	var captured string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	client := &http.Client{
		Transport: NewRoundTripper(http.DefaultTransport, &mockAuth{token: "test-token"}),
	}

	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if captured != "Bearer test-token" {
		t.Errorf("expected 'Bearer test-token', got %q", captured)
	}
}

// mockValidator is a simple Validator for testing.
type mockValidator struct {
	claims *m2mauth.Claims
	err    error
}

func (m *mockValidator) Validate(_ context.Context, _ *http.Request) (*m2mauth.Claims, error) {
	return m.claims, m.err
}

func TestRequireAuth_Success(t *testing.T) {
	claims := &m2mauth.Claims{Subject: "svc-test", Scopes: []string{"read:users"}}
	v := &mockValidator{claims: claims}

	var gotClaims *m2mauth.Claims
	handler := RequireAuth(v)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, ok := m2mauth.ClaimsFromContext(r.Context())
		if ok {
			gotClaims = c
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if gotClaims == nil || gotClaims.Subject != "svc-test" {
		t.Error("expected claims in context")
	}
}

func TestRequireAuth_Failure(t *testing.T) {
	v := &mockValidator{err: m2mauth.ErrMissingToken}

	handler := RequireAuth(v)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called on auth failure")
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}
