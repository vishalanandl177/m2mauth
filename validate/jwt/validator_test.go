package jwt

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestValidator_ValidateToken(t *testing.T) {
	key, jwksServer := setupTestJWKS(t)
	defer jwksServer.Close()

	v, err := New(
		WithJWKSURL(jwksServer.URL),
		WithIssuer("https://auth.example.com/"),
		WithAudience("https://api.example.com"),
		WithRequiredScopes("read:users"),
	)
	if err != nil {
		t.Fatal(err)
	}

	token := createTestJWT(t, key, map[string]any{
		"sub":   "svc-orders",
		"iss":   "https://auth.example.com/",
		"aud":   "https://api.example.com",
		"scope": "read:users write:orders",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
	})

	claims, err := v.ValidateToken(context.Background(), token)
	if err != nil {
		t.Fatalf("ValidateToken error: %v", err)
	}
	if claims.Subject != "svc-orders" {
		t.Errorf("expected subject svc-orders, got %q", claims.Subject)
	}
	if !claims.HasScope("read:users") {
		t.Error("expected scope read:users")
	}
	if !claims.HasScope("write:orders") {
		t.Error("expected scope write:orders")
	}
}

func TestValidator_Validate_HTTP(t *testing.T) {
	key, jwksServer := setupTestJWKS(t)
	defer jwksServer.Close()

	v, err := New(WithJWKSURL(jwksServer.URL))
	if err != nil {
		t.Fatal(err)
	}

	token := createTestJWT(t, key, map[string]any{
		"sub": "svc-test",
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	claims, err := v.Validate(context.Background(), req)
	if err != nil {
		t.Fatalf("Validate error: %v", err)
	}
	if claims.Subject != "svc-test" {
		t.Errorf("expected subject svc-test, got %q", claims.Subject)
	}
}

func TestValidator_ExpiredToken(t *testing.T) {
	key, jwksServer := setupTestJWKS(t)
	defer jwksServer.Close()

	v, err := New(WithJWKSURL(jwksServer.URL), WithClockSkew(0))
	if err != nil {
		t.Fatal(err)
	}

	token := createTestJWT(t, key, map[string]any{
		"sub": "svc-test",
		"exp": time.Now().Add(-time.Hour).Unix(),
	})

	_, err = v.ValidateToken(context.Background(), token)
	if err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestValidator_WrongIssuer(t *testing.T) {
	key, jwksServer := setupTestJWKS(t)
	defer jwksServer.Close()

	v, err := New(
		WithJWKSURL(jwksServer.URL),
		WithIssuer("https://expected.com/"),
	)
	if err != nil {
		t.Fatal(err)
	}

	token := createTestJWT(t, key, map[string]any{
		"sub": "svc-test",
		"iss": "https://wrong.com/",
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	_, err = v.ValidateToken(context.Background(), token)
	if err == nil {
		t.Fatal("expected error for wrong issuer")
	}
}

func TestValidator_InsufficientScope(t *testing.T) {
	key, jwksServer := setupTestJWKS(t)
	defer jwksServer.Close()

	v, err := New(
		WithJWKSURL(jwksServer.URL),
		WithRequiredScopes("admin:write"),
	)
	if err != nil {
		t.Fatal(err)
	}

	token := createTestJWT(t, key, map[string]any{
		"sub":   "svc-test",
		"scope": "read:users",
		"exp":   time.Now().Add(time.Hour).Unix(),
	})

	_, err = v.ValidateToken(context.Background(), token)
	if err == nil {
		t.Fatal("expected error for insufficient scope")
	}
}

func TestValidator_MissingToken(t *testing.T) {
	v, _ := New(WithJWKSURL("http://unused.example.com/jwks"))
	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)

	_, err := v.Validate(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for missing token")
	}
}

func TestValidator_AudienceArray(t *testing.T) {
	key, jwksServer := setupTestJWKS(t)
	defer jwksServer.Close()

	v, err := New(
		WithJWKSURL(jwksServer.URL),
		WithAudience("https://api.example.com"),
	)
	if err != nil {
		t.Fatal(err)
	}

	token := createTestJWT(t, key, map[string]any{
		"sub": "svc-test",
		"aud": []string{"https://api.example.com", "https://other.example.com"},
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	claims, err := v.ValidateToken(context.Background(), token)
	if err != nil {
		t.Fatalf("ValidateToken error: %v", err)
	}
	if len(claims.Audience) != 2 {
		t.Errorf("expected 2 audiences, got %d", len(claims.Audience))
	}
}

// --- Test helpers ---

func setupTestJWKS(t *testing.T) (*rsa.PrivateKey, *httptest.Server) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	nB64 := base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes())
	eB64 := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes())

	jwks := map[string]any{
		"keys": []map[string]any{
			{
				"kty": "RSA",
				"kid": "test-key-1",
				"alg": "RS256",
				"use": "sig",
				"n":   nB64,
				"e":   eB64,
			},
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	}))

	return key, srv
}

func createTestJWT(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()

	header := map[string]string{"alg": "RS256", "typ": "JWT", "kid": "test-key-1"}
	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	signingInput := fmt.Sprintf("%s.%s", headerB64, claimsB64)
	h := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
	if err != nil {
		t.Fatal(err)
	}
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	return fmt.Sprintf("%s.%s.%s", headerB64, claimsB64, sigB64)
}
