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

func benchSetupJWKS(b *testing.B) (*rsa.PrivateKey, *httptest.Server) {
	b.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatal(err)
	}
	nB64 := base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes())
	eB64 := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes())
	jwks := map[string]any{
		"keys": []map[string]any{{
			"kty": "RSA", "kid": "bench-key", "alg": "RS256", "use": "sig",
			"n": nB64, "e": eB64,
		}},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	}))
	return key, srv
}

func benchCreateJWT(b *testing.B, key *rsa.PrivateKey, claims map[string]any) string {
	b.Helper()
	header := map[string]string{"alg": "RS256", "typ": "JWT", "kid": "bench-key"}
	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signingInput := fmt.Sprintf("%s.%s", headerB64, claimsB64)
	h := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
	if err != nil {
		b.Fatal(err)
	}
	return fmt.Sprintf("%s.%s.%s", headerB64, claimsB64, base64.RawURLEncoding.EncodeToString(sig))
}

func BenchmarkJWTValidateToken(b *testing.B) {
	key, srv := benchSetupJWKS(b)
	defer srv.Close()

	v, err := New(
		WithJWKSURL(srv.URL),
		WithIssuer("https://auth.example.com/"),
		WithAudience("https://api.example.com"),
		WithRequiredScopes("read:users"),
	)
	if err != nil {
		b.Fatal(err)
	}

	token := benchCreateJWT(b, key, map[string]any{
		"sub":   "svc-bench",
		"iss":   "https://auth.example.com/",
		"aud":   "https://api.example.com",
		"scope": "read:users write:orders",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
	})

	ctx := context.Background()

	// Warm up JWKS cache
	v.ValidateToken(ctx, token)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := v.ValidateToken(ctx, token)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkJWTValidateTokenParallel(b *testing.B) {
	key, srv := benchSetupJWKS(b)
	defer srv.Close()

	v, err := New(WithJWKSURL(srv.URL))
	if err != nil {
		b.Fatal(err)
	}

	token := benchCreateJWT(b, key, map[string]any{
		"sub": "svc-bench",
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	ctx := context.Background()
	v.ValidateToken(ctx, token) // warm cache

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := v.ValidateToken(ctx, token)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkJWTValidateHTTP(b *testing.B) {
	key, srv := benchSetupJWKS(b)
	defer srv.Close()

	v, err := New(WithJWKSURL(srv.URL))
	if err != nil {
		b.Fatal(err)
	}

	token := benchCreateJWT(b, key, map[string]any{
		"sub": "svc-bench",
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	ctx := context.Background()
	v.ValidateToken(ctx, token) // warm cache

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		_, err := v.Validate(ctx, req)
		if err != nil {
			b.Fatal(err)
		}
	}
}
