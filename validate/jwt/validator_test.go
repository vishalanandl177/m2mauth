package jwt

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
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
	v, _ := New(WithJWKSURL("https://unused.example.com/jwks"))
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

func TestNew_RequiresJWKSURL(t *testing.T) {
	_, err := New()
	if err == nil {
		t.Fatal("expected error for missing JWKS URL")
	}
}

func TestNew_RequiresHTTPS(t *testing.T) {
	_, err := New(WithJWKSURL("http://remote.example.com/jwks"))
	if err == nil {
		t.Fatal("expected error for non-HTTPS JWKS URL")
	}

	// localhost should be allowed
	_, err = New(WithJWKSURL("http://127.0.0.1:9999/jwks"))
	if err != nil {
		t.Fatalf("expected localhost to be allowed: %v", err)
	}
}

func TestValidator_InvalidToken_Malformed(t *testing.T) {
	_, jwksServer := setupTestJWKS(t)
	defer jwksServer.Close()

	v, err := New(WithJWKSURL(jwksServer.URL))
	if err != nil {
		t.Fatal(err)
	}

	// Not a JWT
	_, err = v.ValidateToken(context.Background(), "not-a-jwt")
	if err == nil {
		t.Fatal("expected error for malformed token")
	}

	// Two parts only
	_, err = v.ValidateToken(context.Background(), "a.b")
	if err == nil {
		t.Fatal("expected error for two-part token")
	}

	// Bad base64 header
	_, err = v.ValidateToken(context.Background(), "!!!.bbb.ccc")
	if err == nil {
		t.Fatal("expected error for bad base64 header")
	}

	// Valid base64 but invalid JSON header
	_, err = v.ValidateToken(context.Background(), "bm90LWpzb24.bbb.ccc")
	if err == nil {
		t.Fatal("expected error for non-JSON header")
	}
}

func TestValidator_DisallowedAlgorithm(t *testing.T) {
	key, jwksServer := setupTestJWKS(t)
	defer jwksServer.Close()

	v, err := New(
		WithJWKSURL(jwksServer.URL),
		WithAlgorithms("ES256"), // Only allow ES256
	)
	if err != nil {
		t.Fatal(err)
	}

	token := createTestJWT(t, key, map[string]any{
		"sub": "svc-test",
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	_, err = v.ValidateToken(context.Background(), token)
	if err == nil {
		t.Fatal("expected error for disallowed algorithm")
	}
}

func TestValidator_BadSignature(t *testing.T) {
	_, jwksServer := setupTestJWKS(t)
	defer jwksServer.Close()

	v, err := New(WithJWKSURL(jwksServer.URL))
	if err != nil {
		t.Fatal(err)
	}

	// Create a token signed with a different key
	otherKey, err2 := rsa.GenerateKey(rand.Reader, 2048)
	if err2 != nil {
		t.Fatal(err2)
	}
	token := createTestJWT(t, otherKey, map[string]any{
		"sub": "svc-test",
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	_, err = v.ValidateToken(context.Background(), token)
	if err == nil {
		t.Fatal("expected error for bad signature")
	}
}

func TestValidator_NotBefore(t *testing.T) {
	key, jwksServer := setupTestJWKS(t)
	defer jwksServer.Close()

	v, err := New(WithJWKSURL(jwksServer.URL), WithClockSkew(0))
	if err != nil {
		t.Fatal(err)
	}

	token := createTestJWT(t, key, map[string]any{
		"sub": "svc-test",
		"nbf": time.Now().Add(time.Hour).Unix(),
		"exp": time.Now().Add(2 * time.Hour).Unix(),
	})

	_, err = v.ValidateToken(context.Background(), token)
	if err == nil {
		t.Fatal("expected error for not-yet-valid token")
	}
}

func TestValidator_CustomScopesClaim(t *testing.T) {
	key, jwksServer := setupTestJWKS(t)
	defer jwksServer.Close()

	v, err := New(
		WithJWKSURL(jwksServer.URL),
		WithScopesClaim("permissions"),
		WithRequiredScopes("admin"),
	)
	if err != nil {
		t.Fatal(err)
	}

	token := createTestJWT(t, key, map[string]any{
		"sub":         "svc-test",
		"permissions": "admin editor",
		"exp":         time.Now().Add(time.Hour).Unix(),
	})

	claims, err := v.ValidateToken(context.Background(), token)
	if err != nil {
		t.Fatalf("ValidateToken error: %v", err)
	}
	if !claims.HasScope("admin") {
		t.Error("expected admin scope from custom claim")
	}
}

func TestValidator_ExtraClaimsExtracted(t *testing.T) {
	key, jwksServer := setupTestJWKS(t)
	defer jwksServer.Close()

	v, err := New(WithJWKSURL(jwksServer.URL))
	if err != nil {
		t.Fatal(err)
	}

	token := createTestJWT(t, key, map[string]any{
		"sub":       "svc-test",
		"exp":       time.Now().Add(time.Hour).Unix(),
		"tenant_id": "org-123",
		"role":      "admin",
	})

	claims, err := v.ValidateToken(context.Background(), token)
	if err != nil {
		t.Fatalf("ValidateToken error: %v", err)
	}
	if claims.Extra["tenant_id"] != "org-123" {
		t.Errorf("expected tenant_id org-123 in extra, got %v", claims.Extra)
	}
	if claims.Extra["role"] != "admin" {
		t.Errorf("expected role admin in extra, got %v", claims.Extra)
	}
}

func TestValidator_InvalidAudience(t *testing.T) {
	key, jwksServer := setupTestJWKS(t)
	defer jwksServer.Close()

	v, err := New(
		WithJWKSURL(jwksServer.URL),
		WithAudience("https://expected.com"),
	)
	if err != nil {
		t.Fatal(err)
	}

	token := createTestJWT(t, key, map[string]any{
		"sub": "svc-test",
		"aud": "https://wrong.com",
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	_, err = v.ValidateToken(context.Background(), token)
	if err == nil {
		t.Fatal("expected error for wrong audience")
	}
}

func TestValidator_BearerPrefixRequired(t *testing.T) {
	_, jwksServer := setupTestJWKS(t)
	defer jwksServer.Close()

	v, err := New(WithJWKSURL(jwksServer.URL))
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.Header.Set("Authorization", "Basic abc123")

	_, err = v.Validate(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for non-Bearer auth")
	}
}

func TestValidator_WithAllOptions(t *testing.T) {
	_, jwksServer := setupTestJWKS(t)
	defer jwksServer.Close()

	_, err := New(
		WithJWKSURL(jwksServer.URL),
		WithJWKSRefreshInterval(30*time.Minute),
		WithMinRefreshInterval(2*time.Second),
		WithHTTPClient(http.DefaultClient),
		WithEventHandler(nil),
		WithServiceName("my-jwt-validator"),
	)
	if err != nil {
		t.Fatal(err)
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

// --- ECDSA tests ---

func setupTestECDSAJWKS(t *testing.T) (*ecdsa.PrivateKey, *httptest.Server) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	xB64 := base64.RawURLEncoding.EncodeToString(key.PublicKey.X.Bytes())
	yB64 := base64.RawURLEncoding.EncodeToString(key.PublicKey.Y.Bytes())

	jwks := map[string]any{
		"keys": []map[string]any{
			{
				"kty": "EC",
				"kid": "ec-key-1",
				"alg": "ES256",
				"use": "sig",
				"crv": "P-256",
				"x":   xB64,
				"y":   yB64,
			},
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	}))

	return key, srv
}

func createTestECDSAJWT(t *testing.T, key *ecdsa.PrivateKey, claims map[string]any) string {
	t.Helper()

	header := map[string]string{"alg": "ES256", "typ": "JWT", "kid": "ec-key-1"}
	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	signingInput := fmt.Sprintf("%s.%s", headerB64, claimsB64)
	h := sha256.Sum256([]byte(signingInput))

	sig, err := ecdsa.SignASN1(rand.Reader, key, h[:])
	if err != nil {
		t.Fatal(err)
	}
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	return fmt.Sprintf("%s.%s.%s", headerB64, claimsB64, sigB64)
}

func TestValidator_ECDSA_ES256(t *testing.T) {
	key, jwksServer := setupTestECDSAJWKS(t)
	defer jwksServer.Close()

	v, err := New(
		WithJWKSURL(jwksServer.URL),
		WithAlgorithms("ES256"),
	)
	if err != nil {
		t.Fatal(err)
	}

	token := createTestECDSAJWT(t, key, map[string]any{
		"sub": "svc-ecdsa",
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	claims, err := v.ValidateToken(context.Background(), token)
	if err != nil {
		t.Fatalf("ValidateToken error: %v", err)
	}
	if claims.Subject != "svc-ecdsa" {
		t.Errorf("expected subject svc-ecdsa, got %q", claims.Subject)
	}
}

func TestValidator_ECDSA_BadSignature(t *testing.T) {
	_, jwksServer := setupTestECDSAJWKS(t)
	defer jwksServer.Close()

	// Create token signed with a different key
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	v, err := New(
		WithJWKSURL(jwksServer.URL),
		WithAlgorithms("ES256"),
	)
	if err != nil {
		t.Fatal(err)
	}

	token := createTestECDSAJWT(t, otherKey, map[string]any{
		"sub": "svc-test",
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	_, err = v.ValidateToken(context.Background(), token)
	if err == nil {
		t.Fatal("expected error for bad ECDSA signature")
	}
}

// --- JWKS error path tests ---

func TestValidator_JWKSServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	v, err := New(WithJWKSURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}

	// Generate a valid-looking token that needs JWKS to verify
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	token := createTestJWT(t, key, map[string]any{
		"sub": "svc-test",
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	_, err = v.ValidateToken(context.Background(), token)
	if err == nil {
		t.Fatal("expected error when JWKS server returns 500")
	}
}

func TestValidator_JWKSBadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not-json"))
	}))
	defer srv.Close()

	v, err := New(WithJWKSURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	token := createTestJWT(t, key, map[string]any{
		"sub": "svc-test",
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	_, err = v.ValidateToken(context.Background(), token)
	if err == nil {
		t.Fatal("expected error when JWKS returns bad JSON")
	}
}

func TestValidator_JWKSKeyNotFound(t *testing.T) {
	// JWKS with no keys
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"keys": []any{}})
	}))
	defer srv.Close()

	v, err := New(WithJWKSURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	token := createTestJWT(t, key, map[string]any{
		"sub": "svc-test",
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	_, err = v.ValidateToken(context.Background(), token)
	if err == nil {
		t.Fatal("expected error when key not found in JWKS")
	}
}

func TestValidator_JWKSUnsupportedKeyType(t *testing.T) {
	// JWKS with an unsupported key type
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwks := map[string]any{
			"keys": []map[string]any{
				{
					"kty": "OKP",
					"kid": "test-key-1",
					"alg": "EdDSA",
				},
			},
		}
		json.NewEncoder(w).Encode(jwks)
	}))
	defer srv.Close()

	v, err := New(WithJWKSURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	token := createTestJWT(t, key, map[string]any{
		"sub": "svc-test",
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	_, err = v.ValidateToken(context.Background(), token)
	if err == nil {
		t.Fatal("expected error for unsupported key type")
	}
}

func TestValidator_BadSignatureBase64(t *testing.T) {
	_, jwksServer := setupTestJWKS(t)
	defer jwksServer.Close()

	v, err := New(WithJWKSURL(jwksServer.URL))
	if err != nil {
		t.Fatal(err)
	}

	// Create a token with valid header but invalid base64 signature
	header := map[string]string{"alg": "RS256", "typ": "JWT", "kid": "test-key-1"}
	headerJSON, _ := json.Marshal(header)
	claimsMap := map[string]any{"sub": "test", "exp": time.Now().Add(time.Hour).Unix()}
	claimsJSON, _ := json.Marshal(claimsMap)

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	token := fmt.Sprintf("%s.%s.!!!invalid-base64!!!", headerB64, claimsB64)

	_, err = v.ValidateToken(context.Background(), token)
	if err == nil {
		t.Fatal("expected error for bad signature base64")
	}
}

func TestValidator_UnsupportedVerifyAlgorithm(t *testing.T) {
	// Test verifySignature with unsupported algorithm
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	err := verifySignature("RS999", &key.PublicKey, []byte("test"), []byte("sig"))
	if err == nil {
		t.Fatal("expected error for unsupported algorithm")
	}
}

func TestValidator_UnsupportedKeyTypeInVerify(t *testing.T) {
	// Test verifySignature with unsupported key type
	type fakeKey struct{}
	err := verifySignature("RS256", fakeKey{}, []byte("test"), []byte("sig"))
	if err == nil {
		t.Fatal("expected error for unsupported key type")
	}
}

func TestJWKS_ECCurves(t *testing.T) {
	curves := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P-256", elliptic.P256()},
		{"P-384", elliptic.P384()},
		{"P-521", elliptic.P521()},
	}

	for _, tc := range curves {
		t.Run(tc.name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}

			jwk := jwkKey{
				Kty: "EC",
				Kid: "ec-key",
				Crv: tc.name,
				X:   base64.RawURLEncoding.EncodeToString(key.PublicKey.X.Bytes()),
				Y:   base64.RawURLEncoding.EncodeToString(key.PublicKey.Y.Bytes()),
			}

			pub, err := jwk.toPublicKey()
			if err != nil {
				t.Fatalf("toPublicKey error: %v", err)
			}
			ecPub, ok := pub.(*ecdsa.PublicKey)
			if !ok {
				t.Fatalf("expected *ecdsa.PublicKey, got %T", pub)
			}
			if ecPub.Curve != tc.curve {
				t.Errorf("curve mismatch")
			}
		})
	}
}

func TestJWKS_UnsupportedCurve(t *testing.T) {
	jwk := jwkKey{
		Kty: "EC",
		Kid: "ec-key",
		Crv: "P-999",
		X:   base64.RawURLEncoding.EncodeToString([]byte("x")),
		Y:   base64.RawURLEncoding.EncodeToString([]byte("y")),
	}
	_, err := jwk.toPublicKey()
	if err == nil {
		t.Fatal("expected error for unsupported curve")
	}
}

func TestJWKS_BadECBase64(t *testing.T) {
	// Bad X
	jwk := jwkKey{Kty: "EC", Crv: "P-256", X: "!!!bad!!!", Y: "AAAA"}
	_, err := jwk.toECPublicKey()
	if err == nil {
		t.Fatal("expected error for bad X base64")
	}

	// Bad Y
	jwk2 := jwkKey{Kty: "EC", Crv: "P-256", X: "AAAA", Y: "!!!bad!!!"}
	_, err = jwk2.toECPublicKey()
	if err == nil {
		t.Fatal("expected error for bad Y base64")
	}
}

func TestJWKS_BadRSABase64(t *testing.T) {
	// Bad N
	jwk := jwkKey{Kty: "RSA", N: "!!!bad!!!", E: "AQAB"}
	_, err := jwk.toRSAPublicKey()
	if err == nil {
		t.Fatal("expected error for bad N base64")
	}

	// Bad E
	jwk2 := jwkKey{Kty: "RSA", N: "AAAA", E: "!!!bad!!!"}
	_, err = jwk2.toRSAPublicKey()
	if err == nil {
		t.Fatal("expected error for bad E base64")
	}
}

func TestJWKS_AlgorithmMismatch(t *testing.T) {
	// Create JWKS server with RSA key that has alg: "RS256"
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	nB64 := base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes())
	eB64 := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes())

	jwks := map[string]any{
		"keys": []map[string]any{{
			"kty": "RSA",
			"kid": "test-key-1",
			"alg": "RS384", // Key declares RS384
			"n":   nB64,
			"e":   eB64,
		}},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jwks)
	}))
	defer srv.Close()

	v, err := New(
		WithJWKSURL(srv.URL),
		WithAlgorithms("RS256", "RS384"),
	)
	if err != nil {
		t.Fatal(err)
	}

	// Token uses RS256 but key declares RS384 — should fail
	token := createTestJWT(t, key, map[string]any{
		"sub": "svc-test",
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	_, err = v.ValidateToken(context.Background(), token)
	if err == nil {
		t.Fatal("expected error for algorithm mismatch between token and JWKS key")
	}
}
