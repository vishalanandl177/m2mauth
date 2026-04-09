// Package jwt provides server-side JWT validation for M2M authentication.
// It supports JWKS key fetching, audience/issuer/scope enforcement, and
// multiple signing algorithms (RS256, RS384, RS512, ES256, ES384, ES512).
package jwt

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/vishalanandl177/m2mauth"
	"github.com/vishalanandl177/m2mauth/authlog"
)

// Config holds the configuration for a JWT validator.
type Config struct {
	// JWKSURL is the URL of the JSON Web Key Set endpoint.
	JWKSURL string

	// JWKSRefreshInterval controls how often the JWKS is re-fetched.
	// Defaults to 1 hour.
	JWKSRefreshInterval time.Duration

	// Issuer is the expected token issuer (iss claim).
	Issuer string

	// Audiences are the expected token audiences (aud claim).
	Audiences []string

	// RequiredScopes are scopes that must be present in the token.
	RequiredScopes []string

	// ScopesClaim is the claim name for scopes. Defaults to "scope".
	ScopesClaim string

	// Algorithms is the list of accepted signing algorithms.
	// Defaults to ["RS256"].
	Algorithms []string

	// MinRefreshInterval is the minimum time between JWKS refreshes,
	// preventing thundering herd on key misses. Defaults to 5 seconds.
	MinRefreshInterval time.Duration

	// ClockSkew is the allowed clock skew for time-based validation.
	// Defaults to 30 seconds.
	ClockSkew time.Duration

	// HTTPClient is used to fetch the JWKS. Defaults to http.DefaultClient.
	HTTPClient *http.Client

	// EventHandler receives auth events.
	EventHandler authlog.EventHandler

	// ServiceName identifies this validator in logs.
	ServiceName string
}

// Option configures a Config.
type Option func(*Config)

func WithJWKSURL(url string) Option          { return func(c *Config) { c.JWKSURL = url } }
func WithJWKSRefreshInterval(d time.Duration) Option {
	return func(c *Config) { c.JWKSRefreshInterval = d }
}
func WithIssuer(iss string) Option            { return func(c *Config) { c.Issuer = iss } }
func WithAudience(aud ...string) Option       { return func(c *Config) { c.Audiences = aud } }
func WithRequiredScopes(scopes ...string) Option {
	return func(c *Config) { c.RequiredScopes = scopes }
}
func WithScopesClaim(claim string) Option     { return func(c *Config) { c.ScopesClaim = claim } }
func WithAlgorithms(algs ...string) Option    { return func(c *Config) { c.Algorithms = algs } }
func WithMinRefreshInterval(d time.Duration) Option {
	return func(c *Config) { c.MinRefreshInterval = d }
}
func WithClockSkew(d time.Duration) Option { return func(c *Config) { c.ClockSkew = d } }
func WithHTTPClient(hc *http.Client) Option   { return func(c *Config) { c.HTTPClient = hc } }
func WithEventHandler(h authlog.EventHandler) Option {
	return func(c *Config) { c.EventHandler = h }
}
func WithServiceName(name string) Option { return func(c *Config) { c.ServiceName = name } }

// Validator validates JWTs on inbound HTTP requests.
type Validator struct {
	cfg  Config
	jwks *jwksCache
}

// New creates a new JWT validator.
func New(opts ...Option) (*Validator, error) {
	cfg := Config{
		JWKSRefreshInterval: time.Hour,
		MinRefreshInterval:  5 * time.Second,
		ScopesClaim:         "scope",
		Algorithms:          []string{"RS256"},
		ClockSkew:           30 * time.Second,
		HTTPClient:          http.DefaultClient,
		EventHandler:        authlog.NopHandler(),
		ServiceName:         "jwt-validator",
	}
	for _, o := range opts {
		o(&cfg)
	}

	if cfg.JWKSURL == "" {
		return nil, fmt.Errorf("m2mauth/jwt: JWKS URL is required")
	}
	parsed, err := url.Parse(cfg.JWKSURL)
	if err != nil {
		return nil, fmt.Errorf("m2mauth/jwt: invalid JWKS URL: %w", err)
	}
	if parsed.Scheme != "https" && !strings.HasPrefix(parsed.Host, "localhost") && !strings.HasPrefix(parsed.Host, "127.0.0.1") {
		return nil, fmt.Errorf("m2mauth/jwt: JWKS URL must use HTTPS")
	}

	return &Validator{
		cfg:  cfg,
		jwks: newJWKSCache(cfg.JWKSURL, cfg.HTTPClient, cfg.JWKSRefreshInterval, cfg.MinRefreshInterval),
	}, nil
}

// Validate extracts and validates the JWT from an inbound HTTP request.
// It satisfies the m2mauth.Validator interface.
func (v *Validator) Validate(ctx context.Context, req *http.Request) (*m2mauth.Claims, error) {
	start := time.Now()

	tokenStr, err := extractBearerToken(req)
	if err != nil {
		authlog.Emit(ctx, v.cfg.EventHandler, authlog.EventAuthFailure, v.cfg.ServiceName,
			map[string]string{"reason": "missing_token"}, time.Since(start), err)
		return nil, err
	}

	claims, err := v.ValidateToken(ctx, tokenStr)
	dur := time.Since(start)
	if err != nil {
		authlog.Emit(ctx, v.cfg.EventHandler, authlog.EventAuthFailure, v.cfg.ServiceName,
			map[string]string{"reason": err.Error()}, dur, err)
		return nil, err
	}

	authlog.Emit(ctx, v.cfg.EventHandler, authlog.EventAuthSuccess, v.cfg.ServiceName,
		map[string]string{"subject": claims.Subject}, dur, nil)
	return claims, nil
}

// ValidateToken validates a raw JWT string and returns the claims.
func (v *Validator) ValidateToken(ctx context.Context, tokenStr string) (*m2mauth.Claims, error) {
	// Split token.
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, m2mauth.ErrInvalidToken
	}

	// Decode header.
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, m2mauth.ErrInvalidToken
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, m2mauth.ErrInvalidToken
	}

	// Check algorithm.
	algAllowed := false
	for _, a := range v.cfg.Algorithms {
		if a == header.Alg {
			algAllowed = true
			break
		}
	}
	if !algAllowed {
		return nil, m2mauth.ErrInvalidToken
	}

	// Get signing key from JWKS (also validates key algorithm matches token).
	key, err := v.jwks.getKey(ctx, header.Kid, header.Alg)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", m2mauth.ErrInvalidSignature, err)
	}

	// Verify signature.
	signingInput := parts[0] + "." + parts[1]
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, m2mauth.ErrInvalidSignature
	}

	if err := verifySignature(header.Alg, key, []byte(signingInput), signature); err != nil {
		return nil, m2mauth.ErrInvalidSignature
	}

	// Decode payload.
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, m2mauth.ErrInvalidToken
	}

	var payload struct {
		Sub   string   `json:"sub"`
		Iss   string   `json:"iss"`
		Aud   audience `json:"aud"`
		Iat   float64  `json:"iat"`
		Exp   float64  `json:"exp"`
		Nbf   float64  `json:"nbf"`
		Scope string   `json:"scope"`
	}

	// Dynamically handle scope claim name.
	var rawPayload map[string]json.RawMessage
	if err := json.Unmarshal(payloadJSON, &rawPayload); err != nil {
		return nil, m2mauth.ErrInvalidToken
	}
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return nil, m2mauth.ErrInvalidToken
	}

	// If custom scope claim, extract it.
	if v.cfg.ScopesClaim != "scope" {
		if raw, ok := rawPayload[v.cfg.ScopesClaim]; ok {
			var s string
			if err := json.Unmarshal(raw, &s); err == nil {
				payload.Scope = s
			}
		}
	}

	now := time.Now()

	// Validate expiry.
	if payload.Exp > 0 {
		expTime := time.Unix(int64(payload.Exp), 0)
		if now.After(expTime.Add(v.cfg.ClockSkew)) {
			return nil, m2mauth.ErrTokenExpired
		}
	}

	// Validate not-before.
	if payload.Nbf > 0 {
		nbfTime := time.Unix(int64(payload.Nbf), 0)
		if now.Before(nbfTime.Add(-v.cfg.ClockSkew)) {
			return nil, m2mauth.ErrTokenNotYetValid
		}
	}

	// Validate issuer.
	if v.cfg.Issuer != "" && payload.Iss != v.cfg.Issuer {
		return nil, m2mauth.ErrInvalidIssuer
	}

	// Validate audience.
	if len(v.cfg.Audiences) > 0 {
		found := false
		for _, expected := range v.cfg.Audiences {
			for _, got := range payload.Aud {
				if got == expected {
					found = true
					break
				}
			}
		}
		if !found {
			return nil, m2mauth.ErrInvalidAudience
		}
	}

	// Parse scopes.
	var scopes []string
	if payload.Scope != "" {
		scopes = strings.Split(payload.Scope, " ")
	}

	// Validate required scopes.
	if len(v.cfg.RequiredScopes) > 0 {
		have := make(map[string]struct{}, len(scopes))
		for _, s := range scopes {
			have[s] = struct{}{}
		}
		for _, req := range v.cfg.RequiredScopes {
			if _, ok := have[req]; !ok {
				return nil, m2mauth.ErrInsufficientScope
			}
		}
	}

	// Build extra claims.
	extra := make(map[string]any)
	for k, v := range rawPayload {
		switch k {
		case "sub", "iss", "aud", "iat", "exp", "nbf", "scope":
			continue
		default:
			var val any
			json.Unmarshal(v, &val)
			extra[k] = val
		}
	}

	claims := &m2mauth.Claims{
		Subject:   payload.Sub,
		Issuer:    payload.Iss,
		Audience:  payload.Aud,
		Scopes:    scopes,
		IssuedAt:  time.Unix(int64(payload.Iat), 0),
		ExpiresAt: time.Unix(int64(payload.Exp), 0),
		Extra:     extra,
	}

	return claims, nil
}

// audience handles both string and []string JSON for the "aud" claim.
type audience []string

func (a *audience) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*a = []string{single}
		return nil
	}
	var multi []string
	if err := json.Unmarshal(data, &multi); err != nil {
		return err
	}
	*a = multi
	return nil
}

func extractBearerToken(req *http.Request) (string, error) {
	auth := req.Header.Get("Authorization")
	if auth == "" {
		return "", m2mauth.ErrMissingToken
	}
	if !strings.HasPrefix(auth, "Bearer ") {
		return "", m2mauth.ErrMissingToken
	}
	return strings.TrimPrefix(auth, "Bearer "), nil
}

func verifySignature(alg string, key crypto.PublicKey, signingInput, signature []byte) error {
	hash := crypto.SHA256
	switch alg {
	case "RS256", "ES256":
		hash = crypto.SHA256
	case "RS384", "ES384":
		hash = crypto.SHA384
	case "RS512", "ES512":
		hash = crypto.SHA512
	default:
		return fmt.Errorf("unsupported algorithm: %s", alg)
	}

	h := hash.New()
	h.Write(signingInput)
	hashed := h.Sum(nil)

	switch k := key.(type) {
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(k, hash, hashed, signature)
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(k, hashed, signature) {
			return errors.New("ECDSA verification failed")
		}
		return nil
	default:
		return fmt.Errorf("unsupported key type: %T", key)
	}
}

// --- JWKS Cache ---

// jwkEntry holds a parsed public key together with the algorithm declared in JWKS.
type jwkEntry struct {
	key crypto.PublicKey
	alg string
}

type jwksCache struct {
	url      string
	client   *http.Client
	interval time.Duration
	minRefreshInterval time.Duration

	mu         sync.RWMutex
	keys       map[string]jwkEntry
	lastFetch  time.Time
}

func newJWKSCache(url string, client *http.Client, interval, minRefreshInterval time.Duration) *jwksCache {
	return &jwksCache{
		url:                url,
		client:             client,
		interval:           interval,
		minRefreshInterval: minRefreshInterval,
		keys:               make(map[string]jwkEntry),
	}
}

func (c *jwksCache) getKey(ctx context.Context, kid, alg string) (crypto.PublicKey, error) {
	c.mu.RLock()
	entry, ok := c.keys[kid]
	needsRefresh := time.Since(c.lastFetch) > c.interval
	c.mu.RUnlock()

	if ok && !needsRefresh {
		if entry.alg != "" && entry.alg != alg {
			return nil, fmt.Errorf("key %q algorithm %q does not match token algorithm %q", kid, entry.alg, alg)
		}
		return entry.key, nil
	}

	// Refresh and retry.
	if err := c.refresh(ctx); err != nil {
		// If we had a cached key, return it despite refresh failure.
		if ok {
			if entry.alg != "" && entry.alg != alg {
				return nil, fmt.Errorf("key %q algorithm %q does not match token algorithm %q", kid, entry.alg, alg)
			}
			return entry.key, nil
		}
		return nil, fmt.Errorf("JWKS fetch failed: %w", err)
	}

	c.mu.RLock()
	entry, ok = c.keys[kid]
	c.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("key %q not found in JWKS", kid)
	}
	if entry.alg != "" && entry.alg != alg {
		return nil, fmt.Errorf("key %q algorithm %q does not match token algorithm %q", kid, entry.alg, alg)
	}
	return entry.key, nil
}

func (c *jwksCache) refresh(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Double-check: another goroutine may have refreshed.
	if time.Since(c.lastFetch) < c.minRefreshInterval {
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS endpoint returned HTTP %d", resp.StatusCode)
	}

	var jwksResp struct {
		Keys []jwkKey `json:"keys"`
	}
	// Limit response body to 10MB to prevent resource exhaustion.
	limitedBody := io.LimitReader(resp.Body, 10*1024*1024)
	if err := json.NewDecoder(limitedBody).Decode(&jwksResp); err != nil {
		return fmt.Errorf("decode JWKS: %w", err)
	}

	keys := make(map[string]jwkEntry, len(jwksResp.Keys))
	for _, k := range jwksResp.Keys {
		pub, err := k.toPublicKey()
		if err != nil {
			continue // Skip keys we can't parse.
		}
		keys[k.Kid] = jwkEntry{key: pub, alg: k.Alg}
	}

	c.keys = keys
	c.lastFetch = time.Now()
	return nil
}

type jwkKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func (k *jwkKey) toPublicKey() (crypto.PublicKey, error) {
	switch k.Kty {
	case "RSA":
		return k.toRSAPublicKey()
	case "EC":
		return k.toECPublicKey()
	default:
		return nil, fmt.Errorf("unsupported key type: %s", k.Kty)
	}
}

func (k *jwkKey) toRSAPublicKey() (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, err
	}

	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)

	// Validate exponent is a safe positive integer (prevents truncation attacks).
	if e.Sign() <= 0 || !e.IsInt64() || e.Int64() > math.MaxInt32 {
		return nil, fmt.Errorf("invalid RSA exponent")
	}

	return &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}, nil
}

func (k *jwkKey) toECPublicKey() (*ecdsa.PublicKey, error) {
	xBytes, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, err
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil {
		return nil, err
	}

	curve, err := curveFromName(k.Crv)
	if err != nil {
		return nil, err
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}, nil
}

func curveFromName(name string) (ellipticCurve, error) {
	switch name {
	case "P-256":
		return ellipticP256(), nil
	case "P-384":
		return ellipticP384(), nil
	case "P-521":
		return ellipticP521(), nil
	default:
		return nil, fmt.Errorf("unsupported curve: %s", name)
	}
}
