// Package apikey provides server-side API key validation for inbound requests.
package apikey

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net/http"

	"github.com/vishalanandl177/m2mauth"
	"github.com/vishalanandl177/m2mauth/authlog"
)

// KeyStore looks up API key metadata. Implement this interface to back
// the validator with a database, Redis, config file, etc.
//
// Security: implementations MUST use constant-time comparison
// (crypto/subtle.ConstantTimeCompare) when matching keys to prevent
// timing side-channel attacks. See MapStore for a reference implementation.
type KeyStore interface {
	// Lookup returns the claims associated with the given API key.
	// Returns nil claims and nil error if the key is not found.
	Lookup(ctx context.Context, key string) (*m2mauth.Claims, error)
}

// MapStore is an in-memory KeyStore backed by a map.
type MapStore struct {
	keys map[string]*m2mauth.Claims
}

// NewMapStore creates a MapStore from a map of key -> claims.
func NewMapStore(keys map[string]*m2mauth.Claims) *MapStore {
	return &MapStore{keys: keys}
}

func (s *MapStore) Lookup(_ context.Context, key string) (*m2mauth.Claims, error) {
	// Use constant-time comparison to prevent timing attacks.
	for k, claims := range s.keys {
		if subtle.ConstantTimeCompare([]byte(k), []byte(key)) == 1 {
			return claims, nil
		}
	}
	return nil, nil
}

// Config holds validation configuration.
type Config struct {
	// Store is the backend for API key lookups.
	Store KeyStore

	// HeaderName is the header to read the API key from. Defaults to "X-API-Key".
	HeaderName string

	// EventHandler receives auth events.
	EventHandler authlog.EventHandler

	// ServiceName identifies this validator in logs.
	ServiceName string
}

// Option configures a Config.
type Option func(*Config)

func WithStore(s KeyStore) Option            { return func(c *Config) { c.Store = s } }
func WithHeaderName(name string) Option      { return func(c *Config) { c.HeaderName = name } }
func WithEventHandler(h authlog.EventHandler) Option {
	return func(c *Config) { c.EventHandler = h }
}
func WithServiceName(name string) Option { return func(c *Config) { c.ServiceName = name } }

// Validator validates API keys on inbound requests.
type Validator struct {
	cfg Config
}

// New creates a new API key validator.
func New(opts ...Option) (*Validator, error) {
	cfg := Config{
		HeaderName:   "X-API-Key",
		EventHandler: authlog.NopHandler(),
		ServiceName:  "apikey-validator",
	}
	for _, o := range opts {
		o(&cfg)
	}

	if cfg.Store == nil {
		return nil, fmt.Errorf("m2mauth/validate/apikey: Store is required")
	}

	return &Validator{cfg: cfg}, nil
}

// Validate extracts the API key from the request and looks it up.
func (v *Validator) Validate(ctx context.Context, req *http.Request) (*m2mauth.Claims, error) {
	key := req.Header.Get(v.cfg.HeaderName)
	if key == "" {
		return nil, m2mauth.ErrMissingAPIKey
	}

	claims, err := v.cfg.Store.Lookup(ctx, key)
	if err != nil {
		return nil, &m2mauth.AuthError{Op: "apikey_validate", Kind: "store", Err: err}
	}
	if claims == nil {
		authlog.Emit(ctx, v.cfg.EventHandler, authlog.EventAuthFailure, v.cfg.ServiceName,
			map[string]string{"reason": "invalid_key"}, 0, nil)
		return nil, m2mauth.ErrInvalidAPIKey
	}

	authlog.Emit(ctx, v.cfg.EventHandler, authlog.EventAuthSuccess, v.cfg.ServiceName,
		map[string]string{"subject": claims.Subject}, 0, nil)
	return claims, nil
}
