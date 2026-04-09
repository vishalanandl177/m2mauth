// Package apikey implements API key authentication for outbound HTTP requests.
package apikey

import (
	"context"
	"fmt"
	"net/http"

	"github.com/vishalanandl177/m2mauth"
	"github.com/vishalanandl177/m2mauth/authlog"
)

// Location specifies where to place the API key in the request.
type Location int

const (
	// Header places the API key in a custom header (default: X-API-Key).
	Header Location = iota
	// BearerHeader places the API key as a Bearer token in the Authorization header.
	BearerHeader
	// QueryParam places the API key as a URL query parameter.
	QueryParam
)

// Config holds the configuration for an API key authenticator.
type Config struct {
	// Key is the API key value. Ignored if SecretProvider is set.
	Key string

	// SecretProvider dynamically retrieves the API key.
	SecretProvider m2mauth.SecretProvider

	// SecretKey is the key passed to SecretProvider.GetSecret.
	SecretKey string

	// Location determines where to place the key.
	Location Location

	// HeaderName is the header name when Location is Header.
	// Defaults to "X-API-Key".
	HeaderName string

	// ParamName is the query parameter name when Location is QueryParam.
	ParamName string

	// EventHandler receives auth events.
	EventHandler authlog.EventHandler

	// ServiceName identifies this client in logs.
	ServiceName string
}

// Option configures a Config.
type Option func(*Config)

func WithKey(key string) Option {
	return func(c *Config) { c.Key = key }
}

func WithSecretProvider(sp m2mauth.SecretProvider, secretKey string) Option {
	return func(c *Config) { c.SecretProvider = sp; c.SecretKey = secretKey }
}

func WithLocation(loc Location) Option {
	return func(c *Config) { c.Location = loc }
}

func WithHeaderName(name string) Option {
	return func(c *Config) { c.HeaderName = name }
}

func WithParamName(name string) Option {
	return func(c *Config) { c.ParamName = name }
}

func WithEventHandler(h authlog.EventHandler) Option {
	return func(c *Config) { c.EventHandler = h }
}

func WithServiceName(name string) Option {
	return func(c *Config) { c.ServiceName = name }
}

// Authenticator attaches an API key to outbound HTTP requests.
// It implements the m2mauth.Authenticator interface.
type Authenticator struct {
	cfg Config
}

// New creates a new API key authenticator.
func New(opts ...Option) (*Authenticator, error) {
	cfg := Config{
		HeaderName:   "X-API-Key",
		ParamName:    "api_key",
		Location:     Header,
		EventHandler: authlog.NopHandler(),
	}
	for _, o := range opts {
		o(&cfg)
	}

	if cfg.Key == "" && cfg.SecretProvider == nil {
		return nil, fmt.Errorf("m2mauth/apikey: either Key or SecretProvider is required")
	}

	return &Authenticator{cfg: cfg}, nil
}

// Authenticate adds the API key to the request.
func (a *Authenticator) Authenticate(ctx context.Context, req *http.Request) error {
	key, err := a.resolveKey(ctx)
	if err != nil {
		return &m2mauth.AuthError{Op: "apikey_auth", Kind: "credential", Err: err}
	}

	switch a.cfg.Location {
	case Header:
		req.Header.Set(a.cfg.HeaderName, key)
	case BearerHeader:
		req.Header.Set("Authorization", "Bearer "+key)
	case QueryParam:
		q := req.URL.Query()
		q.Set(a.cfg.ParamName, key)
		req.URL.RawQuery = q.Encode()
	}

	return nil
}

func (a *Authenticator) resolveKey(ctx context.Context) (string, error) {
	if a.cfg.SecretProvider != nil {
		return a.cfg.SecretProvider.GetSecret(ctx, a.cfg.SecretKey)
	}
	return a.cfg.Key, nil
}
