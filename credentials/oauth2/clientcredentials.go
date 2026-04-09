// Package oauth2 implements the OAuth 2.0 Client Credentials flow for
// machine-to-machine authentication.
package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/vishalanandl177/m2mauth"
	"github.com/vishalanandl177/m2mauth/authlog"
	"github.com/vishalanandl177/m2mauth/retry"
)

// Config holds the configuration for a client credentials authenticator.
type Config struct {
	// TokenURL is the OAuth 2.0 token endpoint.
	TokenURL string

	// ClientID is the service's client identifier.
	ClientID string

	// ClientSecret is the service's client secret.
	// If SecretProvider is set, this is ignored.
	ClientSecret string

	// SecretProvider dynamically retrieves the client secret.
	SecretProvider m2mauth.SecretProvider

	// SecretKey is the key passed to SecretProvider.GetSecret.
	SecretKey string

	// Audience is the intended recipient of the token.
	Audience string

	// Scopes are the requested permissions.
	Scopes []string

	// ExpiryBuffer is subtracted from the token's actual expiry to trigger
	// early refresh. Defaults to 30 seconds.
	ExpiryBuffer time.Duration

	// HTTPClient is the HTTP client used for token requests.
	// Defaults to http.DefaultClient.
	HTTPClient *http.Client

	// RetryPolicy configures retry behavior for token requests.
	RetryPolicy *retry.Policy

	// EventHandler receives auth events for logging/audit.
	EventHandler authlog.EventHandler

	// ServiceName identifies this client in logs and metrics.
	ServiceName string
}

// Option configures a Config.
type Option func(*Config)

func WithClientSecret(secret string) Option {
	return func(c *Config) { c.ClientSecret = secret }
}

func WithSecretProvider(sp m2mauth.SecretProvider, key string) Option {
	return func(c *Config) { c.SecretProvider = sp; c.SecretKey = key }
}

func WithAudience(aud string) Option {
	return func(c *Config) { c.Audience = aud }
}

func WithScopes(scopes ...string) Option {
	return func(c *Config) { c.Scopes = scopes }
}

func WithExpiryBuffer(d time.Duration) Option {
	return func(c *Config) { c.ExpiryBuffer = d }
}

func WithHTTPClient(hc *http.Client) Option {
	return func(c *Config) { c.HTTPClient = hc }
}

func WithRetryPolicy(p retry.Policy) Option {
	return func(c *Config) { c.RetryPolicy = &p }
}

func WithEventHandler(h authlog.EventHandler) Option {
	return func(c *Config) { c.EventHandler = h }
}

func WithServiceName(name string) Option {
	return func(c *Config) { c.ServiceName = name }
}

// Client implements m2mauth.Authenticator and m2mauth.TokenSource using
// the OAuth 2.0 Client Credentials flow with thread-safe token caching.
type Client struct {
	cfg   Config
	cache *tokenCache
}

// New creates a new OAuth 2.0 Client Credentials client.
func New(tokenURL, clientID string, opts ...Option) (*Client, error) {
	cfg := Config{
		TokenURL:     tokenURL,
		ClientID:     clientID,
		ExpiryBuffer: 30 * time.Second,
		HTTPClient:   http.DefaultClient,
		EventHandler: authlog.NopHandler(),
		ServiceName:  clientID,
	}
	for _, o := range opts {
		o(&cfg)
	}

	if cfg.TokenURL == "" {
		return nil, fmt.Errorf("m2mauth/oauth2: token URL is required")
	}
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("m2mauth/oauth2: client ID is required")
	}

	return &Client{
		cfg:   cfg,
		cache: newTokenCache(cfg.ExpiryBuffer),
	}, nil
}

// Authenticate adds the Bearer token to the request's Authorization header.
// It satisfies the m2mauth.Authenticator interface.
func (c *Client) Authenticate(ctx context.Context, req *http.Request) error {
	tok, err := c.Token(ctx)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	return nil
}

// Token returns a valid access token, fetching or refreshing as needed.
// It satisfies the m2mauth.TokenSource interface.
func (c *Client) Token(ctx context.Context) (*m2mauth.Token, error) {
	// Fast path: return cached token if still valid.
	if tok := c.cache.get(); tok != nil {
		return tok, nil
	}

	// Slow path: fetch a new token (with single-flight to prevent thundering herd).
	return c.cache.refresh(ctx, c.fetchToken)
}

// RevokeToken clears the cached token and optionally calls the revocation endpoint.
func (c *Client) RevokeToken() {
	c.cache.clear()
	authlog.Emit(context.Background(), c.cfg.EventHandler, authlog.EventTokenRevoked, c.cfg.ServiceName, nil, 0, nil)
}

func (c *Client) fetchToken(ctx context.Context) (*m2mauth.Token, error) {
	start := time.Now()

	secret, err := c.resolveSecret(ctx)
	if err != nil {
		authlog.Emit(ctx, c.cfg.EventHandler, authlog.EventTokenFetchErr, c.cfg.ServiceName, nil, time.Since(start), err)
		return nil, &m2mauth.AuthError{Op: "token_fetch", Kind: "credential", Err: err, Retryable: false}
	}

	var tok *m2mauth.Token
	fetchFn := func(ctx context.Context) error {
		tok, err = c.doTokenRequest(ctx, secret)
		return err
	}

	if c.cfg.RetryPolicy != nil {
		err = retry.Do(ctx, *c.cfg.RetryPolicy, fetchFn)
	} else {
		err = fetchFn(ctx)
	}

	dur := time.Since(start)
	if err != nil {
		authlog.Emit(ctx, c.cfg.EventHandler, authlog.EventTokenFetchErr, c.cfg.ServiceName,
			map[string]string{"token_url": c.cfg.TokenURL}, dur, err)
		return nil, err
	}

	authlog.Emit(ctx, c.cfg.EventHandler, authlog.EventTokenAcquired, c.cfg.ServiceName,
		map[string]string{"expires_in": fmt.Sprintf("%v", time.Until(tok.ExpiresAt))}, dur, nil)
	return tok, nil
}

func (c *Client) resolveSecret(ctx context.Context) (string, error) {
	if c.cfg.SecretProvider != nil {
		return c.cfg.SecretProvider.GetSecret(ctx, c.cfg.SecretKey)
	}
	return c.cfg.ClientSecret, nil
}

func (c *Client) doTokenRequest(ctx context.Context, secret string) (*m2mauth.Token, error) {
	data := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {c.cfg.ClientID},
		"client_secret": {secret},
	}
	if c.cfg.Audience != "" {
		data.Set("audience", c.cfg.Audience)
	}
	if len(c.cfg.Scopes) > 0 {
		data.Set("scope", strings.Join(c.cfg.Scopes, " "))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, &m2mauth.AuthError{Op: "token_fetch", Kind: "request", Err: err, Retryable: false}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, &m2mauth.AuthError{Op: "token_fetch", Kind: "network", Err: err, Retryable: true}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, &m2mauth.AuthError{Op: "token_fetch", Kind: "network", Err: err, Retryable: true}
	}

	if resp.StatusCode != http.StatusOK {
		retryable := resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests
		return nil, &m2mauth.AuthError{
			Op:        "token_fetch",
			Kind:      "response",
			Err:       fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body)),
			Retryable: retryable,
		}
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
		Scope       string `json:"scope"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, &m2mauth.AuthError{Op: "token_fetch", Kind: "decode", Err: err, Retryable: false}
	}

	var scopes []string
	if tokenResp.Scope != "" {
		scopes = strings.Split(tokenResp.Scope, " ")
	}

	raw := make(map[string]any)
	json.Unmarshal(body, &raw)

	return &m2mauth.Token{
		AccessToken: tokenResp.AccessToken,
		TokenType:   tokenResp.TokenType,
		ExpiresAt:   time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second),
		Scopes:      scopes,
		Raw:         raw,
	}, nil
}
