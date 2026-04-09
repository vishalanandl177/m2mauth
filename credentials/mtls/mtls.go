// Package mtls implements mutual TLS authentication with support for
// certificate loading, hot-reload rotation, and CA verification.
package mtls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/vishalanandl177/m2mauth"
	"github.com/vishalanandl177/m2mauth/authlog"
)

// Config holds the configuration for mTLS.
type Config struct {
	// CertFile is the path to the client certificate PEM file.
	CertFile string

	// KeyFile is the path to the client private key PEM file.
	KeyFile string

	// CertPEM is the client certificate in PEM format (alternative to CertFile).
	CertPEM []byte

	// KeyPEM is the client key in PEM format (alternative to KeyFile).
	KeyPEM []byte

	// CACertFile is the path to the CA certificate PEM file for server verification.
	CACertFile string

	// CACertPEM is the CA certificate in PEM format (alternative to CACertFile).
	CACertPEM []byte

	// ServerName overrides the server name for TLS verification.
	ServerName string

	// RotationInterval controls how often certificates are re-read from disk.
	// Zero means no rotation. Typically 5-15 minutes.
	RotationInterval time.Duration

	// EventHandler receives auth events (cert rotations, errors).
	EventHandler authlog.EventHandler

	// ServiceName identifies this client in logs.
	ServiceName string
}

// Option configures a Config.
type Option func(*Config)

func WithCertFile(certFile, keyFile string) Option {
	return func(c *Config) { c.CertFile = certFile; c.KeyFile = keyFile }
}

func WithCertPEM(certPEM, keyPEM []byte) Option {
	return func(c *Config) { c.CertPEM = certPEM; c.KeyPEM = keyPEM }
}

func WithCACertFile(caFile string) Option {
	return func(c *Config) { c.CACertFile = caFile }
}

func WithCACertPEM(caPEM []byte) Option {
	return func(c *Config) { c.CACertPEM = caPEM }
}

func WithServerName(name string) Option {
	return func(c *Config) { c.ServerName = name }
}

func WithRotationInterval(d time.Duration) Option {
	return func(c *Config) { c.RotationInterval = d }
}

func WithEventHandler(h authlog.EventHandler) Option {
	return func(c *Config) { c.EventHandler = h }
}

func WithServiceName(name string) Option {
	return func(c *Config) { c.ServiceName = name }
}

// Transport creates a mTLS-configured http.Transport with optional certificate rotation.
type Transport struct {
	cfg Config

	mu   sync.RWMutex
	cert *tls.Certificate

	stopCh chan struct{}
}

// NewTransport creates a new mTLS transport.
func NewTransport(opts ...Option) (*Transport, error) {
	cfg := Config{
		EventHandler: authlog.NopHandler(),
		ServiceName:  "mtls-client",
	}
	for _, o := range opts {
		o(&cfg)
	}

	t := &Transport{cfg: cfg, stopCh: make(chan struct{})}

	// Load initial certificate.
	cert, err := t.loadCert()
	if err != nil {
		return nil, fmt.Errorf("m2mauth/mtls: load certificate: %w", err)
	}
	t.cert = cert

	// Start rotation if configured.
	if cfg.RotationInterval > 0 && cfg.CertFile != "" {
		go t.rotationLoop()
	}

	return t, nil
}

// TLSConfig returns a *tls.Config configured for mTLS.
func (t *Transport) TLSConfig() (*tls.Config, error) {
	tlsCfg := &tls.Config{
		GetClientCertificate: t.getClientCertificate,
	}

	if t.cfg.ServerName != "" {
		tlsCfg.ServerName = t.cfg.ServerName
	}

	// Load CA cert pool.
	pool, err := t.loadCACertPool()
	if err != nil {
		return nil, err
	}
	if pool != nil {
		tlsCfg.RootCAs = pool
	}

	return tlsCfg, nil
}

// HTTPTransport returns an *http.Transport configured for mTLS.
func (t *Transport) HTTPTransport() (*http.Transport, error) {
	tlsCfg, err := t.TLSConfig()
	if err != nil {
		return nil, err
	}

	return &http.Transport{
		TLSClientConfig: tlsCfg,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:  10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}, nil
}

// Stop halts the certificate rotation loop.
func (t *Transport) Stop() {
	close(t.stopCh)
}

// CertInfo returns information about the currently loaded certificate.
func (t *Transport) CertInfo() *CertInfo {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if t.cert == nil || len(t.cert.Certificate) == 0 {
		return nil
	}

	parsed, err := x509.ParseCertificate(t.cert.Certificate[0])
	if err != nil {
		return nil
	}

	return &CertInfo{
		Subject:   parsed.Subject.CommonName,
		Issuer:    parsed.Issuer.CommonName,
		NotBefore: parsed.NotBefore,
		NotAfter:  parsed.NotAfter,
		Serial:    parsed.SerialNumber.String(),
	}
}

// CertInfo holds metadata about a loaded certificate.
type CertInfo struct {
	Subject   string
	Issuer    string
	NotBefore time.Time
	NotAfter  time.Time
	Serial    string
}

// IsExpiring reports whether the certificate expires within the given window.
func (ci *CertInfo) IsExpiring(within time.Duration) bool {
	return time.Now().Add(within).After(ci.NotAfter)
}

func (t *Transport) getClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if t.cert == nil {
		return nil, &m2mauth.AuthError{Op: "mtls_auth", Kind: "credential", Err: fmt.Errorf("no certificate loaded")}
	}
	return t.cert, nil
}

func (t *Transport) loadCert() (*tls.Certificate, error) {
	var cert tls.Certificate
	var err error

	if t.cfg.CertFile != "" {
		cert, err = tls.LoadX509KeyPair(t.cfg.CertFile, t.cfg.KeyFile)
	} else if t.cfg.CertPEM != nil {
		cert, err = tls.X509KeyPair(t.cfg.CertPEM, t.cfg.KeyPEM)
	} else {
		return nil, fmt.Errorf("no certificate source configured")
	}

	if err != nil {
		return nil, err
	}
	return &cert, nil
}

func (t *Transport) loadCACertPool() (*x509.CertPool, error) {
	var caPEM []byte
	if t.cfg.CACertFile != "" {
		var err error
		caPEM, err = os.ReadFile(t.cfg.CACertFile)
		if err != nil {
			return nil, fmt.Errorf("read CA cert: %w", err)
		}
	} else if t.cfg.CACertPEM != nil {
		caPEM = t.cfg.CACertPEM
	} else {
		return nil, nil // Use system pool.
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}
	return pool, nil
}

func (t *Transport) rotationLoop() {
	ticker := time.NewTicker(t.cfg.RotationInterval)
	defer ticker.Stop()

	for {
		select {
		case <-t.stopCh:
			return
		case <-ticker.C:
			t.rotateCert()
		}
	}
}

func (t *Transport) rotateCert() {
	ctx := context.Background()
	cert, err := t.loadCert()
	if err != nil {
		authlog.Emit(ctx, t.cfg.EventHandler, authlog.EventCertLoadErr, t.cfg.ServiceName,
			map[string]string{"cert_file": t.cfg.CertFile}, 0, err)
		return
	}

	// Validate the new certificate is not already expired before accepting it.
	if len(cert.Certificate) > 0 {
		parsed, parseErr := x509.ParseCertificate(cert.Certificate[0])
		if parseErr != nil {
			authlog.Emit(ctx, t.cfg.EventHandler, authlog.EventCertLoadErr, t.cfg.ServiceName,
				map[string]string{"cert_file": t.cfg.CertFile, "reason": "parse_failed"}, 0, parseErr)
			return
		}
		if time.Now().After(parsed.NotAfter) {
			authlog.Emit(ctx, t.cfg.EventHandler, authlog.EventCertLoadErr, t.cfg.ServiceName,
				map[string]string{"cert_file": t.cfg.CertFile, "reason": "cert_expired"}, 0,
				fmt.Errorf("rotated certificate is already expired (NotAfter: %s)", parsed.NotAfter.Format(time.RFC3339)))
			return
		}
	}

	t.mu.Lock()
	t.cert = cert
	t.mu.Unlock()

	authlog.Emit(ctx, t.cfg.EventHandler, authlog.EventCertRotated, t.cfg.ServiceName,
		map[string]string{"cert_file": t.cfg.CertFile}, 0, nil)

	// Check if the new cert is expiring soon.
	info := t.CertInfo()
	if info != nil && info.IsExpiring(24*time.Hour) {
		authlog.Emit(ctx, t.cfg.EventHandler, authlog.EventCertExpiring, t.cfg.ServiceName,
			map[string]string{"expires_at": info.NotAfter.Format(time.RFC3339)}, 0, nil)
	}
}
