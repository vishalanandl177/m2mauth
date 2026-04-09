// Package mtls provides server-side mTLS client certificate verification.
package mtls

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/vishalanandl177/m2mauth"
	"github.com/vishalanandl177/m2mauth/authlog"
)

// Config configures the mTLS verifier.
type Config struct {
	// TrustedCAs is the pool of trusted CA certificates.
	// If nil, the server's TLS config must handle verification.
	TrustedCAs *x509.CertPool

	// RequiredOU limits access to certificates with a specific Organizational Unit.
	RequiredOU string

	// RequiredCN limits access to certificates matching a specific Common Name pattern.
	RequiredCN string

	// EventHandler receives auth events.
	EventHandler authlog.EventHandler

	// ServiceName identifies this verifier in logs.
	ServiceName string
}

// Option configures a Config.
type Option func(*Config)

func WithTrustedCAs(pool *x509.CertPool) Option {
	return func(c *Config) { c.TrustedCAs = pool }
}

func WithRequiredOU(ou string) Option {
	return func(c *Config) { c.RequiredOU = ou }
}

func WithRequiredCN(cn string) Option {
	return func(c *Config) { c.RequiredCN = cn }
}

func WithEventHandler(h authlog.EventHandler) Option {
	return func(c *Config) { c.EventHandler = h }
}

func WithServiceName(name string) Option {
	return func(c *Config) { c.ServiceName = name }
}

// Verifier validates client certificates on inbound mTLS connections.
// Verifier is safe for concurrent use by multiple goroutines.
type Verifier struct {
	cfg Config
}

// New creates a new mTLS verifier.
func New(opts ...Option) *Verifier {
	cfg := Config{
		EventHandler: authlog.NopHandler(),
		ServiceName:  "mtls-verifier",
	}
	for _, o := range opts {
		o(&cfg)
	}
	return &Verifier{cfg: cfg}
}

// Validate checks the client certificate from the TLS connection.
func (v *Verifier) Validate(ctx context.Context, req *http.Request) (*m2mauth.Claims, error) {
	if req.TLS == nil || len(req.TLS.PeerCertificates) == 0 {
		authlog.Emit(ctx, v.cfg.EventHandler, authlog.EventAuthFailure, v.cfg.ServiceName,
			map[string]string{"reason": "no_client_cert"}, 0, nil)
		return nil, &m2mauth.AuthError{Op: "mtls_validate", Kind: "credential",
			Err: fmt.Errorf("no client certificate presented")}
	}

	cert := req.TLS.PeerCertificates[0]

	// Verify against trusted CAs if configured.
	if v.cfg.TrustedCAs != nil {
		opts := x509.VerifyOptions{
			Roots:     v.cfg.TrustedCAs,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
		if _, err := cert.Verify(opts); err != nil {
			authlog.Emit(ctx, v.cfg.EventHandler, authlog.EventAuthFailure, v.cfg.ServiceName,
				map[string]string{"reason": "cert_not_trusted", "cn": cert.Subject.CommonName}, 0, err)
			return nil, m2mauth.ErrCertNotTrusted
		}
	}

	// Always check certificate expiry regardless of TrustedCAs config.
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		authlog.Emit(ctx, v.cfg.EventHandler, authlog.EventAuthFailure, v.cfg.ServiceName,
			map[string]string{"reason": "cert_expired", "cn": cert.Subject.CommonName}, 0, nil)
		return nil, m2mauth.ErrCertExpired
	}

	// Check CN constraint.
	if v.cfg.RequiredCN != "" && cert.Subject.CommonName != v.cfg.RequiredCN {
		return nil, &m2mauth.AuthError{
			Op:   "mtls_validate",
			Kind: "validation",
			Err:  fmt.Errorf("CN %q does not match required %q", cert.Subject.CommonName, v.cfg.RequiredCN),
		}
	}

	// Check OU constraint.
	if v.cfg.RequiredOU != "" {
		found := false
		for _, ou := range cert.Subject.OrganizationalUnit {
			if ou == v.cfg.RequiredOU {
				found = true
				break
			}
		}
		if !found {
			return nil, &m2mauth.AuthError{
				Op:   "mtls_validate",
				Kind: "validation",
				Err:  fmt.Errorf("OU %q not found in certificate", v.cfg.RequiredOU),
			}
		}
	}

	claims := &m2mauth.Claims{
		Subject:   cert.Subject.CommonName,
		Issuer:    cert.Issuer.CommonName,
		IssuedAt:  cert.NotBefore,
		ExpiresAt: cert.NotAfter,
		Extra: map[string]any{
			"serial":  cert.SerialNumber.String(),
			"ou":      strings.Join(cert.Subject.OrganizationalUnit, ","),
			"dns_san": cert.DNSNames,
		},
	}

	authlog.Emit(ctx, v.cfg.EventHandler, authlog.EventAuthSuccess, v.cfg.ServiceName,
		map[string]string{"subject": claims.Subject}, 0, nil)
	return claims, nil
}
