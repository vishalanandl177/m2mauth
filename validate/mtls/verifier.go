// Package mtls provides server-side mTLS client certificate verification.
//
// Includes built-in SPIFFE support: if a client certificate has a
// spiffe:// URI SAN, it is extracted and can be enforced via
// WithTrustDomain or WithAllowedSPIFFEIDs. For live SPIRE Workload
// API integration, see contrib/spiffe.
package mtls

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
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

	// TrustDomain, if set, requires the peer certificate to carry a SPIFFE ID
	// (spiffe:// URI SAN) belonging to this trust domain.
	// Example: "prod.acme.com"
	TrustDomain string

	// AllowedSPIFFEIDs, if non-empty, restricts access to certificates whose
	// SPIFFE ID exactly matches one of the entries.
	// Example: []string{"spiffe://prod.acme.com/ns/default/sa/orders"}
	AllowedSPIFFEIDs []string

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

// WithTrustDomain requires the peer certificate to carry a SPIFFE ID
// belonging to the given trust domain (e.g., "prod.acme.com").
func WithTrustDomain(domain string) Option {
	return func(c *Config) { c.TrustDomain = domain }
}

// WithAllowedSPIFFEIDs restricts access to a specific list of SPIFFE IDs.
// Example: WithAllowedSPIFFEIDs("spiffe://prod.acme.com/ns/default/sa/orders")
func WithAllowedSPIFFEIDs(ids ...string) Option {
	return func(c *Config) { c.AllowedSPIFFEIDs = ids }
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
		authlog.Emit(ctx, v.cfg.EventHandler, authlog.EventAuthFailure, v.cfg.ServiceName,
			map[string]string{"reason": "cn_mismatch", "cn": cert.Subject.CommonName}, 0, nil)
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
			authlog.Emit(ctx, v.cfg.EventHandler, authlog.EventAuthFailure, v.cfg.ServiceName,
				map[string]string{"reason": "ou_mismatch", "cn": cert.Subject.CommonName}, 0, nil)
			return nil, &m2mauth.AuthError{
				Op:   "mtls_validate",
				Kind: "validation",
				Err:  fmt.Errorf("OU %q not found in certificate", v.cfg.RequiredOU),
			}
		}
	}

	// Extract SPIFFE ID from URI SANs (if present).
	spiffeID, spiffeErr := extractSPIFFEID(cert.URIs)

	// Enforce trust domain if configured — requires a SPIFFE ID to be present.
	if v.cfg.TrustDomain != "" {
		if spiffeErr != nil {
			authlog.Emit(ctx, v.cfg.EventHandler, authlog.EventAuthFailure, v.cfg.ServiceName,
				map[string]string{"reason": "spiffe_id_missing"}, 0, spiffeErr)
			return nil, m2mauth.ErrInvalidSPIFFEID
		}
		if spiffeTrustDomain(spiffeID) != v.cfg.TrustDomain {
			authlog.Emit(ctx, v.cfg.EventHandler, authlog.EventAuthFailure, v.cfg.ServiceName,
				map[string]string{"reason": "wrong_trust_domain", "spiffe_id": spiffeID}, 0, nil)
			return nil, m2mauth.ErrWrongTrustDomain
		}
	}

	// Enforce SPIFFE ID allowlist if configured.
	if len(v.cfg.AllowedSPIFFEIDs) > 0 {
		if spiffeErr != nil {
			authlog.Emit(ctx, v.cfg.EventHandler, authlog.EventAuthFailure, v.cfg.ServiceName,
				map[string]string{"reason": "spiffe_id_missing"}, 0, spiffeErr)
			return nil, m2mauth.ErrInvalidSPIFFEID
		}
		allowed := false
		for _, id := range v.cfg.AllowedSPIFFEIDs {
			if id == spiffeID {
				allowed = true
				break
			}
		}
		if !allowed {
			authlog.Emit(ctx, v.cfg.EventHandler, authlog.EventAuthFailure, v.cfg.ServiceName,
				map[string]string{"reason": "spiffe_id_not_allowed", "spiffe_id": spiffeID}, 0, nil)
			return nil, m2mauth.ErrSPIFFEIDNotAllowed
		}
	}

	// Choose subject: prefer SPIFFE ID if present, fall back to CN.
	subject := cert.Subject.CommonName
	if spiffeID != "" {
		subject = spiffeID
	}

	extra := map[string]any{
		"serial":  cert.SerialNumber.String(),
		"ou":      strings.Join(cert.Subject.OrganizationalUnit, ","),
		"dns_san": cert.DNSNames,
		"cn":      cert.Subject.CommonName,
	}
	if spiffeID != "" {
		extra["spiffe_id"] = spiffeID
		extra["trust_domain"] = spiffeTrustDomain(spiffeID)
	}

	claims := &m2mauth.Claims{
		Subject:   subject,
		Issuer:    cert.Issuer.CommonName,
		IssuedAt:  cert.NotBefore,
		ExpiresAt: cert.NotAfter,
		Extra:     extra,
	}

	authlog.Emit(ctx, v.cfg.EventHandler, authlog.EventAuthSuccess, v.cfg.ServiceName,
		map[string]string{"subject": claims.Subject}, 0, nil)
	return claims, nil
}

// extractSPIFFEID returns the SPIFFE ID (spiffe://trust-domain/path) from
// a certificate's URI SANs. Per SPIFFE spec, certificates should contain
// exactly one SPIFFE URI SAN. Returns an error if none is found or multiple
// are present.
func extractSPIFFEID(uris []*url.URL) (string, error) {
	var found string
	for _, u := range uris {
		if u == nil {
			continue
		}
		if u.Scheme != "spiffe" {
			continue
		}
		if found != "" {
			return "", fmt.Errorf("certificate contains multiple SPIFFE IDs")
		}
		// Validate SPIFFE URI structure: must have a non-empty host (trust domain).
		if u.Host == "" {
			return "", fmt.Errorf("SPIFFE ID missing trust domain")
		}
		// SPIFFE IDs must not have userinfo, query, or fragment.
		if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return "", fmt.Errorf("SPIFFE ID has forbidden URI components")
		}
		found = u.String()
	}
	if found == "" {
		return "", fmt.Errorf("no SPIFFE ID found in URI SANs")
	}
	return found, nil
}

// spiffeTrustDomain extracts the trust domain (host) from a SPIFFE ID string.
func spiffeTrustDomain(spiffeID string) string {
	u, err := url.Parse(spiffeID)
	if err != nil {
		return ""
	}
	return u.Host
}
