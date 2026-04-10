// Package spiffe provides a SPIFFE/SPIRE-aware mTLS verifier for m2mauth.
//
// Unlike the built-in validate/mtls which works with pre-loaded CA pools,
// this package integrates with the SPIRE Workload API for live trust bundle
// and X509-SVID updates. It eliminates the need to manage CA certificates
// manually — SPIRE agent delivers them over a Unix domain socket.
//
// Usage:
//
//	import (
//	    "github.com/spiffe/go-spiffe/v2/workloadapi"
//	    spiffeauth "github.com/vishalanandl177/m2mauth/contrib/spiffe"
//	)
//
//	// Connect to the SPIRE agent (default socket: /tmp/spire-agent/public/api.sock)
//	source, err := workloadapi.NewX509Source(ctx)
//	if err != nil { log.Fatal(err) }
//	defer source.Close()
//
//	// Create the verifier — authorizes any workload in the given trust domain
//	verifier, err := spiffeauth.NewVerifier(source,
//	    spiffeauth.WithTrustDomain("prod.acme.com"),
//	)
//	if err != nil { log.Fatal(err) }
//
//	// Use with m2mauth middleware
//	mux.Handle("/api", middleware.RequireAuth(verifier)(handler))
//
// Authorization modes (use at most one):
//
//   - WithTrustDomain("prod.acme.com")        — any workload in this trust domain
//   - WithAllowedIDs("spiffe://.../orders")   — specific SPIFFE IDs only
//   - WithAuthorizer(tlsconfig.AuthorizeAny()) — custom go-spiffe authorizer
package spiffe

import (
	"context"
	"fmt"
	"net/http"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"

	"github.com/vishalanandl177/m2mauth"
	"github.com/vishalanandl177/m2mauth/authlog"
)

// X509BundleSource is the interface for supplying SPIFFE X.509 trust bundles.
// It is an alias for x509bundle.Source, satisfied by *workloadapi.X509Source
// and any custom implementation.
type X509BundleSource = x509bundle.Source

// Authorizer is a function that authorizes a peer SPIFFE ID.
// It returns nil if the ID is allowed, or an error if it is rejected.
type Authorizer func(id spiffeid.ID) error

// Config configures the SPIFFE-aware verifier.
type Config struct {
	TrustDomain  string
	AllowedIDs   []string
	Authorizer   Authorizer
	EventHandler authlog.EventHandler
	ServiceName  string
}

// Option configures a Config.
type Option func(*Config)

// WithTrustDomain authorizes any workload in the given trust domain.
// Example: WithTrustDomain("prod.acme.com")
func WithTrustDomain(td string) Option {
	return func(c *Config) { c.TrustDomain = td }
}

// WithAllowedIDs restricts access to an explicit list of SPIFFE IDs.
// Example: WithAllowedIDs("spiffe://prod.acme.com/ns/default/sa/orders")
func WithAllowedIDs(ids ...string) Option {
	return func(c *Config) { c.AllowedIDs = ids }
}

// WithAuthorizer sets a custom authorizer function. This takes precedence
// over WithTrustDomain and WithAllowedIDs if provided.
func WithAuthorizer(a Authorizer) Option {
	return func(c *Config) { c.Authorizer = a }
}

// WithEventHandler sets the authlog event handler for observability.
func WithEventHandler(h authlog.EventHandler) Option {
	return func(c *Config) { c.EventHandler = h }
}

// WithServiceName identifies this verifier in logs.
func WithServiceName(name string) Option {
	return func(c *Config) { c.ServiceName = name }
}

// Verifier validates client certificates against a live SPIFFE trust bundle.
// It implements m2mauth.Validator.
//
// Verifier is safe for concurrent use by multiple goroutines.
type Verifier struct {
	source     X509BundleSource
	authorizer Authorizer
	cfg        Config
}

// NewVerifier creates a SPIFFE-aware verifier backed by a live bundle source
// (typically *workloadapi.X509Source).
func NewVerifier(source X509BundleSource, opts ...Option) (*Verifier, error) {
	if source == nil {
		return nil, fmt.Errorf("m2mauth/spiffe: X509BundleSource is required")
	}

	cfg := Config{
		EventHandler: authlog.NopHandler(),
		ServiceName:  "spiffe-verifier",
	}
	for _, o := range opts {
		o(&cfg)
	}

	// Determine effective authorizer.
	authz := cfg.Authorizer
	if authz == nil {
		if cfg.TrustDomain != "" {
			td, err := spiffeid.TrustDomainFromString(cfg.TrustDomain)
			if err != nil {
				return nil, fmt.Errorf("m2mauth/spiffe: invalid trust domain: %w", err)
			}
			authz = func(id spiffeid.ID) error {
				if !id.MemberOf(td) {
					return m2mauth.ErrWrongTrustDomain
				}
				return nil
			}
		} else if len(cfg.AllowedIDs) > 0 {
			allowed := make(map[string]bool, len(cfg.AllowedIDs))
			for _, s := range cfg.AllowedIDs {
				id, err := spiffeid.FromString(s)
				if err != nil {
					return nil, fmt.Errorf("m2mauth/spiffe: invalid SPIFFE ID %q: %w", s, err)
				}
				allowed[id.String()] = true
			}
			authz = func(id spiffeid.ID) error {
				if !allowed[id.String()] {
					return m2mauth.ErrSPIFFEIDNotAllowed
				}
				return nil
			}
		} else {
			return nil, fmt.Errorf("m2mauth/spiffe: must configure WithTrustDomain, WithAllowedIDs, or WithAuthorizer")
		}
	}

	return &Verifier{
		source:     source,
		authorizer: authz,
		cfg:        cfg,
	}, nil
}

// Validate checks the client certificate from the TLS connection against
// the live SPIFFE trust bundle and authorizer.
func (v *Verifier) Validate(ctx context.Context, req *http.Request) (*m2mauth.Claims, error) {
	if req.TLS == nil || len(req.TLS.PeerCertificates) == 0 {
		authlog.Emit(ctx, v.cfg.EventHandler, authlog.EventAuthFailure, v.cfg.ServiceName,
			map[string]string{"reason": "no_client_cert"}, 0, nil)
		return nil, &m2mauth.AuthError{
			Op: "spiffe_validate", Kind: "credential",
			Err: fmt.Errorf("no client certificate presented"),
		}
	}

	// Verify the peer certificate chain against the live SPIFFE bundle.
	// go-spiffe's x509svid.ParseAndVerify validates the chain against the
	// trust bundle for the SPIFFE ID's trust domain and returns the SVID.
	certs := req.TLS.PeerCertificates
	rawCerts := make([][]byte, 0, len(certs))
	for _, c := range certs {
		rawCerts = append(rawCerts, c.Raw)
	}

	peerID, _, err := x509svid.ParseAndVerify(rawCerts, v.source)
	if err != nil {
		authlog.Emit(ctx, v.cfg.EventHandler, authlog.EventAuthFailure, v.cfg.ServiceName,
			map[string]string{"reason": "svid_verify_failed"}, 0, err)
		return nil, m2mauth.ErrCertNotTrusted
	}

	// Authorize the peer SPIFFE ID.
	if err := v.authorizer(peerID); err != nil {
		authlog.Emit(ctx, v.cfg.EventHandler, authlog.EventAuthFailure, v.cfg.ServiceName,
			map[string]string{"reason": "authz_denied", "spiffe_id": peerID.String()}, 0, err)
		return nil, err
	}

	// Build claims from the verified SVID.
	leaf := certs[0]
	claims := &m2mauth.Claims{
		Subject:   peerID.String(),
		Issuer:    leaf.Issuer.CommonName,
		IssuedAt:  leaf.NotBefore,
		ExpiresAt: leaf.NotAfter,
		Extra: map[string]any{
			"spiffe_id":    peerID.String(),
			"trust_domain": peerID.TrustDomain().String(),
			"serial":       leaf.SerialNumber.String(),
			"dns_san":      leaf.DNSNames,
		},
	}

	authlog.Emit(ctx, v.cfg.EventHandler, authlog.EventAuthSuccess, v.cfg.ServiceName,
		map[string]string{"subject": claims.Subject}, 0, nil)
	return claims, nil
}

// NewVerifierFromWorkloadAPI is a convenience constructor that connects to
// the SPIRE Workload API at the default socket address and creates a verifier.
// The returned close function should be called on shutdown.
func NewVerifierFromWorkloadAPI(ctx context.Context, opts ...Option) (*Verifier, func() error, error) {
	source, err := workloadapi.NewX509Source(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("m2mauth/spiffe: connect to workload API: %w", err)
	}

	verifier, err := NewVerifier(source, opts...)
	if err != nil {
		source.Close()
		return nil, nil, err
	}

	return verifier, source.Close, nil
}

// Ensure Verifier satisfies the m2mauth.Validator interface.
var _ m2mauth.Validator = (*Verifier)(nil)
