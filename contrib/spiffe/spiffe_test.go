package spiffe

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/vishalanandl177/m2mauth"
)

// --- Test helpers: fake SPIRE-like infrastructure ---

// fakeBundleSource implements x509bundle.Source for testing.
type fakeBundleSource struct {
	bundles map[spiffeid.TrustDomain]*x509bundle.Bundle
}

func (f *fakeBundleSource) GetX509BundleForTrustDomain(td spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	b, ok := f.bundles[td]
	if !ok {
		return nil, errors.New("trust domain not found in bundle source")
	}
	return b, nil
}

// newTestCA creates a fresh CA for a given trust domain.
func newTestCA(t *testing.T, td spiffeid.TrustDomain) (*x509.Certificate, *ecdsa.PrivateKey, *x509bundle.Bundle) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "SPIRE CA " + td.String()},
		URIs:                  []*url.URL{{Scheme: "spiffe", Host: td.Name()}},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(certDER)

	bundle := x509bundle.FromX509Authorities(td, []*x509.Certificate{caCert})
	return caCert, key, bundle
}

// newTestSVID creates a leaf cert (X509-SVID) signed by the given CA.
func newTestSVID(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, id spiffeid.ID) *x509.Certificate {
	t.Helper()

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	u, err := url.Parse(id.String())
	if err != nil {
		t.Fatal(err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: ""},
		URIs:         []*url.URL{u},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func reqWithCerts(certs ...*x509.Certificate) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: certs}
	return req
}

// --- Tests ---

func TestNewVerifier_RequiresSource(t *testing.T) {
	_, err := NewVerifier(nil, WithTrustDomain("prod.acme.com"))
	if err == nil {
		t.Fatal("expected error for nil source")
	}
}

func TestNewVerifier_RequiresAuthorization(t *testing.T) {
	source := &fakeBundleSource{bundles: map[spiffeid.TrustDomain]*x509bundle.Bundle{}}
	_, err := NewVerifier(source)
	if err == nil {
		t.Fatal("expected error when no authorization configured")
	}
}

func TestNewVerifier_InvalidTrustDomain(t *testing.T) {
	source := &fakeBundleSource{bundles: map[spiffeid.TrustDomain]*x509bundle.Bundle{}}
	_, err := NewVerifier(source, WithTrustDomain("!invalid!"))
	if err == nil {
		t.Fatal("expected error for invalid trust domain")
	}
}

func TestNewVerifier_InvalidAllowedID(t *testing.T) {
	source := &fakeBundleSource{bundles: map[spiffeid.TrustDomain]*x509bundle.Bundle{}}
	_, err := NewVerifier(source, WithAllowedIDs("not-a-spiffe-id"))
	if err == nil {
		t.Fatal("expected error for invalid SPIFFE ID")
	}
}

func TestVerifier_NoClientCert(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("prod.acme.com")
	_, _, bundle := newTestCA(t, td)
	source := &fakeBundleSource{bundles: map[spiffeid.TrustDomain]*x509bundle.Bundle{td: bundle}}

	v, err := NewVerifier(source, WithTrustDomain("prod.acme.com"))
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	_, err = v.Validate(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for no client cert")
	}
}

func TestVerifier_TrustDomain_Valid(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("prod.acme.com")
	caCert, caKey, bundle := newTestCA(t, td)
	source := &fakeBundleSource{bundles: map[spiffeid.TrustDomain]*x509bundle.Bundle{td: bundle}}

	peerID := spiffeid.RequireFromString("spiffe://prod.acme.com/ns/default/sa/orders")
	leaf := newTestSVID(t, caCert, caKey, peerID)

	v, err := NewVerifier(source, WithTrustDomain("prod.acme.com"))
	if err != nil {
		t.Fatal(err)
	}

	claims, err := v.Validate(context.Background(), reqWithCerts(leaf, caCert))
	if err != nil {
		t.Fatalf("Validate error: %v", err)
	}
	if claims.Subject != peerID.String() {
		t.Errorf("expected subject %q, got %q", peerID.String(), claims.Subject)
	}
	if claims.Extra["trust_domain"] != "prod.acme.com" {
		t.Errorf("expected trust_domain in extra, got %v", claims.Extra["trust_domain"])
	}
}

func TestVerifier_TrustDomain_Mismatch(t *testing.T) {
	// CA for prod.acme.com
	prodTD := spiffeid.RequireTrustDomainFromString("prod.acme.com")
	prodCA, prodKey, prodBundle := newTestCA(t, prodTD)

	// CA for staging.acme.com
	stagingTD := spiffeid.RequireTrustDomainFromString("staging.acme.com")
	_, _, stagingBundle := newTestCA(t, stagingTD)

	source := &fakeBundleSource{bundles: map[spiffeid.TrustDomain]*x509bundle.Bundle{
		prodTD:    prodBundle,
		stagingTD: stagingBundle,
	}}

	// Leaf cert is in prod, but verifier only allows staging
	peerID := spiffeid.RequireFromString("spiffe://prod.acme.com/orders")
	leaf := newTestSVID(t, prodCA, prodKey, peerID)

	v, err := NewVerifier(source, WithTrustDomain("staging.acme.com"))
	if err != nil {
		t.Fatal(err)
	}

	_, err = v.Validate(context.Background(), reqWithCerts(leaf, prodCA))
	if !errors.Is(err, m2mauth.ErrWrongTrustDomain) {
		t.Errorf("expected ErrWrongTrustDomain, got %v", err)
	}
}

func TestVerifier_AllowedIDs_Match(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("prod.acme.com")
	caCert, caKey, bundle := newTestCA(t, td)
	source := &fakeBundleSource{bundles: map[spiffeid.TrustDomain]*x509bundle.Bundle{td: bundle}}

	peerID := spiffeid.RequireFromString("spiffe://prod.acme.com/ns/default/sa/orders")
	leaf := newTestSVID(t, caCert, caKey, peerID)

	v, err := NewVerifier(source,
		WithAllowedIDs("spiffe://prod.acme.com/ns/default/sa/orders"),
	)
	if err != nil {
		t.Fatal(err)
	}

	claims, err := v.Validate(context.Background(), reqWithCerts(leaf, caCert))
	if err != nil {
		t.Fatalf("Validate error: %v", err)
	}
	if claims.Subject != peerID.String() {
		t.Errorf("unexpected subject: %q", claims.Subject)
	}
}

func TestVerifier_AllowedIDs_NoMatch(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("prod.acme.com")
	caCert, caKey, bundle := newTestCA(t, td)
	source := &fakeBundleSource{bundles: map[spiffeid.TrustDomain]*x509bundle.Bundle{td: bundle}}

	peerID := spiffeid.RequireFromString("spiffe://prod.acme.com/ns/default/sa/unauthorized")
	leaf := newTestSVID(t, caCert, caKey, peerID)

	v, err := NewVerifier(source,
		WithAllowedIDs("spiffe://prod.acme.com/ns/default/sa/orders"),
	)
	if err != nil {
		t.Fatal(err)
	}

	_, err = v.Validate(context.Background(), reqWithCerts(leaf, caCert))
	if !errors.Is(err, m2mauth.ErrSPIFFEIDNotAllowed) {
		t.Errorf("expected ErrSPIFFEIDNotAllowed, got %v", err)
	}
}

func TestVerifier_CustomAuthorizer(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("prod.acme.com")
	caCert, caKey, bundle := newTestCA(t, td)
	source := &fakeBundleSource{bundles: map[spiffeid.TrustDomain]*x509bundle.Bundle{td: bundle}}

	peerID := spiffeid.RequireFromString("spiffe://prod.acme.com/ns/team-a/sa/orders")
	leaf := newTestSVID(t, caCert, caKey, peerID)

	// Custom: allow only IDs in team-a namespace
	customAuth := func(id spiffeid.ID) error {
		if !containsNamespace(id.String(), "team-a") {
			return errors.New("only team-a allowed")
		}
		return nil
	}

	v, err := NewVerifier(source, WithAuthorizer(customAuth))
	if err != nil {
		t.Fatal(err)
	}

	_, err = v.Validate(context.Background(), reqWithCerts(leaf, caCert))
	if err != nil {
		t.Fatalf("Validate error: %v", err)
	}

	// Different namespace should fail
	wrongID := spiffeid.RequireFromString("spiffe://prod.acme.com/ns/team-b/sa/orders")
	wrongLeaf := newTestSVID(t, caCert, caKey, wrongID)
	_, err = v.Validate(context.Background(), reqWithCerts(wrongLeaf, caCert))
	if err == nil {
		t.Fatal("expected error for team-b")
	}
}

func TestVerifier_UntrustedCA(t *testing.T) {
	// Source has one trust bundle
	td := spiffeid.RequireTrustDomainFromString("prod.acme.com")
	_, _, bundle := newTestCA(t, td)
	source := &fakeBundleSource{bundles: map[spiffeid.TrustDomain]*x509bundle.Bundle{td: bundle}}

	// But cert is signed by a different CA
	otherTD := spiffeid.RequireTrustDomainFromString("attacker.com")
	otherCA, otherKey, _ := newTestCA(t, otherTD)
	peerID := spiffeid.RequireFromString("spiffe://attacker.com/malicious")
	leaf := newTestSVID(t, otherCA, otherKey, peerID)

	v, err := NewVerifier(source, WithTrustDomain("prod.acme.com"))
	if err != nil {
		t.Fatal(err)
	}

	_, err = v.Validate(context.Background(), reqWithCerts(leaf, otherCA))
	if !errors.Is(err, m2mauth.ErrCertNotTrusted) {
		t.Errorf("expected ErrCertNotTrusted, got %v", err)
	}
}

// containsNamespace is a helper for the custom authorizer test.
func containsNamespace(spiffeID, ns string) bool {
	return len(spiffeID) > 0 && (spiffeID == "spiffe://prod.acme.com/ns/"+ns+"/sa/orders")
}
