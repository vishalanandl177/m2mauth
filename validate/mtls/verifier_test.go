package mtls

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vishalanandl177/m2mauth"
)

// helper: generate a CA cert + key
func generateCA(t *testing.T) (*x509.Certificate, *rsa.PrivateKey, *x509.CertPool) {
	t.Helper()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return caCert, caKey, pool
}

type certOpts struct {
	cn       string
	ou       []string
	dns      []string
	notAfter time.Time
}

// helper: sign a client cert with the CA
func signClientCert(t *testing.T, caCert *x509.Certificate, caKey *rsa.PrivateKey, opts certOpts) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if opts.notAfter.IsZero() {
		opts.notAfter = time.Now().Add(time.Hour)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:         opts.cn,
			OrganizationalUnit: opts.ou,
		},
		DNSNames:    opts.dns,
		NotBefore:   time.Now().Add(-time.Minute),
		NotAfter:    opts.notAfter,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// build an *http.Request with TLS peer certs attached
func reqWithCerts(certs ...*x509.Certificate) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: certs}
	return req
}

func TestVerifier_ValidCert(t *testing.T) {
	caCert, caKey, pool := generateCA(t)
	clientCert := signClientCert(t, caCert, caKey, certOpts{
		cn:  "svc-orders",
		ou:  []string{"Engineering"},
		dns: []string{"orders.internal"},
	})

	v := New(WithTrustedCAs(pool))
	claims, err := v.Validate(context.Background(), reqWithCerts(clientCert))
	if err != nil {
		t.Fatalf("Validate error: %v", err)
	}
	if claims.Subject != "svc-orders" {
		t.Errorf("expected subject svc-orders, got %q", claims.Subject)
	}
	if claims.Issuer != "Test CA" {
		t.Errorf("expected issuer Test CA, got %q", claims.Issuer)
	}
	// Check extra claims
	if serial, ok := claims.Extra["serial"]; !ok || serial == "" {
		t.Error("expected serial in extra claims")
	}
}

func TestVerifier_NoCert(t *testing.T) {
	v := New()

	// No TLS at all
	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	_, err := v.Validate(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for no client certificate")
	}

	// TLS but empty peer certs
	req.TLS = &tls.ConnectionState{}
	_, err = v.Validate(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for empty peer certificates")
	}
}

func TestVerifier_UntrustedCert(t *testing.T) {
	// Create two separate CAs
	caCert1, caKey1, _ := generateCA(t)
	_, _, pool2 := generateCA(t) // different CA

	// Sign cert with CA1 but validate against CA2's pool
	clientCert := signClientCert(t, caCert1, caKey1, certOpts{cn: "svc-untrusted"})

	v := New(WithTrustedCAs(pool2))
	_, err := v.Validate(context.Background(), reqWithCerts(clientCert))
	if err == nil {
		t.Fatal("expected error for untrusted certificate")
	}
	if err != m2mauth.ErrCertNotTrusted {
		t.Errorf("expected ErrCertNotTrusted, got %v", err)
	}
}

func TestVerifier_RequiredCN_Match(t *testing.T) {
	caCert, caKey, pool := generateCA(t)
	clientCert := signClientCert(t, caCert, caKey, certOpts{cn: "svc-orders"})

	v := New(WithTrustedCAs(pool), WithRequiredCN("svc-orders"))
	claims, err := v.Validate(context.Background(), reqWithCerts(clientCert))
	if err != nil {
		t.Fatalf("Validate error: %v", err)
	}
	if claims.Subject != "svc-orders" {
		t.Errorf("expected subject svc-orders, got %q", claims.Subject)
	}
}

func TestVerifier_RequiredCN_Mismatch(t *testing.T) {
	caCert, caKey, pool := generateCA(t)
	clientCert := signClientCert(t, caCert, caKey, certOpts{cn: "svc-payments"})

	v := New(WithTrustedCAs(pool), WithRequiredCN("svc-orders"))
	_, err := v.Validate(context.Background(), reqWithCerts(clientCert))
	if err == nil {
		t.Fatal("expected error for CN mismatch")
	}
}

func TestVerifier_RequiredOU_Match(t *testing.T) {
	caCert, caKey, pool := generateCA(t)
	clientCert := signClientCert(t, caCert, caKey, certOpts{
		cn: "svc-orders",
		ou: []string{"Engineering", "Platform"},
	})

	v := New(WithTrustedCAs(pool), WithRequiredOU("Engineering"))
	claims, err := v.Validate(context.Background(), reqWithCerts(clientCert))
	if err != nil {
		t.Fatalf("Validate error: %v", err)
	}
	if claims.Subject != "svc-orders" {
		t.Errorf("expected subject svc-orders, got %q", claims.Subject)
	}
}

func TestVerifier_RequiredOU_Mismatch(t *testing.T) {
	caCert, caKey, pool := generateCA(t)
	clientCert := signClientCert(t, caCert, caKey, certOpts{
		cn: "svc-orders",
		ou: []string{"Marketing"},
	})

	v := New(WithTrustedCAs(pool), WithRequiredOU("Engineering"))
	_, err := v.Validate(context.Background(), reqWithCerts(clientCert))
	if err == nil {
		t.Fatal("expected error for OU mismatch")
	}
}

func TestVerifier_DNSSANInExtra(t *testing.T) {
	caCert, caKey, pool := generateCA(t)
	clientCert := signClientCert(t, caCert, caKey, certOpts{
		cn:  "svc-orders",
		dns: []string{"orders.internal", "orders.svc.cluster.local"},
	})

	v := New(WithTrustedCAs(pool))
	claims, err := v.Validate(context.Background(), reqWithCerts(clientCert))
	if err != nil {
		t.Fatalf("Validate error: %v", err)
	}
	dnsNames, ok := claims.Extra["dns_san"].([]string)
	if !ok {
		t.Fatal("expected dns_san in extra claims")
	}
	if len(dnsNames) != 2 {
		t.Errorf("expected 2 DNS SANs, got %d", len(dnsNames))
	}
}

func TestVerifier_NoTrustedCAs_SkipsVerification(t *testing.T) {
	// When no TrustedCAs configured, skip CA verification (rely on TLS layer)
	caCert, caKey, _ := generateCA(t)
	clientCert := signClientCert(t, caCert, caKey, certOpts{cn: "svc-test"})

	v := New() // no TrustedCAs
	claims, err := v.Validate(context.Background(), reqWithCerts(clientCert))
	if err != nil {
		t.Fatalf("Validate error: %v", err)
	}
	if claims.Subject != "svc-test" {
		t.Errorf("expected subject svc-test, got %q", claims.Subject)
	}
}

func TestVerifier_ExpiredCert(t *testing.T) {
	caCert, caKey, _ := generateCA(t)
	// Create a cert that expired 1 hour ago
	expiredCert := signClientCert(t, caCert, caKey, certOpts{
		cn:       "svc-expired",
		notAfter: time.Now().Add(-time.Hour),
	})

	v := New() // no TrustedCAs
	_, err := v.Validate(context.Background(), reqWithCerts(expiredCert))
	if err == nil {
		t.Fatal("expected error for expired certificate")
	}
	if err != m2mauth.ErrCertExpired {
		t.Errorf("expected ErrCertExpired, got %v", err)
	}
}

func TestVerifier_WithOptions(t *testing.T) {
	caCert, caKey, pool := generateCA(t)
	clientCert := signClientCert(t, caCert, caKey, certOpts{cn: "svc-test"})

	v := New(
		WithTrustedCAs(pool),
		WithEventHandler(nil),
		WithServiceName("my-mtls-verifier"),
	)
	claims, err := v.Validate(context.Background(), reqWithCerts(clientCert))
	if err != nil {
		t.Fatalf("Validate error: %v", err)
	}
	if claims.Subject != "svc-test" {
		t.Errorf("expected subject svc-test, got %q", claims.Subject)
	}
}
