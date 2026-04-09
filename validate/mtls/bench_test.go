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
)

// benchmark helpers — same as test helpers but use b.Fatal instead of t.Fatal

func benchGenerateCA(b *testing.B) (*x509.Certificate, *rsa.PrivateKey, *x509.CertPool) {
	b.Helper()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatal(err)
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
		b.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		b.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return caCert, caKey, pool
}

func benchSignClientCert(b *testing.B, caCert *x509.Certificate, caKey *rsa.PrivateKey) *x509.Certificate {
	b.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:         "svc-bench",
			OrganizationalUnit: []string{"Engineering"},
		},
		DNSNames:    []string{"bench.internal"},
		NotBefore:   time.Now().Add(-time.Minute),
		NotAfter:    time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		b.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		b.Fatal(err)
	}
	return cert
}

func benchReqWithCert(cert *x509.Certificate) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	return req
}

func BenchmarkVerifierCreation(b *testing.B) {
	_, _, pool := benchGenerateCA(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		New(WithTrustedCAs(pool), WithRequiredOU("Engineering"))
	}
}

func BenchmarkVerifierValidate(b *testing.B) {
	caCert, caKey, pool := benchGenerateCA(b)
	clientCert := benchSignClientCert(b, caCert, caKey)
	v := New(WithTrustedCAs(pool), WithRequiredOU("Engineering"))
	req := benchReqWithCert(clientCert)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := v.Validate(ctx, req)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifierValidateParallel(b *testing.B) {
	caCert, caKey, pool := benchGenerateCA(b)
	clientCert := benchSignClientCert(b, caCert, caKey)
	v := New(WithTrustedCAs(pool), WithRequiredOU("Engineering"))
	ctx := context.Background()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		req := benchReqWithCert(clientCert)
		for pb.Next() {
			_, err := v.Validate(ctx, req)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}
