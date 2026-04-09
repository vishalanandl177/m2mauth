package mtls

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vishalanandl177/m2mauth/internal/testutil"
)

func TestNewTransport_PEM(t *testing.T) {
	certPEM, keyPEM, err := testutil.GenerateSelfSignedCert("test-service", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	tr, err := NewTransport(WithCertPEM(certPEM, keyPEM))
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Stop()

	info := tr.CertInfo()
	if info == nil {
		t.Fatal("expected cert info")
	}
	if info.Subject != "test-service" {
		t.Errorf("expected subject test-service, got %q", info.Subject)
	}
}

func TestNewTransport_File(t *testing.T) {
	certPEM, keyPEM, err := testutil.GenerateSelfSignedCert("file-test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	os.WriteFile(certFile, certPEM, 0o600)
	os.WriteFile(keyFile, keyPEM, 0o600)

	tr, err := NewTransport(WithCertFile(certFile, keyFile))
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Stop()

	if info := tr.CertInfo(); info.Subject != "file-test" {
		t.Errorf("expected subject file-test, got %q", info.Subject)
	}
}

func TestNewTransport_WithCA(t *testing.T) {
	certPEM, keyPEM, err := testutil.GenerateSelfSignedCert("ca-test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	caCertPEM, _, _, _, err := testutil.GenerateCA()
	if err != nil {
		t.Fatal(err)
	}

	tr, err := NewTransport(
		WithCertPEM(certPEM, keyPEM),
		WithCACertPEM(caCertPEM),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Stop()

	tlsCfg, err := tr.TLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	if tlsCfg.RootCAs == nil {
		t.Error("expected RootCAs to be set")
	}
}

func TestNewTransport_HTTPTransport(t *testing.T) {
	certPEM, keyPEM, err := testutil.GenerateSelfSignedCert("http-test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	tr, err := NewTransport(WithCertPEM(certPEM, keyPEM))
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Stop()

	httpTr, err := tr.HTTPTransport()
	if err != nil {
		t.Fatal(err)
	}
	if httpTr.TLSClientConfig == nil {
		t.Error("expected TLS config on HTTP transport")
	}
}

func TestCertInfo_IsExpiring(t *testing.T) {
	ci := &CertInfo{
		NotAfter: time.Now().Add(12 * time.Hour),
	}

	if !ci.IsExpiring(24 * time.Hour) {
		t.Error("cert expiring within 24h should be flagged")
	}
	if ci.IsExpiring(1 * time.Hour) {
		t.Error("cert not expiring within 1h should not be flagged")
	}
}

func TestNewTransport_Rotation(t *testing.T) {
	certPEM1, keyPEM1, _ := testutil.GenerateSelfSignedCert("rotation-v1", time.Hour)
	certPEM2, keyPEM2, _ := testutil.GenerateSelfSignedCert("rotation-v2", time.Hour)

	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	os.WriteFile(certFile, certPEM1, 0o600)
	os.WriteFile(keyFile, keyPEM1, 0o600)

	tr, err := NewTransport(
		WithCertFile(certFile, keyFile),
		WithRotationInterval(50*time.Millisecond),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Stop()

	if info := tr.CertInfo(); info.Subject != "rotation-v1" {
		t.Fatalf("expected rotation-v1, got %q", info.Subject)
	}

	// Replace cert files.
	os.WriteFile(certFile, certPEM2, 0o600)
	os.WriteFile(keyFile, keyPEM2, 0o600)

	// Wait for rotation.
	time.Sleep(200 * time.Millisecond)

	if info := tr.CertInfo(); info.Subject != "rotation-v2" {
		t.Errorf("expected rotation-v2 after rotation, got %q", info.Subject)
	}
}
