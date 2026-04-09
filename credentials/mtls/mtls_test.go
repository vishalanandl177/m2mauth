package mtls

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vishalanandl177/m2mauth/authlog"
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

func TestNewTransport_NoCertSource(t *testing.T) {
	_, err := NewTransport()
	if err == nil {
		t.Fatal("expected error when no cert source configured")
	}
}

func TestNewTransport_WithCAFile(t *testing.T) {
	certPEM, keyPEM, err := testutil.GenerateSelfSignedCert("ca-file-test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	caCertPEM, _, _, _, err := testutil.GenerateCA()
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.pem")
	os.WriteFile(caFile, caCertPEM, 0o600)

	tr, err := NewTransport(
		WithCertPEM(certPEM, keyPEM),
		WithCACertFile(caFile),
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

func TestNewTransport_InvalidCAFile(t *testing.T) {
	certPEM, keyPEM, err := testutil.GenerateSelfSignedCert("test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	tr, err := NewTransport(WithCertPEM(certPEM, keyPEM), WithCACertFile("/nonexistent/ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Stop()

	_, err = tr.TLSConfig()
	if err == nil {
		t.Fatal("expected error for missing CA file")
	}
}

func TestNewTransport_InvalidCAPEM(t *testing.T) {
	certPEM, keyPEM, err := testutil.GenerateSelfSignedCert("test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	tr, err := NewTransport(WithCertPEM(certPEM, keyPEM), WithCACertPEM([]byte("not-a-cert")))
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Stop()

	_, err = tr.TLSConfig()
	if err == nil {
		t.Fatal("expected error for invalid CA PEM")
	}
}

func TestNewTransport_WithServerName(t *testing.T) {
	certPEM, keyPEM, err := testutil.GenerateSelfSignedCert("test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	tr, err := NewTransport(WithCertPEM(certPEM, keyPEM), WithServerName("custom.local"))
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Stop()

	tlsCfg, err := tr.TLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	if tlsCfg.ServerName != "custom.local" {
		t.Errorf("expected server name custom.local, got %q", tlsCfg.ServerName)
	}
}

func TestNewTransport_WithOptions(t *testing.T) {
	certPEM, keyPEM, err := testutil.GenerateSelfSignedCert("test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	tr, err := NewTransport(
		WithCertPEM(certPEM, keyPEM),
		WithEventHandler(authlog.NopHandler()),
		WithServiceName("my-svc"),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Stop()
}

func TestTransport_CertInfoNil(t *testing.T) {
	certPEM, keyPEM, err := testutil.GenerateSelfSignedCert("test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	tr, err := NewTransport(WithCertPEM(certPEM, keyPEM))
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Stop()

	// Force nil cert to test nil path
	tr.mu.Lock()
	tr.cert = nil
	tr.mu.Unlock()

	if info := tr.CertInfo(); info != nil {
		t.Error("expected nil CertInfo when cert is nil")
	}
}

func TestTransport_HTTPTransportError(t *testing.T) {
	certPEM, keyPEM, err := testutil.GenerateSelfSignedCert("test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	tr, err := NewTransport(WithCertPEM(certPEM, keyPEM), WithCACertFile("/nonexistent"))
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Stop()

	_, err = tr.HTTPTransport()
	if err == nil {
		t.Fatal("expected error for bad CA in HTTPTransport")
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
