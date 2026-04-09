package mtls

import (
	"testing"
	"time"

	"github.com/vishalanandl177/m2mauth/internal/testutil"
)

func BenchmarkTransportCreation(b *testing.B) {
	certPEM, keyPEM, err := testutil.GenerateSelfSignedCert("bench-svc", time.Hour)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tr, err := NewTransport(WithCertPEM(certPEM, keyPEM))
		if err != nil {
			b.Fatal(err)
		}
		tr.Stop()
	}
}

func BenchmarkCertInfo(b *testing.B) {
	certPEM, keyPEM, err := testutil.GenerateSelfSignedCert("bench-svc", time.Hour)
	if err != nil {
		b.Fatal(err)
	}
	tr, err := NewTransport(WithCertPEM(certPEM, keyPEM))
	if err != nil {
		b.Fatal(err)
	}
	defer tr.Stop()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		info := tr.CertInfo()
		if info == nil {
			b.Fatal("nil cert info")
		}
	}
}

func BenchmarkCertInfoParallel(b *testing.B) {
	certPEM, keyPEM, err := testutil.GenerateSelfSignedCert("bench-svc", time.Hour)
	if err != nil {
		b.Fatal(err)
	}
	tr, err := NewTransport(WithCertPEM(certPEM, keyPEM))
	if err != nil {
		b.Fatal(err)
	}
	defer tr.Stop()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			info := tr.CertInfo()
			if info == nil {
				b.Fatal("nil cert info")
			}
		}
	})
}
