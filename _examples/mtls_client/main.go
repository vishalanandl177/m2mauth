// Example: mTLS client with certificate rotation.
package main

import (
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"time"

	"github.com/vishalanandl177/m2mauth/authlog"
	"github.com/vishalanandl177/m2mauth/credentials/mtls"
)

func main() {
	// Create an mTLS transport with automatic certificate rotation.
	transport, err := mtls.NewTransport(
		mtls.WithCertFile("/etc/certs/client.crt", "/etc/certs/client.key"),
		mtls.WithCACertFile("/etc/certs/ca.crt"),
		mtls.WithRotationInterval(5*time.Minute),
		mtls.WithEventHandler(authlog.NewSlogHandler(slog.Default())),
		mtls.WithServiceName("payment-service"),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer transport.Stop()

	// Check certificate info.
	info := transport.CertInfo()
	fmt.Printf("Certificate: %s (expires: %s)\n", info.Subject, info.NotAfter)

	if info.IsExpiring(24 * time.Hour) {
		fmt.Println("WARNING: Certificate expires within 24 hours!")
	}

	// Create HTTP client with mTLS transport.
	httpTransport, err := transport.HTTPTransport()
	if err != nil {
		log.Fatal(err)
	}
	client := &http.Client{Transport: httpTransport}

	// Make authenticated requests — mTLS handles auth at the transport layer.
	resp, err := client.Get("https://internal-api.example.com/data")
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	fmt.Printf("Response status: %s\n", resp.Status)
}
