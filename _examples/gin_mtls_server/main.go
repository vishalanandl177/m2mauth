// Example: Gin framework mTLS-protected API server using m2mauth.
//
// This demonstrates how to use the ginauth adapter with the mTLS verifier
// to authenticate client certificates on a Gin server. It covers:
//   - Loading a trusted CA pool for client certificate verification
//   - Restricting access by Organizational Unit (OU)
//   - Configuring Go's TLS server to request client certificates
//   - Accessing verified certificate claims in Gin handlers
//
// Usage:
//
//	go run main.go
//
// Test with curl:
//
//	curl --cert client.crt --key client.key --cacert ca.crt https://localhost:8443/api/whoami
package main

import (
	"crypto/tls"
	"crypto/x509"
	"log"
	"log/slog"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/vishalanandl177/m2mauth/authlog"
	"github.com/vishalanandl177/m2mauth/contrib/ginauth"
	vmtls "github.com/vishalanandl177/m2mauth/validate/mtls"
)

func main() {
	// ── 1. Load the CA certificate pool ──────────────────────────────────
	caCertPEM, err := os.ReadFile("/etc/certs/ca.crt")
	if err != nil {
		log.Fatalf("Failed to read CA cert: %v", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCertPEM) {
		log.Fatal("Failed to parse CA certificate")
	}

	// ── 2. Create the mTLS verifier ──────────────────────────────────────
	verifier := vmtls.New(
		vmtls.WithTrustedCAs(caPool),
		vmtls.WithRequiredOU("Engineering"), // Only allow Engineering OU
		vmtls.WithEventHandler(authlog.NewSlogHandler(slog.Default())),
		vmtls.WithServiceName("gin-mtls-server"),
	)

	// ── 3. Set up Gin routes ─────────────────────────────────────────────
	r := gin.Default()

	// Public health check — no mTLS required.
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// Protected API — requires valid client certificate.
	api := r.Group("/api")
	api.Use(ginauth.RequireAuth(verifier))
	{
		// Returns the authenticated service identity.
		api.GET("/whoami", func(c *gin.Context) {
			claims := ginauth.ClaimsFromContext(c)
			c.JSON(http.StatusOK, gin.H{
				"subject":    claims.Subject,
				"issuer":     claims.Issuer,
				"issued_at":  claims.IssuedAt,
				"expires_at": claims.ExpiresAt,
				"serial":     claims.Extra["serial"],
				"ou":         claims.Extra["ou"],
				"dns_san":    claims.Extra["dns_san"],
			})
		})

		// Example: restrict to specific CN in addition to OU.
		api.GET("/admin", func(c *gin.Context) {
			claims := ginauth.ClaimsFromContext(c)
			if claims.Subject != "admin-service" {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
					"error": "only admin-service is allowed",
				})
				return
			}
			c.JSON(http.StatusOK, gin.H{"message": "admin access granted"})
		})
	}

	// ── 4. Configure TLS server to request client certificates ───────────
	tlsCfg := &tls.Config{
		ClientCAs:  caPool,
		ClientAuth: tls.RequireAnyClientCert, // Request cert; m2mauth verifies it
		MinVersion: tls.VersionTLS12,
	}

	server := &http.Server{
		Addr:      ":8443",
		Handler:   r,
		TLSConfig: tlsCfg,
	}

	log.Println("Starting Gin mTLS server on :8443")
	if err := server.ListenAndServeTLS("/etc/certs/server.crt", "/etc/certs/server.key"); err != nil {
		log.Fatal(err)
	}
}
