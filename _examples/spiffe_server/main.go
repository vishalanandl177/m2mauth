// Example: SPIFFE/SPIRE-aware HTTP server using m2mauth contrib/spiffe.
//
// This example demonstrates workload authentication via the SPIRE
// Workload API. The SPIRE agent delivers X509-SVIDs and trust bundles
// over a Unix domain socket — no manual CA management needed.
//
// Prerequisites:
//   - SPIRE agent running on the host (default socket: /tmp/spire-agent/public/api.sock)
//   - Workload registered in SPIRE server with an appropriate SPIFFE ID
//
// Set the socket path via env var if non-default:
//
//	export SPIFFE_ENDPOINT_SOCKET=unix:///tmp/spire-agent/public/api.sock
//
// Run with:
//
//	go run main.go
package main

import (
	"context"
	"encoding/json"
	"log"
	"log/slog"
	"net/http"

	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"

	"github.com/vishalanandl177/m2mauth"
	"github.com/vishalanandl177/m2mauth/authlog"
	spiffeauth "github.com/vishalanandl177/m2mauth/contrib/spiffe"
	"github.com/vishalanandl177/m2mauth/middleware"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger := slog.Default()

	// ── 1. Connect to the SPIRE Workload API ─────────────────────────────
	// This returns a live source of X509-SVIDs and trust bundles that
	// auto-rotates as SPIRE delivers new material.
	source, err := workloadapi.NewX509Source(ctx)
	if err != nil {
		log.Fatalf("Failed to connect to SPIRE Workload API: %v", err)
	}
	defer source.Close()

	// ── 2. Create the m2mauth SPIFFE verifier ────────────────────────────
	// This validates peer client certificates against the live SPIRE
	// trust bundle and authorizes the resulting SPIFFE ID.
	verifier, err := spiffeauth.NewVerifier(source,
		spiffeauth.WithTrustDomain("prod.acme.com"),
		// Or restrict to specific SPIFFE IDs:
		// spiffeauth.WithAllowedIDs(
		//     "spiffe://prod.acme.com/ns/default/sa/orders",
		//     "spiffe://prod.acme.com/ns/default/sa/payments",
		// ),
		spiffeauth.WithEventHandler(authlog.NewSlogHandler(logger)),
		spiffeauth.WithServiceName("orders-api"),
	)
	if err != nil {
		log.Fatalf("Failed to create SPIFFE verifier: %v", err)
	}

	// ── 3. Set up HTTP routes protected by the verifier ──────────────────
	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok"}`))
	})

	// Protected endpoint — only workloads in prod.acme.com trust domain get in.
	mux.Handle("GET /api/whoami", middleware.RequireAuth(verifier)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := m2mauth.ClaimsFromContext(r.Context())
			if !ok {
				http.Error(w, "no claims", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"spiffe_id":    claims.Subject,
				"trust_domain": claims.Extra["trust_domain"],
				"expires_at":   claims.ExpiresAt,
			})
		}),
	))

	// ── 4. Build TLS config that requires client certs and uses our SVID ─
	// tlsconfig.MTLSServerConfig builds a tls.Config that:
	//   - Uses our SPIFFE X509-SVID as the server cert
	//   - Requires clients to present certs (mTLS)
	//   - Uses the SPIRE trust bundle for peer verification
	//
	// Note: go-spiffe's AuthorizeAny() just permits any peer in the bundle;
	// our m2mauth verifier then applies the finer-grained trust-domain
	// or SPIFFE ID allowlist policy inside the HTTP handler chain.
	tlsCfg := tlsconfig.MTLSServerConfig(source, source, tlsconfig.AuthorizeAny())

	server := &http.Server{
		Addr:      ":8443",
		Handler:   mux,
		TLSConfig: tlsCfg,
	}

	log.Println("Starting SPIFFE-secured server on :8443")
	// ListenAndServeTLS with empty cert/key — the TLS config provides them via SPIFFE source.
	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Fatal(err)
	}
}
