// Example: Combined setup — outbound OAuth 2.0 + inbound JWT validation + secrets.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"net/http"

	"github.com/vishalanandl177/m2mauth"
	"github.com/vishalanandl177/m2mauth/authlog"
	"github.com/vishalanandl177/m2mauth/credentials/oauth2"
	"github.com/vishalanandl177/m2mauth/middleware"
	"github.com/vishalanandl177/m2mauth/retry"
	"github.com/vishalanandl177/m2mauth/secrets"
	jwtvalidator "github.com/vishalanandl177/m2mauth/validate/jwt"
)

func main() {
	logger := authlog.NewSlogHandler(slog.Default())

	// --- Secret Management ---
	// Chain providers: try env vars first, then mounted files.
	secretProvider := secrets.NewChain(
		secrets.NewEnvProvider("M2M_"),
		secrets.NewFileProvider("/run/secrets"),
	)

	// --- Outbound: OAuth 2.0 Client Credentials ---
	auth, err := oauth2.New(
		"https://auth.example.com/oauth/token",
		"svc-order-processor",
		oauth2.WithSecretProvider(secretProvider, "CLIENT_SECRET"),
		oauth2.WithAudience("https://api.example.com"),
		oauth2.WithScopes("read:users", "write:orders"),
		oauth2.WithRetryPolicy(retry.NewPolicy(retry.WithMaxRetries(3))),
		oauth2.WithEventHandler(logger),
	)
	if err != nil {
		log.Fatal(err)
	}

	// Outbound HTTP client with auto-auth.
	outboundClient := &http.Client{
		Transport: middleware.NewRoundTripper(http.DefaultTransport, auth),
	}

	// --- Inbound: JWT Validation ---
	validator, err := jwtvalidator.New(
		jwtvalidator.WithJWKSURL("https://auth.example.com/.well-known/jwks.json"),
		jwtvalidator.WithIssuer("https://auth.example.com/"),
		jwtvalidator.WithAudience("https://api.example.com"),
		jwtvalidator.WithRequiredScopes("read:users"),
		jwtvalidator.WithEventHandler(logger),
	)
	if err != nil {
		log.Fatal(err)
	}

	// --- HTTP Server ---
	mux := http.NewServeMux()

	// Protected endpoint: validates inbound JWT, then makes outbound OAuth2 call.
	mux.Handle("GET /api/orders", middleware.RequireAuth(validator)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, _ := m2mauth.ClaimsFromContext(r.Context())
			log.Printf("Authenticated request from: %s", claims.Subject)

			// Make an outbound call to another service (auto-authenticated).
			resp, err := outboundClient.Get("https://api.example.com/users")
			if err != nil {
				http.Error(w, "upstream error", http.StatusBadGateway)
				return
			}
			defer resp.Body.Close()

			json.NewEncoder(w).Encode(map[string]any{
				"caller":          claims.Subject,
				"upstream_status": resp.Status,
			})
		}),
	))

	fmt.Println("Combined M2M service listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
