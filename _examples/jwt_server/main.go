// Example: JWT validation middleware for protecting API endpoints.
package main

import (
	"encoding/json"
	"log"
	"log/slog"
	"net/http"

	"github.com/vishalanandl177/m2mauth"
	"github.com/vishalanandl177/m2mauth/authlog"
	"github.com/vishalanandl177/m2mauth/middleware"
	jwtvalidator "github.com/vishalanandl177/m2mauth/validate/jwt"
)

func main() {
	// Create a JWT validator.
	validator, err := jwtvalidator.New(
		jwtvalidator.WithJWKSURL("https://auth.example.com/.well-known/jwks.json"),
		jwtvalidator.WithIssuer("https://auth.example.com/"),
		jwtvalidator.WithAudience("https://api.example.com"),
		jwtvalidator.WithRequiredScopes("read:users"),
		jwtvalidator.WithEventHandler(authlog.NewSlogHandler(slog.Default())),
	)
	if err != nil {
		log.Fatal(err)
	}

	// Create a protected handler.
	mux := http.NewServeMux()

	// Public endpoint.
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	// Protected endpoint — requires valid JWT with read:users scope.
	protected := middleware.RequireAuth(validator)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, _ := m2mauth.ClaimsFromContext(r.Context())
			json.NewEncoder(w).Encode(map[string]any{
				"message": "authenticated!",
				"service": claims.Subject,
				"scopes":  claims.Scopes,
			})
		}),
	)
	mux.Handle("GET /api/users", protected)

	log.Println("Server listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
