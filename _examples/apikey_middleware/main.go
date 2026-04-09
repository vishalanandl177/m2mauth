// Example: API key validation middleware.
package main

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/vishalanandl177/m2mauth"
	"github.com/vishalanandl177/m2mauth/middleware"
	apikeyvalidator "github.com/vishalanandl177/m2mauth/validate/apikey"
)

func main() {
	// Define valid API keys and their associated claims.
	store := apikeyvalidator.NewMapStore(map[string]*m2mauth.Claims{
		"sk_live_orders_abc123": {
			Subject: "order-service",
			Scopes:  []string{"read:data", "write:orders"},
		},
		"sk_live_analytics_def456": {
			Subject: "analytics-service",
			Scopes:  []string{"read:data"},
		},
	})

	validator, err := apikeyvalidator.New(
		apikeyvalidator.WithStore(store),
		apikeyvalidator.WithHeaderName("X-API-Key"),
	)
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	protected := middleware.RequireAuth(validator)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, _ := m2mauth.ClaimsFromContext(r.Context())
			json.NewEncoder(w).Encode(map[string]any{
				"service": claims.Subject,
				"scopes":  claims.Scopes,
			})
		}),
	)
	mux.Handle("GET /api/data", protected)

	log.Println("Server listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
