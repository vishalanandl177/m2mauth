// Example: OAuth 2.0 Client Credentials flow for outbound M2M authentication.
package main

import (
	"fmt"
	"log"
	"log/slog"
	"net/http"

	"github.com/vishalanandl177/m2mauth/authlog"
	"github.com/vishalanandl177/m2mauth/credentials/oauth2"
	"github.com/vishalanandl177/m2mauth/middleware"
	"github.com/vishalanandl177/m2mauth/retry"
)

func main() {
	// Create an OAuth 2.0 client credentials authenticator.
	auth, err := oauth2.New(
		"https://auth.example.com/oauth/token",
		"svc-order-processor",
		oauth2.WithClientSecret("your-secret-here"),
		oauth2.WithAudience("https://api.example.com"),
		oauth2.WithScopes("read:users", "write:orders"),
		oauth2.WithRetryPolicy(retry.DefaultPolicy()),
		oauth2.WithEventHandler(authlog.NewSlogHandler(slog.Default())),
		oauth2.WithServiceName("order-service"),
	)
	if err != nil {
		log.Fatal(err)
	}

	// Wrap http.Client with the authenticator — every request gets a Bearer token.
	client := &http.Client{
		Transport: middleware.NewRoundTripper(http.DefaultTransport, auth),
	}

	// Make authenticated requests — tokens are cached and auto-refreshed.
	resp, err := client.Get("https://api.example.com/users")
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	fmt.Printf("Response status: %s\n", resp.Status)
}
