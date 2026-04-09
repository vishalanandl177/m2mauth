// Example: Gin server that makes authenticated outbound calls using OAuth 2.0
// Client Credentials.
//
// This demonstrates a common pattern: a Gin API server that receives requests
// and then calls downstream services using OAuth 2.0 tokens. It covers:
//   - OAuth 2.0 Client Credentials token acquisition with caching
//   - Wrapping http.Client with auto-auth via RoundTripper
//   - Making authenticated calls to downstream APIs from Gin handlers
//   - Combining inbound auth (JWT) with outbound auth (OAuth2)
//
// Usage:
//
//	go run main.go
package main

import (
	"io"
	"log"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/vishalanandl177/m2mauth/authlog"
	"github.com/vishalanandl177/m2mauth/contrib/ginauth"
	"github.com/vishalanandl177/m2mauth/credentials/oauth2"
	"github.com/vishalanandl177/m2mauth/middleware"
	"github.com/vishalanandl177/m2mauth/retry"
	jwtvalidator "github.com/vishalanandl177/m2mauth/validate/jwt"
)

func main() {
	logger := authlog.NewSlogHandler(slog.Default())

	// ── 1. Outbound: OAuth 2.0 client for calling downstream services ────
	downstreamAuth, err := oauth2.New(
		"https://auth.example.com/oauth/token",
		"my-gin-service",
		oauth2.WithClientSecret("my-client-secret"),
		oauth2.WithAudience("https://downstream-api.example.com"),
		oauth2.WithScopes("read:users", "write:events"),
		oauth2.WithRetryPolicy(retry.NewPolicy(
			retry.WithMaxRetries(3),
			retry.WithBaseDelay(100*time.Millisecond),
		)),
		oauth2.WithEventHandler(logger),
		oauth2.WithServiceName("downstream-client"),
	)
	if err != nil {
		log.Fatal(err)
	}

	// HTTP client with auto-auth — tokens are cached and refreshed automatically.
	downstreamClient := &http.Client{
		Transport: middleware.NewRoundTripper(http.DefaultTransport, downstreamAuth),
		Timeout:   10 * time.Second,
	}

	// ── 2. Inbound: JWT validation for incoming requests ─────────────────
	inboundValidator, err := jwtvalidator.New(
		jwtvalidator.WithJWKSURL("https://auth.example.com/.well-known/jwks.json"),
		jwtvalidator.WithIssuer("https://auth.example.com/"),
		jwtvalidator.WithAudience("https://my-gin-service.example.com"),
		jwtvalidator.WithEventHandler(logger),
	)
	if err != nil {
		log.Fatal(err)
	}

	// ── 3. Set up Gin routes ─────────────────────────────────────────────
	r := gin.Default()

	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// Protected API — validates inbound JWT, then calls downstream with OAuth2.
	api := r.Group("/api")
	api.Use(ginauth.RequireAuth(inboundValidator))
	{
		// Proxy user data from downstream service.
		api.GET("/users/:id", func(c *gin.Context) {
			claims := ginauth.ClaimsFromContext(c)
			userID := c.Param("id")

			// Call downstream API — OAuth2 token is attached automatically.
			resp, err := downstreamClient.Get(
				"https://downstream-api.example.com/users/" + userID,
			)
			if err != nil {
				c.JSON(http.StatusBadGateway, gin.H{"error": "downstream call failed"})
				return
			}
			defer resp.Body.Close()

			body, _ := io.ReadAll(resp.Body)
			c.JSON(resp.StatusCode, gin.H{
				"caller":          claims.Subject,
				"downstream_data": string(body),
			})
		})

		// Emit an event to downstream — uses write:events scope.
		api.POST("/events", func(c *gin.Context) {
			claims := ginauth.ClaimsFromContext(c)

			resp, err := downstreamClient.Post(
				"https://downstream-api.example.com/events",
				"application/json",
				c.Request.Body,
			)
			if err != nil {
				c.JSON(http.StatusBadGateway, gin.H{"error": "downstream call failed"})
				return
			}
			defer resp.Body.Close()

			c.JSON(resp.StatusCode, gin.H{
				"message": "event forwarded",
				"by":      claims.Subject,
			})
		})
	}

	log.Println("Starting Gin OAuth2 gateway on :8080")
	r.Run(":8080")
}
