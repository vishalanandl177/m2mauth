// Example: Gin framework JWT-protected API server using m2mauth.
//
// This demonstrates how to use the ginauth adapter to protect
// Gin routes with JWT validation.
//
// Usage:
//
//	go run main.go
package main

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/vishalanandl177/m2mauth/contrib/ginauth"
	"github.com/vishalanandl177/m2mauth/validate/jwt"
)

func main() {
	// Create a JWT validator with your JWKS endpoint.
	v, err := jwt.New(
		jwt.WithJWKSURL("https://auth.example.com/.well-known/jwks.json"),
		jwt.WithIssuer("https://auth.example.com/"),
		jwt.WithAudience("https://api.example.com"),
		jwt.WithRequiredScopes("read:data"),
	)
	if err != nil {
		log.Fatal(err)
	}

	r := gin.Default()

	// Public routes (no auth required).
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// Protected routes — require valid JWT.
	api := r.Group("/api")
	api.Use(ginauth.RequireAuth(v))
	{
		api.GET("/data", func(c *gin.Context) {
			claims := ginauth.ClaimsFromContext(c)
			c.JSON(http.StatusOK, gin.H{
				"message": "authenticated",
				"subject": claims.Subject,
				"scopes":  claims.Scopes,
			})
		})

		api.GET("/profile", func(c *gin.Context) {
			claims := ginauth.ClaimsFromContext(c)
			c.JSON(http.StatusOK, gin.H{
				"subject":    claims.Subject,
				"issuer":     claims.Issuer,
				"expires_at": claims.ExpiresAt,
			})
		})
	}

	log.Println("Starting Gin server on :8080")
	r.Run(":8080")
}
