// Example: Gin framework API key-protected server using m2mauth.
//
// This demonstrates how to use the ginauth adapter with the API key
// validator to protect Gin routes. It covers:
//   - In-memory key store with per-key claims
//   - Custom header name for API key extraction
//   - Scope-based authorization in handlers
//   - Custom error responses
//
// Usage:
//
//	go run main.go
//
// Test with curl:
//
//	curl -H "X-API-Key: sk_live_orders_abc123" http://localhost:8080/api/data
//	curl -H "X-API-Key: sk_live_analytics_def456" http://localhost:8080/api/admin  # 403
package main

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/vishalanandl177/m2mauth"
	"github.com/vishalanandl177/m2mauth/contrib/ginauth"
	apikeyvalidator "github.com/vishalanandl177/m2mauth/validate/apikey"
)

func main() {
	// ── 1. Define valid API keys and their associated claims ─────────────
	store := apikeyvalidator.NewMapStore(map[string]*m2mauth.Claims{
		"sk_live_orders_abc123": {
			Subject: "order-service",
			Scopes:  []string{"read:data", "write:orders"},
		},
		"sk_live_analytics_def456": {
			Subject: "analytics-service",
			Scopes:  []string{"read:data"},
		},
		"sk_live_admin_ghi789": {
			Subject: "admin-service",
			Scopes:  []string{"read:data", "write:orders", "admin"},
		},
	})

	// ── 2. Create the API key validator ──────────────────────────────────
	validator, err := apikeyvalidator.New(
		apikeyvalidator.WithStore(store),
		apikeyvalidator.WithHeaderName("X-API-Key"),
	)
	if err != nil {
		log.Fatal(err)
	}

	// ── 3. Set up Gin routes ─────────────────────────────────────────────
	r := gin.Default()

	// Public health check.
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// Protected routes — require valid API key.
	api := r.Group("/api")
	api.Use(ginauth.RequireAuth(validator))
	{
		// Any valid API key can access this.
		api.GET("/data", func(c *gin.Context) {
			claims := ginauth.ClaimsFromContext(c)
			c.JSON(http.StatusOK, gin.H{
				"service": claims.Subject,
				"scopes":  claims.Scopes,
			})
		})

		// Only keys with "write:orders" scope can access this.
		api.POST("/orders", func(c *gin.Context) {
			claims := ginauth.ClaimsFromContext(c)
			if !claims.HasScope("write:orders") {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
					"error": "insufficient scope: write:orders required",
				})
				return
			}
			c.JSON(http.StatusCreated, gin.H{
				"message": "order created",
				"by":      claims.Subject,
			})
		})

		// Only keys with "admin" scope can access this.
		api.DELETE("/orders/:id", func(c *gin.Context) {
			claims := ginauth.ClaimsFromContext(c)
			if !claims.HasScope("admin") {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
					"error": "admin scope required",
				})
				return
			}
			c.JSON(http.StatusOK, gin.H{
				"message": "order deleted",
				"id":      c.Param("id"),
				"by":      claims.Subject,
			})
		})
	}

	log.Println("Starting Gin API key server on :8080")
	r.Run(":8080")
}
