// Package ginauth provides Gin framework middleware adapters for the m2mauth
// authentication library. It wraps m2mauth.Validator to work natively with
// gin.HandlerFunc and gin.Context.
//
// Usage:
//
//	v, _ := jwt.New(jwt.WithJWKSURL("https://auth.example.com/.well-known/jwks.json"))
//	r := gin.Default()
//	r.Use(ginauth.RequireAuth(v))
//	r.GET("/api/data", func(c *gin.Context) {
//	    claims := ginauth.ClaimsFromContext(c)
//	    c.JSON(200, gin.H{"subject": claims.Subject})
//	})
package ginauth

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/vishalanandl177/m2mauth"
)

// claimsKey is the gin.Context key used to store validated claims.
const claimsKey = "m2mauth.claims"

// Option configures the Gin auth middleware.
type Option func(*config)

type config struct {
	errorHandler func(c *gin.Context, err error)
}

// WithErrorHandler sets a custom error handler for authentication failures.
// The handler should write the HTTP response and call c.Abort().
func WithErrorHandler(fn func(c *gin.Context, err error)) Option {
	return func(cfg *config) { cfg.errorHandler = fn }
}

// RequireAuth returns a Gin middleware that validates every request using the
// given m2mauth.Validator. On success, claims are stored in gin.Context and
// also in the request context (retrievable via m2mauth.ClaimsFromContext).
func RequireAuth(v m2mauth.Validator, opts ...Option) gin.HandlerFunc {
	cfg := &config{
		errorHandler: defaultErrorHandler,
	}
	for _, o := range opts {
		o(cfg)
	}

	return func(c *gin.Context) {
		claims, err := v.Validate(c.Request.Context(), c.Request)
		if err != nil {
			cfg.errorHandler(c, err)
			return
		}

		// Store claims in gin.Context for easy retrieval.
		c.Set(claimsKey, claims)

		// Also store in request context for m2mauth.ClaimsFromContext compatibility.
		ctx := m2mauth.ContextWithClaims(c.Request.Context(), claims)
		c.Request = c.Request.WithContext(ctx)

		c.Next()
	}
}

// ClaimsFromContext extracts the validated claims from a gin.Context.
// Returns nil if no claims are present (i.e., auth middleware didn't run or failed).
func ClaimsFromContext(c *gin.Context) *m2mauth.Claims {
	val, exists := c.Get(claimsKey)
	if !exists {
		return nil
	}
	claims, ok := val.(*m2mauth.Claims)
	if !ok {
		return nil
	}
	return claims
}

func defaultErrorHandler(c *gin.Context, _ error) {
	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
}
