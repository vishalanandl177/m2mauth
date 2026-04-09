package middleware

import (
	"fmt"
	"net/http"

	"github.com/vishalanandl177/m2mauth"
)

// ErrorHandler is called when authentication fails. It should write the
// HTTP error response. If nil, a default 401 response is sent.
type ErrorHandler func(w http.ResponseWriter, r *http.Request, err error)

// ServerOption configures server-side authentication middleware.
type ServerOption func(*serverConfig)

type serverConfig struct {
	errorHandler ErrorHandler
}

// WithErrorHandler sets a custom error handler for auth failures.
func WithErrorHandler(fn ErrorHandler) ServerOption {
	return func(c *serverConfig) { c.errorHandler = fn }
}

// RequireAuth returns an HTTP middleware that validates every request using
// the given Validator. On success, the claims are stored in the request context
// (retrievable via m2mauth.ClaimsFromContext).
func RequireAuth(v m2mauth.Validator, opts ...ServerOption) func(http.Handler) http.Handler {
	cfg := &serverConfig{
		errorHandler: defaultErrorHandler,
	}
	for _, o := range opts {
		o(cfg)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rv := recover(); rv != nil {
					cfg.errorHandler(w, r, fmt.Errorf("auth validation panic: %v", rv))
				}
			}()

			claims, err := v.Validate(r.Context(), r)
			if err != nil {
				cfg.errorHandler(w, r, err)
				return
			}

			ctx := m2mauth.ContextWithClaims(r.Context(), claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func defaultErrorHandler(w http.ResponseWriter, _ *http.Request, _ error) {
	http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
}
