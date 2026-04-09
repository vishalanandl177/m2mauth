// Package middleware provides HTTP middleware for both outbound (client)
// and inbound (server) authentication.
package middleware

import (
	"net/http"

	"github.com/vishalanandl177/m2mauth"
)

// RoundTripper wraps an http.RoundTripper and an Authenticator to automatically
// attach credentials to every outbound HTTP request.
type RoundTripper struct {
	base http.RoundTripper
	auth m2mauth.Authenticator
}

// NewRoundTripper creates a new authenticating RoundTripper.
// It wraps base (typically http.DefaultTransport) and uses auth to add credentials.
func NewRoundTripper(base http.RoundTripper, auth m2mauth.Authenticator) *RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return &RoundTripper{base: base, auth: auth}
}

// RoundTrip adds authentication credentials and then delegates to the base transport.
func (rt *RoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clone the request to avoid mutating the original.
	reqClone := req.Clone(req.Context())
	if err := rt.auth.Authenticate(req.Context(), reqClone); err != nil {
		return nil, err
	}
	return rt.base.RoundTrip(reqClone)
}
