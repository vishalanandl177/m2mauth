# m2mauth

A batteries-included Go library for **Machine-to-Machine (M2M) authentication** — covering OAuth 2.0 Client Credentials, mTLS, API Keys, and JWT validation.

Zero external dependencies. Works with `net/http` out of the box. Framework adapters available for **Gin**.

## Features

| Feature | Package | Direction |
|---------|---------|-----------|
| **OAuth 2.0 Client Credentials** | `credentials/oauth2` | Outbound |
| **mTLS with cert rotation** | `credentials/mtls` | Outbound |
| **API Key injection** | `credentials/apikey` | Outbound |
| **JWT validation (JWKS)** | `validate/jwt` | Inbound |
| **API Key validation** | `validate/apikey` | Inbound |
| **mTLS cert verification** | `validate/mtls` | Inbound |
| **HTTP middleware** | `middleware` | Both |
| **Gin framework adapter** | `contrib/ginauth` | Inbound |
| **Secret management** | `secrets` | Infrastructure |
| **Retry with backoff** | `retry` | Infrastructure |
| **Observability** | `authlog` | Infrastructure |

## Install

```bash
go get github.com/vishalanandl177/m2mauth
```

For Gin framework support:

```bash
go get github.com/vishalanandl177/m2mauth/contrib/ginauth
```

## Quick Start

### Outbound: OAuth 2.0 Client Credentials

```go
import (
    "github.com/vishalanandl177/m2mauth/credentials/oauth2"
    "github.com/vishalanandl177/m2mauth/middleware"
)

auth, _ := oauth2.New("https://auth.example.com/oauth/token", "my-service",
    oauth2.WithClientSecret("secret"),
    oauth2.WithAudience("https://api.example.com"),
    oauth2.WithScopes("read:users", "write:orders"),
)

client := &http.Client{
    Transport: middleware.NewRoundTripper(http.DefaultTransport, auth),
}

// Every request automatically gets a Bearer token (cached, auto-refreshed).
resp, _ := client.Get("https://api.example.com/users")
```

### Inbound: JWT Validation (net/http)

```go
import (
    "github.com/vishalanandl177/m2mauth/middleware"
    jwtvalidator "github.com/vishalanandl177/m2mauth/validate/jwt"
)

v, _ := jwtvalidator.New(
    jwtvalidator.WithJWKSURL("https://auth.example.com/.well-known/jwks.json"),
    jwtvalidator.WithIssuer("https://auth.example.com/"),
    jwtvalidator.WithAudience("https://api.example.com"),
    jwtvalidator.WithRequiredScopes("read:users"),
)

mux.Handle("/api/users", middleware.RequireAuth(v)(usersHandler))
```

### Inbound: JWT Validation (Gin)

```go
import (
    "github.com/gin-gonic/gin"
    "github.com/vishalanandl177/m2mauth/contrib/ginauth"
    jwtvalidator "github.com/vishalanandl177/m2mauth/validate/jwt"
)

v, _ := jwtvalidator.New(
    jwtvalidator.WithJWKSURL("https://auth.example.com/.well-known/jwks.json"),
    jwtvalidator.WithIssuer("https://auth.example.com/"),
    jwtvalidator.WithAudience("https://api.example.com"),
)

r := gin.Default()
api := r.Group("/api")
api.Use(ginauth.RequireAuth(v))
api.GET("/data", func(c *gin.Context) {
    claims := ginauth.ClaimsFromContext(c)
    c.JSON(200, gin.H{"subject": claims.Subject})
})
```

### Inbound: mTLS Verification (Gin)

```go
import (
    "crypto/x509"
    "github.com/gin-gonic/gin"
    "github.com/vishalanandl177/m2mauth/contrib/ginauth"
    vmtls "github.com/vishalanandl177/m2mauth/validate/mtls"
)

caPool := x509.NewCertPool()
caPool.AppendCertsFromPEM(caCertPEM)

verifier := vmtls.New(
    vmtls.WithTrustedCAs(caPool),
    vmtls.WithRequiredOU("Engineering"),
)

r := gin.Default()
api := r.Group("/api")
api.Use(ginauth.RequireAuth(verifier))
api.GET("/whoami", func(c *gin.Context) {
    claims := ginauth.ClaimsFromContext(c)
    c.JSON(200, gin.H{
        "subject": claims.Subject,
        "ou":      claims.Extra["ou"],
        "dns_san": claims.Extra["dns_san"],
    })
})

// Run with TLS configured to request client certs
```

### mTLS Client with Certificate Rotation

```go
import "github.com/vishalanandl177/m2mauth/credentials/mtls"

transport, _ := mtls.NewTransport(
    mtls.WithCertFile("/etc/certs/client.crt", "/etc/certs/client.key"),
    mtls.WithCACertFile("/etc/certs/ca.crt"),
    mtls.WithRotationInterval(5 * time.Minute),  // Auto-reload certs
)
defer transport.Stop()

httpTransport, _ := transport.HTTPTransport()
client := &http.Client{Transport: httpTransport}
```

### Secrets from Multiple Sources

```go
import "github.com/vishalanandl177/m2mauth/secrets"

provider := secrets.NewChain(
    secrets.NewEnvProvider("M2M_"),              // Try env vars first
    secrets.NewFileProvider("/run/secrets"),      // Then K8s mounted secrets
)

auth, _ := oauth2.New(tokenURL, clientID,
    oauth2.WithSecretProvider(provider, "CLIENT_SECRET"),
)
```

## Framework Support

| Framework | Package | Install |
|-----------|---------|---------|
| `net/http` | `middleware` | Included (zero deps) |
| **Gin** | `contrib/ginauth` | `go get github.com/vishalanandl177/m2mauth/contrib/ginauth` |

The `contrib/ginauth` adapter is a separate Go module so the core library stays zero-dependency. It works with any `m2mauth.Validator` (JWT, API Key, mTLS) and stores claims in both `gin.Context` and the request context for maximum flexibility.

## Architecture

```
m2mauth (core interfaces, zero deps)
  ├── credentials/oauth2  -> Token acquisition + caching
  ├── credentials/mtls    -> mTLS transport + cert rotation
  ├── credentials/apikey  -> API key injection
  ├── validate/jwt        -> JWT + JWKS validation
  ├── validate/apikey     -> API key lookup
  ├── validate/mtls       -> Client cert verification
  ├── middleware           -> http.RoundTripper + net/http middleware
  ├── contrib/ginauth     -> Gin framework adapter (separate module)
  ├── secrets             -> Env, File, Static, Chain providers
  ├── retry               -> Exponential backoff with jitter
  └── authlog             -> Events, slog logging, metrics hooks
```

## Security

This library is hardened against common vulnerabilities:

- **HTTPS enforcement** -- Token and JWKS URLs must use HTTPS
- **Constant-time comparison** -- API key validation uses `crypto/subtle`
- **Response body limits** -- `io.LimitReader` prevents memory exhaustion from malicious servers
- **Path traversal protection** -- `FileProvider` validates paths stay within base directory
- **RSA exponent validation** -- JWKS parsing rejects overflowed/truncated exponents
- **Algorithm cross-validation** -- JWT header `alg` is checked against the JWKS key's declared algorithm
- **Certificate expiry checks** -- mTLS verifier always checks `NotBefore`/`NotAfter`
- **Error message sanitization** -- No secrets, response bodies, or internal config leaked in errors

## Design Principles

- **Zero external dependencies** -- stdlib only (framework adapters are separate modules)
- **Thread-safe** -- token cache uses `sync.RWMutex` with double-check locking
- **Context-first** -- every method accepts `context.Context`
- **Functional options** -- extensible configuration via `WithXxx` pattern
- **Observable** -- structured auth events via `log/slog`
- **Secure defaults** -- constant-time comparison, algorithm allowlists, expiry buffers

## Testing

```bash
# Run all tests with race detector
go test -race ./...

# Run Gin adapter tests
cd contrib/ginauth && go test -race ./...
```

**Test coverage: ~90%** (10 of 12 packages at 100%)

### Pre-commit Hook

A pre-commit hook validates build, formatting, static analysis, tests, coverage, vulnerabilities, secrets, and compliance controls before every commit:

```bash
# Install the hook
./scripts/install-hooks.sh

# Or run checks manually
./scripts/pre-commit-check.sh
```

## Examples

| Example | Directory | Description |
|---------|-----------|-------------|
| OAuth 2.0 Client | `_examples/client_credentials` | Token acquisition with caching |
| mTLS Client | `_examples/mtls_client` | Certificate rotation and expiry checks |
| JWT Server | `_examples/jwt_server` | net/http JWT middleware |
| API Key Middleware | `_examples/apikey_middleware` | API key validation |
| Combined | `_examples/combined` | Multiple auth methods together |
| Gin JWT Server | `_examples/gin_jwt_server` | Gin with JWT validation |
| Gin mTLS Server | `_examples/gin_mtls_server` | Gin with mTLS client cert verification |
| Gin API Key Server | `_examples/gin_apikey_server` | Gin with API key auth and scope checks |
| Gin OAuth2 Gateway | `_examples/gin_oauth2_client` | Gin with inbound JWT + outbound OAuth2 |

## Documentation

See [docs/PLAN.md](docs/PLAN.md) for the full architecture plan, including:
- Certificate rotation and revocation strategies
- Implementation phases
- Security considerations

## License

MIT
