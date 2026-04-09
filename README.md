# m2mauth

A batteries-included Go library for **Machine-to-Machine (M2M) authentication** — covering OAuth 2.0 Client Credentials, mTLS, API Keys, and JWT validation.

Zero external dependencies. Works with `net/http` out of the box.

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
| **Secret management** | `secrets` | Infrastructure |
| **Retry with backoff** | `retry` | Infrastructure |
| **Observability** | `authlog` | Infrastructure |

## Install

```bash
go get github.com/vishalanandl177/m2mauth
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

### Inbound: JWT Validation

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

### mTLS with Certificate Rotation

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

## Architecture

```
m2mauth (core interfaces, zero deps)
  ├── credentials/oauth2  → Token acquisition + caching
  ├── credentials/mtls    → mTLS transport + cert rotation
  ├── credentials/apikey  → API key injection
  ├── validate/jwt        → JWT + JWKS validation
  ├─��� validate/apikey     → API key lookup
  ├── validate/mtls       → Client cert verification
  ├── middleware           → http.RoundTripper + net/http middleware
  ├── secrets             → Env, File, Static, Chain providers
  ├── retry               → Exponential backoff with jitter
  └── authlog             → Events, slog logging, metrics hooks
```

## Design Principles

- **Zero external dependencies** — stdlib only
- **Thread-safe** — token cache uses `sync.RWMutex` with double-check locking
- **Context-first** — every method accepts `context.Context`
- **Functional options** — extensible configuration via `WithXxx` pattern
- **Observable** — structured auth events via `log/slog`
- **Secure defaults** — constant-time comparison, algorithm allowlists, expiry buffers

## Testing

```bash
go test -race ./...
```

## Documentation

See [docs/PLAN.md](docs/PLAN.md) for the full architecture plan, including:
- Certificate rotation and revocation strategies
- Implementation phases
- Security considerations

## License

MIT
