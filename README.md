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

## How It Works

### OAuth 2.0 Client Credentials Flow

Service A authenticates to Service B using a token from the authorization server. Tokens are cached and auto-refreshed.

```
┌─────────────┐                    ┌─────────────┐                    ┌─────────────┐
│  Service A  │                    │  Auth Server │                    │  Service B  │
│  (client)   │                    │  (OAuth 2.0) │                    │  (resource) │
└──────┬──────┘                    └──────┬───────┘                    └──────┬──────┘
       │                                  │                                   │
       │  1. POST /oauth/token            │                                   │
       │  (client_id + client_secret)     │                                   │
       │─────────────────────────────────>│                                   │
       │                                  │                                   │
       │  2. { access_token, expires_in } │                                   │
       │<─────────────────────────────────│                                   │
       │                                  │                                   │
       │         ┌──────────────────────┐ │                                   │
       │         │ Token Cache          │ │                                   │
       │         │ - Thread-safe        │ │                                   │
       │         │ - Auto-refresh       │ │                                   │
       │         │ - Expiry buffer (30s)│ │                                   │
       │         └──────────────────────┘ │                                   │
       │                                                                      │
       │  3. GET /api/data                                                    │
       │  Authorization: Bearer <token>                                       │
       │─────────────────────────────────────────────────────────────────────>│
       │                                                                      │
       │  4. 200 OK { data }                                                  │
       │<─────────────────────────────────────────────────────────────────────│
       │                                                                      │

  m2mauth packages used:
  ├── credentials/oauth2  ── Handles steps 1-2 (token fetch + cache)
  ├── middleware           ── RoundTripper injects Bearer token (step 3)
  └── retry               ── Retries token fetch on transient failures
```

### JWT Validation Flow

The server validates incoming JWTs by fetching public keys from the JWKS endpoint. Keys are cached and periodically refreshed.

```
┌─────────────┐                    ┌─────────────┐                    ┌─────────────┐
│  Caller     │                    │  Your Server │                    │  Auth Server │
│  (client)   │                    │  (validator) │                    │  (JWKS)      │
└──────┬──────┘                    └──────┬───────┘                    └──────┬───────┘
       │                                  │                                   │
       │                                  │  1. GET /.well-known/jwks.json    │
       │                                  │  (fetched once, cached 1h)        │
       │                                  │──────────────────────────────────>│
       │                                  │                                   │
       │                                  │  2. { keys: [{ kid, n, e }] }     │
       │                                  │<──────────────────────────────────│
       │                                  │                                   │
       │                                  │  ┌──────────────────────────────┐ │
       │                                  │  │ JWKS Cache                   │ │
       │                                  │  │ - Auto-refresh (1h default)  │ │
       │                                  │  │ - Stale key fallback         │ │
       │                                  │  │ - Refresh debounce (5s)      │ │
       │                                  │  └──────────────────────────────┘ │
       │                                  │                                   │
       │  3. GET /api/data                │                                   │
       │  Authorization: Bearer <JWT>     │                                   │
       │─────────────────────────────────>│                                   │
       │                                  │                                   │
       │                           4. Validate JWT:                           │
       │                           ├── Decode header + payload                │
       │                           ├── Check algorithm allowlist              │
       │                           ├── Verify signature (RSA/ECDSA)           │
       │                           ├── Check exp, nbf, clock skew             │
       │                           ├── Validate issuer + audience             │
       │                           ├── Enforce required scopes                │
       │                           └── Extract claims -> context              │
       │                                  │                                   │
       │  5. 200 OK { data }              │                                   │
       │<─────────────────────────────────│                                   │
       │                                  │                                   │

  m2mauth packages used:
  ├── validate/jwt  ── JWKS fetch, signature verify, claims validation
  ├── middleware     ── RequireAuth wraps net/http handlers
  └── contrib/ginauth ── RequireAuth wraps Gin handlers
```

### Mutual TLS (mTLS) Flow

Both client and server present certificates. The server verifies the client's certificate against a trusted CA and extracts identity from the cert fields.

```
┌─────────────┐                                              ┌─────────────┐
│  Service A  │                                              │  Service B  │
│  (client)   │                                              │  (server)   │
└──────┬──────┘                                              └──────┬──────┘
       │                                                            │
       │  1. TLS Handshake (ClientHello)                            │
       │───────────────────────────────────────────────────────────>│
       │                                                            │
       │  2. ServerHello + Server Certificate                       │
       │     + CertificateRequest (asks for client cert)            │
       │<───────────────────────────────────────────────────────────│
       │                                                            │
       │  3. Client Certificate + ClientKeyExchange                 │
       │  ┌─────────────────────────────────┐                       │
       │  │ credentials/mtls Transport      │                       │
       │  │ - Loads cert from file or PEM   │                       │
       │  │ - Hot-reload via rotation loop  │                       │
       │  │ - Polls every N minutes         │                       │
       │  │ - Validates cert not expired    │                       │
       │  └─────────────────────────────────┘                       │
       │───────────────────────────────────────────────────────────>│
       │                                                            │
       │                                      4. Server validates:  │
       │                                      ┌────────────────────┐│
       │                                      │ validate/mtls      ││
       │                                      │ - Verify against CA││
       │                                      │ - Check NotBefore/ ││
       │                                      │   NotAfter (expiry)││
       │                                      │ - Enforce CN match ││
       │                                      │ - Enforce OU match ││
       │                                      │ - Extract claims:  ││
       │                                      │   subject, issuer, ││
       │                                      │   serial, OU, SANs ││
       │                                      └────────────────────┘│
       │                                                            │
       │  5. TLS Established (mutual authentication)                │
       │<──────────────────────────────────────────────────────────>│
       │                                                            │
       │  6. GET /api/data (over mTLS connection)                   │
       │───────────────────────────────────────────────────────────>│
       │                                                            │
       │  7. 200 OK { data }                                        │
       │<───────────────────────────────────────────────────────────│
       │                                                            │

  m2mauth packages used:
  Client side:                        Server side:
  ├── credentials/mtls  ── Cert       ├── validate/mtls   ── Cert verification
  │   loading + rotation              ├── middleware        ── RequireAuth
  └── authlog ── Rotation events      └── contrib/ginauth  ── Gin middleware
```

### mTLS Certificate Rotation

The client-side transport automatically reloads certificates from disk without downtime.

```
                        ┌─────────────────────────────────────┐
                        │         credentials/mtls             │
                        │         Transport                    │
  ┌──────────┐          │                                     │
  │ cert.pem │─── Load ─┤  ┌───────────┐   ┌──────────────┐  │
  │ key.pem  │          │  │ Current   │   │  Rotation    │  │
  └──────────┘          │  │ TLS Cert  │   │  Loop        │  │
       │                │  │ (RWMutex) │   │              │  │
       │                │  └───────────┘   │  every 5min: │  │
  Cert issuer           │       ^          │  1. Load new │  │
  rotates files         │       │          │  2. Validate │  │
  on disk               │       └──────────│  3. Swap     │  │
       │                │                  │  4. Log event│  │
       v                │                  └──────────────┘  │
  ┌──────────┐          │                                     │
  │ cert.pem │─── Reload┤  GetClientCertificate() callback    │
  │ key.pem  │  (new)   │  returns current cert for every     │
  └──────────┘          │  TLS handshake (no restart needed)  │
                        └─────────────────────────────────────┘
```

### API Key Flow

Simple header-based authentication. The server looks up the key and returns pre-configured claims.

```
┌─────────────┐                    ┌─────────────────────────────────────────┐
│  Caller     │                    │  Your Server                            │
│  (client)   │                    │                                         │
└──────┬──────┘                    │  ┌──────────────┐   ┌────────────────┐  │
       │                           │  │ validate/    │   │ KeyStore       │  │
       │  1. GET /api/data         │  │ apikey       │   │ (MapStore or   │  │
       │  X-API-Key: sk_live_xxx   │  │ Validator    │   │  custom impl)  │  │
       │──────────────────────────>│  └──────┬───────┘   └───────┬────────┘  │
       │                           │         │                   │           │
       │                           │  2. Extract key from header │           │
       │                           │         │                   │           │
       │                           │  3. Lookup(key) ───────────>│           │
       │                           │         │  (constant-time   │           │
       │                           │         │   comparison)     │           │
       │                           │         │                   │           │
       │                           │  4. Claims { subject,  <────│           │
       │                           │           scopes }          │           │
       │                           │         │                   │           │
       │                           │  5. Store claims in context │           │
       │                           │         │                                │
       │  6. 200 OK { data }       │         v                                │
       │<──────────────────────────│  Handler: claims.HasScope("read:data")  │
       │                           │                                         │
       └                           └─────────────────────────────────────────┘

  Outbound (client side):            Inbound (server side):
  ├── credentials/apikey             ├── validate/apikey ── Constant-time lookup
  │   - Header: X-API-Key           ├── middleware       ── RequireAuth
  │   - Bearer: Authorization       └── contrib/ginauth  ── Gin middleware
  │   - Query: ?api_key=xxx
  └── secrets ── Dynamic key from env/file/vault
```

### Combined: Inbound JWT + Outbound OAuth2 (Gateway Pattern)

A common microservices pattern where a gateway validates incoming requests and authenticates outbound calls to downstream services.

```
┌──────────┐          ┌───────────────────────────────┐          ┌────────────┐
│  Client  │          │  API Gateway (Gin)            │          │ Downstream │
│          │          │                               │          │ Service    │
└────┬─────┘          │  ┌─────────┐  ┌────────────┐ │          └─────┬──────┘
     │                │  │validate/│  │credentials/│ │                │
     │ 1. Request     │  │jwt      │  │oauth2      │ │                │
     │ + Bearer JWT   │  │         │  │            │ │                │
     │───────────────>│  └────┬────┘  └─────┬──────┘ │                │
     │                │       │             │        │                │
     │                │  2. Validate        │        │                │
     │                │  inbound JWT        │        │                │
     │                │       │             │        │                │
     │                │  3. Extract         │        │                │
     │                │  caller claims      │        │                │
     │                │       │             │        │                │
     │                │       │  4. Get     │        │                │
     │                │       │  outbound   │        │                │
     │                │       │  token      │        │                │
     │                │       │  (cached)   │        │                │
     │                │       │             │        │                │
     │                │       └─────────────┘        │                │
     │                │              │               │                │
     │                │  5. Forward request           │                │
     │                │  + Bearer <outbound token>    │                │
     │                │──────────────────────────────────────────────>│
     │                │                               │                │
     │                │  6. Response                   │                │
     │                │<──────────────────────────────────────────────│
     │  7. Response   │                               │                │
     │<───────────────│                               │                │
     │                │                               │                │
     └                └───────────────────────────────┘                │

  See: _examples/gin_oauth2_client
```

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
