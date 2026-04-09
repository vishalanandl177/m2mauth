# m2mauth — Go M2M Authentication Library

## Implementation Plan & Architecture Document

**Module:** `github.com/vishalanandl177/m2mauth`
**Status:** v0.1.0 — Initial Implementation
**Go Version:** 1.22+
**License:** MIT

---

## 1. Overview

`m2mauth` is a batteries-included Go library for Machine-to-Machine (M2M) authentication.
It provides both **client-side** (outbound request authentication) and **server-side**
(inbound request validation) capabilities, covering the four primary M2M auth methods:

| Method | Client (outbound) | Server (inbound) |
|--------|-------------------|-------------------|
| OAuth 2.0 Client Credentials | `credentials/oauth2` | `validate/jwt` |
| Mutual TLS (mTLS) | `credentials/mtls` | `validate/mtls` |
| API Keys | `credentials/apikey` | `validate/apikey` |
| JWT Validation | — | `validate/jwt` |

### Name Uniqueness

The name **m2mauth** was chosen after verifying availability across:
- **pkg.go.dev**: 0 results
- **GitHub**: 0 repositories
- **npm/PyPI**: No conflicts

Rejected alternatives: `gogate` (7 existing modules, 32 repos), `goguard` (3 modules),
`authgate` (5 modules, active org).

---

## 2. Package Structure

```
m2mauth/
├── m2mauth.go                        # Core interfaces: Authenticator, Validator, TokenSource, Claims
├── errors.go                          # Sentinel errors + AuthError type
├── go.mod
│
├── credentials/                       # CLIENT-SIDE: Outbound auth
│   ├── oauth2/                        # OAuth 2.0 Client Credentials flow
│   │   ├── clientcredentials.go       # Token acquisition + Authenticator impl
│   │   ├── token_cache.go            # Thread-safe cache (RWMutex + double-check)
│   │   └── clientcredentials_test.go
│   ├── mtls/                          # Mutual TLS with cert rotation
│   │   ├── mtls.go                   # TLS config, transport, rotation loop
│   │   └── mtls_test.go
│   └── apikey/                        # API key injection
│       ├── apikey.go
│       └── apikey_test.go
│
├── validate/                          # SERVER-SIDE: Inbound validation
│   ├── jwt/                           # JWT validation + JWKS
│   │   ├── validator.go              # Full validation pipeline
│   │   ├── curves.go                 # Elliptic curve helpers
│   │   └── validator_test.go
│   ├── apikey/                        # API key lookup + validation
│   │   ├── validator.go
│   │   └── validator_test.go
│   └── mtls/                          # Client certificate verification
│       └── verifier.go
│
├── middleware/                         # HTTP middleware
│   ├── roundtripper.go               # http.RoundTripper (outbound)
│   ├── server.go                     # net/http middleware (inbound)
│   └── middleware_test.go
│
├── secrets/                           # Secret management
│   ├── secrets.go                    # Env, File, Static, Chain providers
│   └── secrets_test.go
│
├── retry/                             # Exponential backoff with jitter
│   ├── retry.go
│   └── retry_test.go
│
├── authlog/                           # Observability
│   └── authlog.go                    # Events, slog handler, metrics interface
│
├── internal/
│   ├── clock/clock.go                # Mockable clock for testing
│   └── testutil/testutil.go          # Cert generation, mock OAuth server
│
├── _examples/                         # Runnable examples
│   ├── client_credentials/
│   ├── jwt_server/
│   ├── mtls_client/
│   ├── apikey_middleware/
│   └── combined/
│
└── docs/
    └── PLAN.md                       # This document
```

---

## 3. Core Interfaces

```go
// Authenticator attaches credentials to outbound HTTP requests.
type Authenticator interface {
    Authenticate(ctx context.Context, req *http.Request) error
}

// Validator validates credentials on inbound HTTP requests.
type Validator interface {
    Validate(ctx context.Context, req *http.Request) (*Claims, error)
}

// TokenSource provides access tokens with caching and auto-refresh.
type TokenSource interface {
    Token(ctx context.Context) (*Token, error)
}

// SecretProvider abstracts secret retrieval from various backends.
type SecretProvider interface {
    GetSecret(ctx context.Context, key string) (string, error)
}
```

---

## 4. Certificate Rotation & Revocation Plan

### 4.1 Certificate Rotation (mTLS)

Certificate rotation is critical for zero-downtime operations. The library supports
two rotation strategies:

#### Strategy A: Polling-Based Rotation (Implemented)

```
┌─────────────────┐     ┌────────────────┐     ┌──────────────┐
│  Cert Manager    │     │  File System   │     │  m2mauth     │
│  (cert-manager,  │────▶│  /etc/certs/   │────▶│  mtls pkg    │
│   Vault, ACME)   │     │  client.crt    │     │              │
└─────────────────┘     │  client.key    │     │  Polls every  │
                         └────────────────┘     │  N minutes    │
                                                 └──────────────┘
```

**How it works:**
1. Configure `WithRotationInterval(5 * time.Minute)` — a background goroutine
   wakes up every 5 minutes.
2. It re-reads the cert/key files from disk.
3. The new certificate is atomically swapped via `sync.RWMutex`.
4. Active TLS connections continue using the old cert; new connections use the new one.
5. The `GetClientCertificate` callback in `tls.Config` ensures the latest cert is
   always served without restarting the HTTP client.

**Observability events emitted:**
- `cert_rotated` — successful rotation with file path
- `cert_load_error` — rotation failed (old cert continues to be used)
- `cert_expiring` — cert expires within 24 hours (warning)

**Configuration:**
```go
transport, _ := mtls.NewTransport(
    mtls.WithCertFile("/etc/certs/client.crt", "/etc/certs/client.key"),
    mtls.WithRotationInterval(5 * time.Minute),
    mtls.WithEventHandler(authlog.NewSlogHandler(slog.Default())),
)
defer transport.Stop()
```

#### Strategy B: Event-Driven Rotation (Future Enhancement)

For environments using `fsnotify` (file system events):
- Watch cert files for `WRITE` events
- Rotate immediately on change instead of polling
- Lower latency but requires `fsnotify` dependency

#### Rotation Best Practices

| Concern | Recommendation |
|---------|---------------|
| **Polling interval** | 5-15 minutes for production; cert-manager default renewal is 2/3 of lifetime |
| **Overlap window** | Ensure new cert is issued before old one expires (cert-manager handles this) |
| **Graceful draining** | Existing connections keep old cert; only new handshakes use new cert |
| **Health checks** | Use `CertInfo().IsExpiring(window)` in health endpoints |
| **Alerting** | Subscribe to `cert_expiring` events via EventHandler |

### 4.2 Certificate Revocation

Certificate revocation prevents compromised certificates from being used.
The library supports checking revocation on the **server side** (validate/mtls).

#### Revocation Methods

**A. CRL (Certificate Revocation List)**

```
┌───────────┐     ┌─────────────┐     ┌──────────────────┐
│ Client     │────▶│ Server      │────▶│ CRL Distribution │
│ presents   │     │ checks cert │     │ Point (CDP)      │
│ client cert│     │ against CRL │     │ (cached locally) │
└───────────┘     └─────────────┘     └──────────────────┘
```

- The CA publishes a CRL (list of revoked serial numbers)
- Server periodically fetches and caches the CRL
- On each mTLS handshake, check if the client cert's serial is in the CRL
- **Pros:** Simple, works offline after initial fetch
- **Cons:** CRL can grow large, latency in revocation propagation

**B. OCSP (Online Certificate Status Protocol)**

```
┌───────────┐     ┌─────────────┐     ┌──────────────┐
│ Client     │────▶│ Server      │────▶│ OCSP         │
│ presents   │     │ checks cert │     │ Responder    │
│ client cert│     │ status      │     │ (real-time)  │
└───────────┘     └─────────────┘     └──────────────┘
```

- Server queries the CA's OCSP responder for each cert
- Real-time status: good, revoked, or unknown
- **Pros:** Real-time, no large CRL downloads
- **Cons:** Requires network call, OCSP responder must be available

**C. OCSP Stapling (Preferred)**

- Client fetches its own OCSP response and "staples" it to the TLS handshake
- Server validates the stapled response (signed by CA)
- **Pros:** No server-side OCSP call, fast validation
- **Cons:** Client must support stapling

#### Implementation Plan for Revocation

**Phase 1 (Current):** Go's `crypto/x509` handles basic revocation via
`VerifyOptions`. The `tls.Config.VerifyPeerCertificate` hook can be extended.

**Phase 2 (Future):**
```go
// Planned API
verifier := mtls.New(
    mtls.WithTrustedCAs(caPool),
    mtls.WithCRLFile("/etc/certs/ca.crl"),           // CRL-based
    mtls.WithCRLURL("https://ca.example.com/crl"),   // Auto-fetch CRL
    mtls.WithCRLRefreshInterval(1 * time.Hour),
    mtls.WithOCSPCheck(true),                         // OCSP real-time check
    mtls.WithOCSPCacheTTL(5 * time.Minute),
)
```

### 4.3 Token Revocation (OAuth 2.0)

For OAuth 2.0 tokens, the library supports:

**Client-side (immediate):**
```go
client.RevokeToken()  // Clears cached token, forces re-fetch on next call
```

**Server-side (JWT validation):**
- JWTs are stateless — they can't be truly "revoked" without a blocklist
- Short-lived tokens (5-15 min) + refresh mitigates this
- For immediate revocation, implement a blocklist:

```go
// Planned API for token blocklist
validator := jwt.New(
    jwt.WithJWKSURL("https://auth.example.com/.well-known/jwks.json"),
    jwt.WithTokenBlocklist(redisBlocklist),  // Check JTI against blocklist
)
```

**Token Lifecycle:**
```
┌──────────┐   Token    ┌──────────┐   Cached    ┌──────────┐
│  Auth     │──────────▶│  Client  │────────────▶│  Cache   │
│  Server   │           │  (m2m)   │             │  (30s    │
│           │◀──────────│          │             │  buffer) │
│           │  Refresh   │          │◀────────────│          │
└──────────┘   (auto)   └──────────┘   Expired   └──────────┘
                              │
                              │ RevokeToken()
                              ▼
                        ┌──────────┐
                        │  Cache   │
                        │  Cleared │
                        │          │
                        └──────────┘
```

---

## 5. Implementation Phases

### Phase 1: Core Foundation (Complete)
- [x] Go module initialization
- [x] Core interfaces (Authenticator, Validator, TokenSource, Claims)
- [x] Error types and sentinel errors
- [x] Retry package with exponential backoff + jitter
- [x] Internal clock and test utilities

### Phase 2: Client-Side Auth (Complete)
- [x] OAuth 2.0 Client Credentials with thread-safe token caching
- [x] API key authenticator (header, bearer, query param)
- [x] mTLS transport with certificate rotation
- [x] Client middleware (http.RoundTripper)

### Phase 3: Server-Side Validation (Complete)
- [x] JWT validator with JWKS caching and auto-refresh
- [x] API key validator with constant-time comparison
- [x] mTLS certificate verifier
- [x] Server middleware (net/http)

### Phase 4: Infrastructure (Complete)
- [x] Secret providers (env, file, static, chain)
- [x] Observability (events, slog handler, metrics interface)
- [x] Examples for all auth methods

### Phase 5: Future Enhancements
- [ ] fsnotify-based cert rotation
- [ ] CRL/OCSP revocation checking
- [ ] Token blocklist for JWT revocation
- [ ] HashiCorp Vault secret provider
- [ ] AWS Secrets Manager provider
- [ ] Gin/Echo/Chi framework adapters
- [ ] OpenTelemetry metrics integration
- [ ] Fuzz tests for JWT parsing
- [ ] Benchmarks

---

## 6. Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| **Functional options** (`WithXxx`) | Extensible config without breaking callers |
| **`sync.RWMutex` + double-check** for token cache | Fast read path, single refresh under contention |
| **`context.Context` everywhere** | Cancellation, deadlines, claim propagation |
| **`log/slog` for logging** | Standard library since Go 1.21, no custom interface |
| **Zero external dependencies** | Core packages use stdlib only; integrations are optional |
| **Separate packages per method** | `go get .../credentials/oauth2` doesn't pull in unrelated deps |
| **Constant-time comparison** for API keys | Prevents timing attacks |
| **`GetClientCertificate` callback** for mTLS | Enables hot-reload without restart |

---

## 7. Testing Strategy

| Level | Approach |
|-------|----------|
| **Unit tests** | Mock HTTP servers, mock providers, testable clock |
| **Race detection** | All tests run with `-race` |
| **Concurrency** | 50-goroutine stress tests on token cache |
| **Integration** | Build-tagged for real Vault, Keycloak, self-signed certs |
| **Fuzz** | JWT parsing, cert loading (planned) |
| **Benchmarks** | Token cache lookup, JWT validation (planned) |

---

## 8. Dependency Graph

```
m2mauth (core interfaces, zero deps)
  ├── retry              → stdlib only
  ├── authlog            → stdlib (log/slog)
  ├── secrets            → stdlib (os, filepath)
  ├── credentials/oauth2 → retry, authlog, secrets
  ├── credentials/apikey → authlog, secrets
  ├── credentials/mtls   → authlog
  ├── validate/jwt       → authlog
  ├── validate/apikey    → authlog
  ├── validate/mtls      → authlog
  ├── middleware          → core interfaces only
  └── internal/          → stdlib (crypto, testing)
```

**External dependencies: NONE** — the entire library uses only the Go standard library.

---

## 9. Security Considerations

- **No secrets in logs:** The authlog package never logs secret values, tokens, or keys
- **Constant-time comparison:** API key validation uses `crypto/subtle.ConstantTimeCompare`
- **Thread safety:** Token cache uses `sync.RWMutex` with double-check locking
- **Expiry buffer:** Tokens refresh 30s before actual expiry to prevent edge-case failures
- **Algorithm allowlist:** JWT validator only accepts explicitly configured algorithms
- **Request cloning:** RoundTripper clones requests before mutation to prevent races

---

## 10. Usage Quick Start

### Outbound: OAuth 2.0 Client Credentials
```go
auth, _ := oauth2.New("https://auth.example.com/token", "my-service",
    oauth2.WithClientSecret("secret"),
    oauth2.WithAudience("https://api.example.com"),
)
client := &http.Client{
    Transport: middleware.NewRoundTripper(http.DefaultTransport, auth),
}
resp, _ := client.Get("https://api.example.com/users")
```

### Inbound: JWT Validation
```go
v, _ := jwt.New(
    jwt.WithJWKSURL("https://auth.example.com/.well-known/jwks.json"),
    jwt.WithIssuer("https://auth.example.com/"),
    jwt.WithRequiredScopes("read:users"),
)
mux.Handle("/api/users", middleware.RequireAuth(v)(usersHandler))
```

### Outbound: mTLS with Cert Rotation
```go
t, _ := mtls.NewTransport(
    mtls.WithCertFile("/etc/certs/client.crt", "/etc/certs/client.key"),
    mtls.WithCACertFile("/etc/certs/ca.crt"),
    mtls.WithRotationInterval(5 * time.Minute),
)
httpTransport, _ := t.HTTPTransport()
client := &http.Client{Transport: httpTransport}
```

### Secrets from Multiple Sources
```go
provider := secrets.NewChain(
    secrets.NewEnvProvider("M2M_"),
    secrets.NewFileProvider("/run/secrets"),
)
auth, _ := oauth2.New(tokenURL, clientID,
    oauth2.WithSecretProvider(provider, "CLIENT_SECRET"),
)
```
