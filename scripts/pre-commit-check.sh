#!/usr/bin/env bash
#
# Pre-commit validation script for m2mauth.
# Runs build, formatting, static analysis, tests, and vulnerability checks.
# Can be invoked directly: ./scripts/pre-commit-check.sh
# Installed as a git pre-commit hook via: ./scripts/install-hooks.sh

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

pass() { echo -e "${GREEN}PASS${NC} $1"; }
fail() { echo -e "${RED}FAIL${NC} $1"; exit 1; }
warn() { echo -e "${YELLOW}WARN${NC} $1"; }
step() { echo -e "\n${YELLOW}==>${NC} $1"; }

# ── 1. Build ──────────────────────────────────────────────────────────────────
step "Building all packages..."
if go build ./... 2>&1; then
    pass "Build"
else
    fail "Build failed"
fi

# ── 2. Formatting ─────────────────────────────────────────────────────────────
step "Checking gofmt formatting..."
UNFORMATTED=$(gofmt -l . 2>&1 | grep -v vendor || true)
if [ -z "$UNFORMATTED" ]; then
    pass "Formatting"
else
    echo -e "${RED}The following files are not formatted:${NC}"
    echo "$UNFORMATTED"
    fail "Run 'gofmt -w .' to fix formatting"
fi

# ── 3. Go Vet (static analysis) ──────────────────────────────────────────────
step "Running go vet..."
if go vet ./... 2>&1; then
    pass "Go vet"
else
    fail "go vet found issues"
fi

# ── 4. Tests with race detector ──────────────────────────────────────────────
step "Running tests with race detector..."
if go test -race -count=1 ./... 2>&1; then
    pass "Tests"
else
    fail "Tests failed"
fi

# ── 5. Test coverage threshold ───────────────────────────────────────────────
step "Checking test coverage..."
COVERAGE_OUT=$(mktemp)
go test -coverprofile="$COVERAGE_OUT" ./... > /dev/null 2>&1

# Calculate coverage for non-internal packages
TOTAL_COVERAGE=$(go tool cover -func="$COVERAGE_OUT" 2>/dev/null | grep "^total:" | awk '{print $3}' | tr -d '%')
rm -f "$COVERAGE_OUT"

THRESHOLD=80
if [ -n "$TOTAL_COVERAGE" ]; then
    COVERAGE_INT=${TOTAL_COVERAGE%.*}
    if [ "$COVERAGE_INT" -ge "$THRESHOLD" ]; then
        pass "Coverage: ${TOTAL_COVERAGE}% (threshold: ${THRESHOLD}%)"
    else
        fail "Coverage ${TOTAL_COVERAGE}% is below threshold ${THRESHOLD}%"
    fi
else
    warn "Could not determine coverage"
fi

# ── 6. Vulnerability scan ────────────────────────────────────────────────────
step "Running vulnerability scan..."
GOVULNCHECK=$(command -v govulncheck 2>/dev/null || echo "$(go env GOPATH)/bin/govulncheck")
if [ -x "$GOVULNCHECK" ]; then
    VULN_OUTPUT=$("$GOVULNCHECK" ./... 2>&1) && VULN_EXIT=0 || VULN_EXIT=$?
    if [ "$VULN_EXIT" -eq 0 ]; then
        pass "Vulnerability scan"
    elif echo "$VULN_OUTPUT" | grep -qi "forbidden\|network\|dial\|connection refused\|no such host"; then
        warn "Vulnerability scan skipped — network unavailable"
    else
        echo "$VULN_OUTPUT"
        fail "Vulnerabilities found — review and update dependencies"
    fi
else
    warn "govulncheck not installed — skipping (install: go install golang.org/x/vuln/cmd/govulncheck@latest)"
fi

# ── 7. Security: check for secrets in staged files ──────────────────────────
step "Checking for potential secrets in staged files..."
SECRETS_PATTERN='(PRIVATE.KEY|SECRET_KEY|password\s*=\s*".+"|\bAIza[0-9A-Za-z_-]{35}\b|-----BEGIN (RSA |EC )?PRIVATE KEY-----)'
if git diff --cached --name-only 2>/dev/null | head -50 | while read -r f; do
    [ -f "$f" ] && grep -lPi "$SECRETS_PATTERN" "$f" 2>/dev/null
done | grep -q .; then
    fail "Potential secrets detected in staged files — review before committing"
else
    pass "No secrets detected"
fi

# ── 8. Compliance: ensure HTTPS enforcement is intact ────────────────────────
step "Checking compliance controls..."
COMPLIANCE_OK=true

# Verify HTTPS enforcement exists in OAuth2
if ! grep -q 'token URL must use HTTPS' credentials/oauth2/clientcredentials.go 2>/dev/null; then
    echo -e "${RED}  Missing HTTPS enforcement in OAuth2 client${NC}"
    COMPLIANCE_OK=false
fi

# Verify HTTPS enforcement exists in JWT validator
if ! grep -q 'JWKS URL must use HTTPS' validate/jwt/validator.go 2>/dev/null; then
    echo -e "${RED}  Missing HTTPS enforcement in JWT validator${NC}"
    COMPLIANCE_OK=false
fi

# Verify path traversal protection in secrets
if ! grep -q 'path traversal' secrets/secrets.go 2>/dev/null; then
    echo -e "${RED}  Missing path traversal protection in FileProvider${NC}"
    COMPLIANCE_OK=false
fi

# Verify constant-time comparison in API key store
if ! grep -q 'ConstantTimeCompare' validate/apikey/validator.go 2>/dev/null; then
    echo -e "${RED}  Missing constant-time comparison in API key validator${NC}"
    COMPLIANCE_OK=false
fi

# Verify response body size limits
if ! grep -q 'LimitReader' credentials/oauth2/clientcredentials.go 2>/dev/null; then
    echo -e "${RED}  Missing response body size limit in OAuth2 client${NC}"
    COMPLIANCE_OK=false
fi

if ! grep -q 'LimitReader' validate/jwt/validator.go 2>/dev/null; then
    echo -e "${RED}  Missing response body size limit in JWT JWKS fetch${NC}"
    COMPLIANCE_OK=false
fi

if [ "$COMPLIANCE_OK" = true ]; then
    pass "Compliance controls"
else
    fail "Compliance controls missing — see above"
fi

# ── Done ─────────────────────────────────────────────────────────────────────
echo -e "\n${GREEN}All pre-commit checks passed.${NC}"
