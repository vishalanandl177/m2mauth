#!/usr/bin/env bash
#
# Install git hooks for the m2mauth project.
# Usage: ./scripts/install-hooks.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HOOKS_DIR="$REPO_ROOT/.git/hooks"

echo "Installing pre-commit hook..."
cat > "$HOOKS_DIR/pre-commit" << 'HOOK'
#!/usr/bin/env bash
# m2mauth pre-commit hook — runs build, tests, vulnerability, and compliance checks.
# To skip (emergency only): git commit --no-verify

exec "$(git rev-parse --show-toplevel)/scripts/pre-commit-check.sh"
HOOK

chmod +x "$HOOKS_DIR/pre-commit"
echo "Pre-commit hook installed at $HOOKS_DIR/pre-commit"

# Ensure the check script is executable
chmod +x "$REPO_ROOT/scripts/pre-commit-check.sh"

echo "Done. Run 'git commit' to trigger checks, or './scripts/pre-commit-check.sh' to run manually."
