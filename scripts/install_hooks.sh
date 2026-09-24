#!/usr/bin/env bash
# Installs a git pre-commit hook that blocks commits containing secrets.
# Run once per clone: bash scripts/install_hooks.sh
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
HOOK_PATH="$REPO_ROOT/.git/hooks/pre-commit"

if ! command -v gitleaks &> /dev/null; then
  echo "gitleaks not found locally. Install it first:"
  echo "  macOS:   brew install gitleaks"
  echo "  Linux:   curl -sSfL https://raw.githubusercontent.com/gitleaks/gitleaks/master/scripts/install.sh | sh"
  exit 1
fi

cat > "$HOOK_PATH" << 'EOF'
#!/usr/bin/env bash
# Auto-installed by scripts/install_hooks.sh — blocks commits with secrets.
set -euo pipefail
echo "🔒 Running gitleaks pre-commit secret scan..."
gitleaks protect --staged --config gitleaks/.gitleaks.toml --redact
if [ $? -ne 0 ]; then
  echo ""
  echo "❌ Commit blocked: potential secret detected."
  echo "   Review the finding above. If it's a false positive, add an allowlist"
  echo "   entry in gitleaks/.gitleaks.toml rather than bypassing the hook."
  exit 1
fi
echo "✅ No secrets detected."
EOF

chmod +x "$HOOK_PATH"
echo "Installed pre-commit secret-scan hook at $HOOK_PATH"
