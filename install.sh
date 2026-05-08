#!/usr/bin/env bash
# install.sh — install audit-skills into the user's Tauri app at ./audit/.
#
# Run this from the root of your Tauri app repo (e.g. ~/desktop/travus).
# Idempotent: re-running is safe and does nothing dangerous.

set -euo pipefail

REPO_URL="https://github.com/user2343242kdisj/audit-skills-mobile-tauri-supabase.git"
REPO_URL_ALT="https://github.com/user2343242kdisj/audit-skills-mobile-tauri-supabase"
AUDIT_DIR="./audit"
GITIGNORE=".gitignore"
ZSHRC="$HOME/.zshrc"
LOCAL_BIN="$HOME/.local/bin"
INSTALL_MARKER="# Added by audit-skills install.sh"

log() { echo "[install] $*"; }
err() { echo "[install] error: $*" >&2; }

# --- Step 1: verify cwd looks like a Tauri app repo root --------------------
log "verifying current directory looks like a Tauri app repo root..."
if [ ! -d "src-tauri" ] && [ ! -d "supabase" ] && [ ! -f "package.json" ]; then
  err "install.sh must be run from your Tauri app repo root (e.g. ~/desktop/travus). cwd=$(pwd)"
  exit 1
fi
log "cwd ok: $(pwd)"

# --- Step 2 & 3: create ./audit/ and clone (or pull) the audit-skills repo --
log "preparing $AUDIT_DIR ..."
if [ -d "$AUDIT_DIR/.git" ]; then
  EXISTING_ORIGIN="$(git -C "$AUDIT_DIR" remote get-url origin 2>/dev/null || true)"
  if [ "$EXISTING_ORIGIN" = "$REPO_URL" ] || [ "$EXISTING_ORIGIN" = "$REPO_URL_ALT" ]; then
    log "$AUDIT_DIR is already the audit-skills repo. Pulling latest..."
    git -C "$AUDIT_DIR" pull --ff-only
  else
    err "$AUDIT_DIR exists and is a git repo, but its origin is '$EXISTING_ORIGIN' (expected '$REPO_URL'). Refusing to overwrite."
    exit 1
  fi
elif [ -e "$AUDIT_DIR" ]; then
  err "$AUDIT_DIR exists but is not a git repo. Refusing to overwrite. Move or remove it and re-run."
  exit 1
else
  log "cloning $REPO_URL into $AUDIT_DIR ..."
  git clone "$REPO_URL" "$AUDIT_DIR"
fi

# --- Step 4 & 5: idempotently add audit/ and audit-reports/ to .gitignore ---
log "ensuring $GITIGNORE ignores audit/ and audit-reports/ ..."
touch "$GITIGNORE"
add_to_gitignore() {
  local entry="$1"
  if grep -qxF "$entry" "$GITIGNORE"; then
    log "$GITIGNORE already contains '$entry'"
  else
    printf '%s\n' "$entry" >> "$GITIGNORE"
    log "appended '$entry' to $GITIGNORE"
  fi
}
add_to_gitignore "audit/"
add_to_gitignore "audit-reports/"

# --- Step 6: install the exec-agent wrapper into ~/.local/bin ---------------
log "installing exec-agent wrapper into $LOCAL_BIN ..."
mkdir -p "$LOCAL_BIN"
EXEC_SRC="$AUDIT_DIR/templates/agent-prompts/numbered/exec"
if [ ! -f "$EXEC_SRC" ]; then
  err "expected wrapper not found at $EXEC_SRC"
  exit 1
fi
cp "$EXEC_SRC" "$LOCAL_BIN/exec-agent"
chmod +x "$LOCAL_BIN/exec-agent"
log "installed $LOCAL_BIN/exec-agent"

# --- Step 7: idempotently add ~/.local/bin to PATH in ~/.zshrc --------------
log "ensuring $LOCAL_BIN is on PATH via $ZSHRC ..."
touch "$ZSHRC"
if grep -qF "$INSTALL_MARKER" "$ZSHRC"; then
  log "$ZSHRC already has the audit-skills PATH entry"
else
  {
    printf '\n%s\n' "$INSTALL_MARKER"
    printf '%s\n' 'export PATH="$HOME/.local/bin:$PATH"'
  } >> "$ZSHRC"
  log "appended PATH entry to $ZSHRC"
fi

# --- Step 8: verify 1Password CLI ('op') is on PATH -------------------------
log "checking for 1Password CLI ('op') ..."
if command -v op >/dev/null 2>&1; then
  log "op found: $(command -v op)"
else
  err "warning: '1Password CLI' (op) not found on PATH."
  err "install with: brew install --cask 1password-cli"
  err "continuing anyway, but agents that need secrets will fail until 'op' is available."
fi

# --- Step 9: final summary --------------------------------------------------
cat <<'EOF'
===================================================================
audit-skills installed at ./audit/
===================================================================
Next steps:
  1. (Open new terminal or `source ~/.zshrc`) so $HOME/.local/bin is on PATH
  2. Verify 1Password is unlocked: `op vault list`
  3. Confirm 1Password items match expected paths (see ./audit/templates/agent-prompts/numbered/README.md)
  4. Run the setup agent in this directory:
       claude --dangerously-skip-permissions
     Then paste the contents of ./audit/templates/agent-prompts/numbered/agent-0.md
     OR equivalently: exec-agent ./audit/templates/agent-prompts/numbered/agent-0.md
  5. After agent-0 finishes, run the others (1, 2-15 in parallel, then 16)
===================================================================
EOF
