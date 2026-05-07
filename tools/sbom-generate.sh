#!/usr/bin/env bash
#
# Generate CycloneDX SBOMs for a mobile + Tauri-desktop + Supabase stack.
# Outputs:
#   sbom-npm.cdx.json     — JS/TS dependencies (root package.json)
#   sbom-cargo.cdx.json   — Rust dependencies (src-tauri/Cargo.toml)
#   sbom-android.cdx.json — Android Gradle dependencies (if android/ exists)
#   sbom-ios.cdx.json     — iOS CocoaPods/SwiftPM (if ios/ exists)
#   sbom-aggregate.cdx.json — combined via cyclonedx-cli merge
#
# Then runs Grype against each for CVE scanning, failing on HIGH+ severity.
#
# Usage:
#   ./tools/sbom-generate.sh [--no-scan]
#
# Prereqs:
#   - Node.js 20+
#   - Rust + cargo
#   - jq (for sanity-check)
#   - Install commands run lazily on first use; idempotent.

set -euo pipefail

OUT_DIR="${SBOM_OUT:-./sbom}"
SCAN="1"
[[ "${1:-}" == "--no-scan" ]] && SCAN="0"

mkdir -p "$OUT_DIR"

log() { printf "\033[0;36m[sbom]\033[0m %s\n" "$*"; }
warn() { printf "\033[0;33m[sbom]\033[0m %s\n" "$*" >&2; }
err() { printf "\033[0;31m[sbom]\033[0m %s\n" "$*" >&2; }

ensure_cmd() {
  command -v "$1" >/dev/null 2>&1 || { err "missing required command: $1"; exit 2; }
}

ensure_cmd node
ensure_cmd cargo
ensure_cmd jq

# ---------------------------------------------------------------------------
# 1. npm / pnpm / yarn — JS+TS dependencies
# ---------------------------------------------------------------------------
if [[ -f package.json ]]; then
  log "generating npm SBOM via @cyclonedx/cdxgen"
  if ! command -v cdxgen >/dev/null 2>&1; then
    npm install -g @cyclonedx/cdxgen >/dev/null 2>&1
  fi
  cdxgen -t javascript -o "$OUT_DIR/sbom-npm.cdx.json" --quiet
  log "  → $OUT_DIR/sbom-npm.cdx.json ($(jq '.components | length' "$OUT_DIR/sbom-npm.cdx.json") components)"
else
  warn "no package.json at repo root — skipping npm SBOM"
fi

# ---------------------------------------------------------------------------
# 2. cargo — Rust dependencies (Tauri core)
# ---------------------------------------------------------------------------
if [[ -f src-tauri/Cargo.toml ]]; then
  log "generating cargo SBOM via cargo-cyclonedx"
  if ! cargo install --list 2>/dev/null | grep -q '^cargo-cyclonedx'; then
    cargo install --locked cargo-cyclonedx >/dev/null 2>&1
  fi
  ( cd src-tauri && cargo cyclonedx --format json --quiet )
  # cargo-cyclonedx writes to src-tauri/<crate>.cdx.json
  CARGO_SBOM=$(find src-tauri -maxdepth 2 -name '*.cdx.json' | head -1)
  if [[ -n "$CARGO_SBOM" ]]; then
    cp "$CARGO_SBOM" "$OUT_DIR/sbom-cargo.cdx.json"
    log "  → $OUT_DIR/sbom-cargo.cdx.json ($(jq '.components | length' "$OUT_DIR/sbom-cargo.cdx.json") components)"
  fi
else
  warn "no src-tauri/Cargo.toml — skipping cargo SBOM"
fi

# ---------------------------------------------------------------------------
# 3. Android — Gradle dependencies
# ---------------------------------------------------------------------------
if [[ -d android ]]; then
  log "generating Android SBOM via cdxgen (Gradle plugin)"
  cdxgen -t java -o "$OUT_DIR/sbom-android.cdx.json" -p android --quiet || \
    warn "  Android SBOM generation failed (verify Gradle wrapper exists)"
  if [[ -f "$OUT_DIR/sbom-android.cdx.json" ]]; then
    log "  → $OUT_DIR/sbom-android.cdx.json"
  fi
fi

# ---------------------------------------------------------------------------
# 4. iOS — Swift PM / CocoaPods
# ---------------------------------------------------------------------------
if [[ -d ios ]]; then
  log "generating iOS SBOM via cdxgen (Swift)"
  cdxgen -t swift -o "$OUT_DIR/sbom-ios.cdx.json" -p ios --quiet || \
    warn "  iOS SBOM generation failed"
  if [[ -f "$OUT_DIR/sbom-ios.cdx.json" ]]; then
    log "  → $OUT_DIR/sbom-ios.cdx.json"
  fi
fi

# ---------------------------------------------------------------------------
# 5. Aggregate (cyclonedx-cli)
# ---------------------------------------------------------------------------
SBOMS=("$OUT_DIR"/sbom-*.cdx.json)
if [[ ${#SBOMS[@]} -gt 1 ]] && [[ -f "${SBOMS[0]}" ]]; then
  log "aggregating SBOMs"
  if ! command -v cyclonedx >/dev/null 2>&1; then
    # cyclonedx-cli — Microsoft port (.NET)
    if command -v dotnet >/dev/null 2>&1; then
      dotnet tool install --global CycloneDX --quiet >/dev/null 2>&1 || true
    fi
  fi
  if command -v cyclonedx >/dev/null 2>&1; then
    cyclonedx merge \
      --input-files "${SBOMS[@]}" \
      --output-file "$OUT_DIR/sbom-aggregate.cdx.json" \
      --output-format json
    log "  → $OUT_DIR/sbom-aggregate.cdx.json"
  else
    warn "cyclonedx-cli not available — skipping aggregate"
  fi
fi

# ---------------------------------------------------------------------------
# 6. Grype scan — fail on HIGH+ severity
# ---------------------------------------------------------------------------
if [[ "$SCAN" == "1" ]]; then
  log "scanning SBOMs with Grype"
  if ! command -v grype >/dev/null 2>&1; then
    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
  fi

  FAIL=0
  for sbom in "${SBOMS[@]}"; do
    [[ ! -f "$sbom" ]] && continue
    log "scanning $(basename "$sbom")"
    set +e
    grype "sbom:$sbom" \
      --fail-on high \
      --output table \
      | tee "$OUT_DIR/$(basename "$sbom" .cdx.json)-grype.txt"
    rc=$?
    set -e
    [[ $rc -ne 0 ]] && FAIL=1
  done

  if [[ $FAIL -ne 0 ]]; then
    err "Grype found HIGH+ vulnerabilities — see reports in $OUT_DIR/"
    exit 1
  fi
fi

log "done. SBOMs in $OUT_DIR/"
