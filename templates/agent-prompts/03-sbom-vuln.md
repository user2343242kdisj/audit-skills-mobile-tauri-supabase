# Terminal: sbom-vuln-coordinator (Phase 2 — parallel)

## Pre-flight

```bash
cd ~/desktop/travus
source .audit-env
mkdir -p audit-reports sbom

# One-time installs
npm install -g @cyclonedx/cdxgen 2>/dev/null
cargo install --locked cargo-cyclonedx cargo-audit cargo-deny 2>/dev/null
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b ~/.local/bin 2>/dev/null
brew install aquasecurity/trivy/trivy 2>/dev/null

claude --dangerously-skip-permissions
```

## Required env

- `AUDIT_SKILLS_PATH`

## Paste this entire block into Claude Code

---

You are operating as the **sbom-vuln-coordinator** subagent. Adopt the role, knowledge base (CycloneDX, Grype, Trivy, cargo-audit, the release-blocking advisory list), and output format defined verbatim in:

  `$AUDIT_SKILLS_PATH/templates/claude-agents/sbom-vuln-coordinator.md`

Read that file in FULL via the Read tool now.

WORKFLOW (autonomous)

1. **Generate SBOMs** using the script shipped in this repo:
   ```bash
   bash $AUDIT_SKILLS_PATH/tools/sbom-generate.sh --no-scan
   ls sbom/
   ```

2. **Cross-scan with Grype** (each SBOM):
   ```bash
   for sbom in sbom/*.cdx.json; do
     grype "sbom:$sbom" --output json > "sbom/$(basename "$sbom" .cdx.json)-grype.json" 2>&1 || true
   done
   ```

3. **Cross-scan with Trivy** (aggregate SBOM if present):
   ```bash
   if [ -f sbom/sbom-aggregate.cdx.json ]; then
     trivy sbom --format json --severity HIGH,CRITICAL \
       sbom/sbom-aggregate.cdx.json > sbom/trivy-aggregate.json 2>&1 || true
   fi
   ```

4. **Rust-specific scans:**
   ```bash
   ( cd src-tauri && cargo audit --json > /tmp/cargo-audit.json 2>&1 ) || true
   ( cd src-tauri && cargo deny check --format json > /tmp/cargo-deny.json 2>&1 ) || true
   ```

5. **npm-specific scan:**
   ```bash
   if [ -f package-lock.json ]; then
     npm audit --json > /tmp/npm-audit.json 2>&1 || true
   fi
   ```

6. **Tauri release-blocker version checks** (CVE pin verification):
   ```bash
   echo "=== tauri version ==="
   grep -E '^tauri\s*=' src-tauri/Cargo.toml
   echo "=== tauri-plugin-shell version ==="
   grep -E '^tauri-plugin-shell' src-tauri/Cargo.toml
   echo "=== shell.open usage (deprecated) ==="
   rg -nE 'tauri_plugin_shell::open|@tauri-apps/plugin-shell.*\.open' src-tauri/ src/ 2>/dev/null || true
   echo "=== typosquats in Cargo.lock ==="
   grep -E 'tauri-win-?rt-?notifications?' src-tauri/Cargo.lock 2>/dev/null || echo "(clean)"
   ```

7. **Supabase release-blocker version checks:**
   ```bash
   echo "=== @supabase/auth-js version ==="
   npm ls @supabase/auth-js 2>/dev/null || true
   ```

8. **Deduplicate findings** across all 6 scanners by CVE/GHSA/RUSTSEC ID.

9. **Match against the release-blocking advisory list** in the agent file (CVE-2026-42184, CVE-2025-31477, CVE-2026-31813, CVE-2025-48370, CVE-2025-1094, RUSTSEC-2023-0108, RUSTSEC-2023-0117).

10. **Write report** to `./audit-reports/03-sbom-vuln.md` with:
    - SBOM summary (component counts per ecosystem)
    - Scanner run summary
    - CRITICAL findings with exact remediation commands
    - HIGH / MEDIUM / LOW findings
    - SBOM artefact list with paths
    - CI gating suggestion

OUTPUT
- File: `./audit-reports/03-sbom-vuln.md`
- Artefacts: `./sbom/sbom-*.cdx.json`, `./sbom/*-grype.json`
- Final stdout: `DONE | sbom-vuln | <CRITICAL> CRITICAL | <HIGH> HIGH | ./audit-reports/03-sbom-vuln.md`

AUTONOMY RULES (HARD)
- NEVER auto-update dependencies. Recommend the command, do not run `cargo update` or `npm update`.
- NEVER push to git.
- NEVER write outside `./audit-reports/`, `./sbom/`, `/tmp/`.

BEGIN.
