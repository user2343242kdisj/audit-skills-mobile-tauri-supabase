# Terminal: secrets-scanner-coordinator (Phase 2 — parallel)

## Pre-flight

```bash
cd ~/desktop/travus
source .audit-env
mkdir -p audit-reports

# Install scanners (one-time)
brew install gitguardian/tap/ggshield trufflesecurity/trufflehog/trufflehog gitleaks 2>/dev/null

claude --dangerously-skip-permissions
```

## Required env

- `GITGUARDIAN_API_KEY` (from https://dashboard.gitguardian.com/api/personal-access-tokens)
- `AUDIT_SKILLS_PATH`

## Paste this entire block into Claude Code

---

You are operating as the **secrets-scanner-coordinator** subagent. Adopt the role, knowledge base (Supabase + Tauri secret formats, the GitGuardian Supabase-specific detectors, CVE-2023-46115 envPrefix leak class), and output format defined verbatim in:

  `$AUDIT_SKILLS_PATH/templates/claude-agents/secrets-scanner-coordinator.md`

Read that file in FULL via the Read tool now.

REQUIRED INPUTS
- `$GITGUARDIAN_API_KEY` — if missing, fall back to TruffleHog + Gitleaks only (note in report).
- Working directory must be a git repo. If not: write `BLOCKED: not a git repo` and exit.

WORKFLOW (autonomous)

1. **Working tree scan (3 tools cross-checked):**
   ```bash
   ggshield secret scan repo . --json > /tmp/ggshield-tree.json 2>&1 || true
   trufflehog filesystem . --only-verified --json > /tmp/trufflehog-tree.json 2>&1 || true
   gitleaks detect --source . --redact --no-git --report-format json --report-path /tmp/gitleaks-tree.json 2>&1 || true
   ```

2. **Git history scan:**
   ```bash
   gitleaks detect --source . --redact --report-format json --report-path /tmp/gitleaks-history.json 2>&1 || true
   trufflehog git file://. --only-verified --json > /tmp/trufflehog-history.json 2>&1 || true
   ```

3. **Built-bundle scan (skip if missing):**
   ```bash
   for d in dist build src-tauri/target/release; do
     [ -d "$d" ] && ggshield secret scan path "$d" --json >> /tmp/ggshield-bundles.json 2>&1
   done
   ```

4. **CVE-2023-46115 check (Vite envPrefix leak):**
   ```bash
   rg -n 'envPrefix' vite.config.* 2>/dev/null
   for d in dist build; do
     [ -d "$d" ] && grep -rE 'TAURI_PRIVATE_KEY|TAURI_SIGNING_PRIVATE_KEY' "$d" 2>/dev/null
   done
   ```

5. **GitHub Push Protection enabled?**
   ```bash
   if command -v gh >/dev/null 2>&1; then
     gh api "repos/$(gh repo view --json owner,name -q '.owner.login + \"/\" + .name')" \
       --jq '.security_and_analysis.secret_scanning_push_protection.status' 2>&1
   fi
   ```

6. **Supabase × GitHub partner verified:**
   - For each repo, document whether public (auto-revoke active) or private (manual rotate).

7. **Deduplicate findings across all three tools** by hashed-secret comparison or location.

8. **Rank by severity:**
   - CRITICAL: verified service_role JWT, sb_secret_*, sk_live_*, AKIA*, .p8/.p12 contents, TAURI_PRIVATE_KEY in bundle
   - HIGH: verified anon JWT, GitHub PAT, OAuth tokens
   - MEDIUM: unverified credential-shaped strings (likely false positives)

9. **Write report** to `./audit-reports/02-secrets-scan.md` following the agent file's output format. Include "REMEDIATION CHECKLIST" with exact rotation commands per finding.

OUTPUT
- File: `./audit-reports/02-secrets-scan.md`
- Final stdout: `DONE | secrets-scanner | <CRITICAL count> CRITICAL | <HIGH count> HIGH | ./audit-reports/02-secrets-scan.md`

AUTONOMY RULES (HARD)
- NEVER print full secret values. Always redact (`sb_secret_***...REDACTED`).
- NEVER push to git.
- NEVER write outside `./audit-reports/`, `/tmp/`.
- If a tool is missing, document in the report; do not crash.

BEGIN.
