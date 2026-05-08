You are operating as **fix-agent-2F** for the pre-launch remediation of the Travus stack. EXECUTE END-TO-END AUTONOMOUSLY.

CONTEXT
- Working directory: `~/travus`.
- Source audit: `./audit-reports/00-FINAL.md`, `./audit-reports/09-supabase-storage-realtime-network.md`.
- Output: `./fix-reports/`.
- Mode: `$FIX_MODE` (default `dev`; valid `dev` | `prod` | `dryrun`).

═══════════════════════════════════════════════════════════════════
SCOPE
═══════════════════════════════════════════════════════════════════
TLS / network hygiene — replace `sslmode=require` with `sslmode=verify-full` everywhere it appears in scripts and docs.

| ID | What |
|---|---|
| H-12 | `scripts/db-parity-check.sh:17` (PROD_URL) |
| H-13 | `scripts/db-parity-check.sh:18` (DEV_URL) |
| M-26 | `docs/dev-branch-onboarding.md:34, 84, 136` |
| L-6  | `scripts/restore-dev-branch.sh:81` (example connection string) |

This is a pure file-edit fix-agent. `MODE=dev` and `MODE=prod` are equivalent (no DB/API to apply against). Default `dev` opens edits + lints; `prod` opens a PR.

═══════════════════════════════════════════════════════════════════
PRE-CONDITIONS
═══════════════════════════════════════════════════════════════════
1. Working tree clean.
2. The 4 target files exist:
   - `scripts/db-parity-check.sh`
   - `scripts/restore-dev-branch.sh`
   - `docs/dev-branch-onboarding.md`
3. Supabase root CA bundle path decided (env: `$SUPABASE_CA_PATH`, default `$HOME/.supabase/ca-bundle.pem`).

═══════════════════════════════════════════════════════════════════
KNOWLEDGE BASE
═══════════════════════════════════════════════════════════════════

`sslmode=require` accepts any TLS cert chain — STARTTLS upgrade is MITM-trivial against a network attacker. `sslmode=verify-full` validates the cert chain AND hostname.

Replacement pattern (preserve query-string position, append `sslrootcert`):
```diff
- ?sslmode=require
+ ?sslmode=verify-full&sslrootcert=$HOME/.supabase/ca-bundle.pem
```

If the connection string already has `?sslmode=...`, replace inline. If using shell variable interpolation, ensure the path expands (avoid single-quoted heredocs).

Supabase root CA bundle is fetchable from:
```
https://supabase.com/docs/img/cdn/prod-ca-2021.crt
# Or per-region — confirm with platform team.
```

═══════════════════════════════════════════════════════════════════
WORKFLOW
═══════════════════════════════════════════════════════════════════

**STEP 0 — Bundle CA**

If `$SUPABASE_CA_PATH` is missing, download:
```bash
mkdir -p "$(dirname "${SUPABASE_CA_PATH:-$HOME/.supabase/ca-bundle.pem}")"
curl -fsSL https://supabase.com/docs/img/cdn/prod-ca-2021.crt \
  -o "${SUPABASE_CA_PATH:-$HOME/.supabase/ca-bundle.pem}"
```

Document the CA-bundle source in the report.

**STEP 1 — Edit `scripts/db-parity-check.sh`**

Read the file. Locate lines 17 and 18 (PROD_URL and DEV_URL). Replace `sslmode=require` with `sslmode=verify-full&sslrootcert=$HOME/.supabase/ca-bundle.pem`. Use Edit tool with full surrounding context for uniqueness.

**STEP 2 — Edit `scripts/restore-dev-branch.sh`**

Locate line 81 (example connection string). Add `?sslmode=verify-full&sslrootcert=$HOME/.supabase/ca-bundle.pem` (append `?` if URL has no query string yet).

**STEP 3 — Edit `docs/dev-branch-onboarding.md`**

Three occurrences (lines 34, 84, 136). Replace each `sslmode=require` with `sslmode=verify-full`. Add a sentence near the first occurrence:
```
> The Supabase root CA bundle is at `$HOME/.supabase/ca-bundle.pem` (fetched from
> https://supabase.com/docs/img/cdn/prod-ca-2021.crt). Pin via `sslrootcert=`.
```

**STEP 4 — Smoke test (MODE=dev)**

```bash
# Source the modified script and try a dummy connection
bash -n scripts/db-parity-check.sh           # syntax check
bash -n scripts/restore-dev-branch.sh        # syntax check
```

Connect smoke (only if a dev connection string is already in env):
```bash
[ -n "${SUPABASE_DEV_URL:-}" ] && {
  psql "$SUPABASE_DEV_URL?sslmode=verify-full&sslrootcert=$HOME/.supabase/ca-bundle.pem" \
    -c "select 1" 2>&1 | tee /tmp/2F-smoke.log
}
```

If the smoke fails with "certificate verify failed", the CA bundle is wrong — flag in the report.

**STEP 5 — Open PR (MODE=prod)**

```bash
git checkout -b fix-2F/tls-verify-full
git add scripts/db-parity-check.sh scripts/restore-dev-branch.sh docs/dev-branch-onboarding.md
git commit -m "fix(tls): pin sslmode=verify-full + sslrootcert across scripts + docs

Closes audit findings: H-12, H-13, M-26, L-6.
Replaces sslmode=require (no chain validation) with sslmode=verify-full
+ sslrootcert pointing at the Supabase root CA bundle."
git push -u origin fix-2F/tls-verify-full
gh pr create --title "fix(tls): sslmode=verify-full across scripts + docs" \
  --body "$(cat ./fix-reports/2F-result.md)"
```

**STEP 6 — Report**

`./fix-reports/2F-result.md`:
```
FIX-AGENT-2F RESULT
===================
Mode: dev | prod | dryrun
Result: PASS | FAIL | BLOCKED

CA bundle: $SUPABASE_CA_PATH
  source: <URL or "already present">

Files edited:
- scripts/db-parity-check.sh  (lines 17, 18)
- scripts/restore-dev-branch.sh  (line 81)
- docs/dev-branch-onboarding.md  (lines 34, 84, 136)

Syntax check (bash -n): PASS
Smoke connect (if SUPABASE_DEV_URL env present): PASS | FAIL | SKIPPED

PR (MODE=prod only): <URL or N/A>

Next agent: any of fix-agent-2A..2H in parallel.
```

**STEP 7 — Final stdout:**
```
DONE | fix-agent-2F | <mode> | <result> | ./fix-reports/2F-result.md
```

═══════════════════════════════════════════════════════════════════
HARD AUTONOMY RULES
═══════════════════════════════════════════════════════════════════
- NEVER auto-merge the PR.
- NEVER print connection strings in full — redact to `postgres://***@<host>:<port>/<db>?...`.
- If the CA bundle URL returns non-PEM content, BLOCKED — do not commit a wrong cert.
- BEGIN IMMEDIATELY.
