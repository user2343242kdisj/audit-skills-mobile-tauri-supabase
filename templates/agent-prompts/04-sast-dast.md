# Terminal: sast-dast-coordinator (Phase 2 — parallel; needs test JWTs)

## Pre-flight

```bash
cd ~/desktop/travus
source .audit-env
mkdir -p audit-reports

# One-time installs
pip install schemathesis requests 2>/dev/null
brew install semgrep 2>/dev/null

claude --dangerously-skip-permissions
```

## Required env

- `SUPABASE_PROJECT_REF` — required for Schemathesis + BOLA
- `SUPABASE_ANON_KEY` — required for Schemathesis + BOLA
- `USER_A_JWT`, `USER_B_JWT` — required for BOLA harness; test users must exist in your Auth project
- `SEMGREP_APP_TOKEN` (optional)
- `AUDIT_SKILLS_PATH`

## Paste this entire block into Claude Code

---

You are operating as the **sast-dast-coordinator** subagent. Adopt the role, knowledge base (Semgrep + Schemathesis + BOLA harness; the RLS-blind limitation; the 13 custom Edge Function rules), and output format defined verbatim in:

  `$AUDIT_SKILLS_PATH/templates/claude-agents/sast-dast-coordinator.md`

Read that file in FULL via the Read tool now.

PHASE A — SAST (autonomous)

1. **Semgrep — custom Edge Function rules + community packs:**
   ```bash
   if [ -d supabase/functions ] || [ -d src ] || [ -d src-tauri/src ]; then
     semgrep \
       --config $AUDIT_SKILLS_PATH/tools/semgrep-edge-functions.yml \
       --config p/typescript \
       --config p/security-audit \
       --severity ERROR --severity WARNING \
       --json --output /tmp/semgrep.json \
       supabase/functions/ src/ src-tauri/src/ 2>/dev/null || true
   fi
   ```

2. **Rust deps quick check:**
   ```bash
   ( cd src-tauri && cargo audit --quiet 2>&1 | tail -20 ) || true
   ```

3. **npm deps quick check:**
   ```bash
   [ -f package-lock.json ] && npm audit --audit-level=high --production 2>&1 | tail -20 || true
   ```

4. **Postgres PL/pgSQL lint:**
   ```bash
   if command -v supabase >/dev/null 2>&1 && [ -n "$SUPABASE_DB_URL" ]; then
     supabase db lint --db-url "$SUPABASE_DB_URL" --level error --fail-on warning > /tmp/db-lint.txt 2>&1 || true
   fi
   ```

PHASE B — DAST against PostgREST (only if env complete)

5. **Schemathesis as anon role:**
   ```bash
   if [ -n "$SUPABASE_PROJECT_REF" ] && [ -n "$SUPABASE_ANON_KEY" ]; then
     URL="https://$SUPABASE_PROJECT_REF.supabase.co"
     schemathesis run "$URL/rest/v1/" \
       --base-url "$URL/rest/v1/" \
       --header "apikey: $SUPABASE_ANON_KEY" \
       --checks all --max-examples 30 --workers 4 \
       --report-junit-path /tmp/schemathesis-anon.xml 2>&1 | tee /tmp/schemathesis-anon.log || true
   fi
   ```

6. **Schemathesis as authenticated user A:**
   ```bash
   if [ -n "$USER_A_JWT" ]; then
     schemathesis run "$URL/rest/v1/" \
       --base-url "$URL/rest/v1/" \
       --header "apikey: $SUPABASE_ANON_KEY" \
       --header "Authorization: Bearer $USER_A_JWT" \
       --checks all --max-examples 30 --workers 4 \
       --report-junit-path /tmp/schemathesis-auth.xml 2>&1 | tee /tmp/schemathesis-auth.log || true
   fi
   ```

7. **BOLA harness (closes the RLS-blindness gap of Schemathesis):**
   ```bash
   if [ -n "$USER_A_JWT" ] && [ -n "$USER_B_JWT" ]; then
     python3 $AUDIT_SKILLS_PATH/tools/bola-harness.py \
       --url "$URL" \
       --anon-key "$SUPABASE_ANON_KEY" \
       --user-a-jwt "$USER_A_JWT" \
       --user-b-jwt "$USER_B_JWT" \
       --output /tmp/bola-report.json \
       --max-rows-per-table 5 2>&1 | tee /tmp/bola.log || true
   else
     echo "SKIP: BOLA harness — missing USER_A_JWT or USER_B_JWT"
   fi
   ```

8. **OWASP ZAP active scan (optional, only if Docker available):**
   ```bash
   if command -v docker >/dev/null 2>&1 && [ -n "$USER_A_JWT" ]; then
     docker run --rm -v "$PWD:/zap/wrk" owasp/zap2docker-stable \
       zap-api-scan.py -t "$URL/rest/v1/" -f openapi \
       -r /zap/wrk/audit-reports/04-zap.html 2>&1 | tail -30 || true
   fi
   ```

9. **Synthesise** all outputs into a single ranked findings list:
   - Semgrep ERROR-level → CRITICAL (esp. supabase-edge-service-role-from-non-env, supabase-edge-jwt-decode-without-verify, supabase-edge-rpc-string-concat)
   - BOLA harness HIGH/CRITICAL → CRITICAL
   - cargo-audit / npm-audit HIGH+ → CRITICAL
   - supabase db lint errors → HIGH
   - Schemathesis 5xx → MEDIUM (server errors)
   - ZAP HIGH+ → HIGH

10. **Write report** to `./audit-reports/04-sast-dast.md` following the agent file's output format. For BOLA findings, recommend cross-referencing with `supabase-rls-auditor`'s findings.

OUTPUT
- File: `./audit-reports/04-sast-dast.md`
- Artefacts: `/tmp/semgrep.json`, `/tmp/bola-report.json`, `audit-reports/04-zap.html`
- Final stdout: `DONE | sast-dast | <CRITICAL> CRITICAL | <HIGH> HIGH | ./audit-reports/04-sast-dast.md`

AUTONOMY RULES (HARD)
- NEVER attempt destructive DAST (the BOLA harness is non-destructive by default; do NOT pass `--enable-destructive`).
- NEVER push to git.
- NEVER write outside `./audit-reports/`, `/tmp/`.
- If env missing, mark phase as "SKIPPED — missing env" in the report.

BEGIN.
