# Terminal: supabase-edge-functions-auditor (Phase 2 — parallel)

## Pre-flight

```bash
cd ~/dev/tauri
source .audit-env
mkdir -p audit-reports
brew install deno semgrep jq 2>/dev/null
pipx install semgrep 2>/dev/null || pip install --user semgrep 2>/dev/null
claude --dangerously-skip-permissions
```

## Required env

- `AUDIT_SKILLS_PATH` — repo root for `tools/semgrep-edge-functions.yml` and the agent file
- `SEMGREP_APP_TOKEN` — optional; only if uploading findings to Semgrep AppSec Platform

## Paste this entire block into Claude Code

---

You are operating as the **supabase-edge-functions-auditor** subagent. Adopt the role, knowledge base (13 custom Semgrep rules verbatim, `verify_jwt` lifecycle, secrets, CORS, canonical anti-patterns), and output format defined verbatim in:

  `$AUDIT_SKILLS_PATH/templates/claude-agents/supabase-edge-functions-auditor.md`

Read that file in FULL via the Read tool now. Then read `$AUDIT_SKILLS_PATH/docs/supabase-security-tools.md` §1.8 (Edge Functions) and `$AUDIT_SKILLS_PATH/tools/semgrep-edge-functions.yml` (the 13 rules) — internalise rule IDs for citing in findings.

REQUIRED INPUT
- `$AUDIT_SKILLS_PATH`. If unset, write `BLOCKED: AUDIT_SKILLS_PATH not set` to `./audit-reports/07-supabase-edge-functions.md` and exit.
- `supabase/functions/` directory. If missing, write `BLOCKED: supabase/functions/ not found` and exit.

WORKFLOW (autonomous)

1. **Inventory functions + companion files:**
   ```bash
   find supabase/functions -mindepth 1 -maxdepth 3 \
     \( -name '*.ts' -o -name 'config.toml' -o -name 'deno.json' -o -name 'import_map.json' \) \
     | sort > /tmp/edge-inventory.txt
   wc -l /tmp/edge-inventory.txt
   ls -1 supabase/functions/ 2>/dev/null | grep -v '^_' > /tmp/edge-fn-names.txt
   ```

2. **Read every `config.toml` — verify_jwt audit:**
   ```bash
   for f in supabase/functions/*/config.toml; do
     echo "=== $f ==="
     cat "$f"
   done > /tmp/edge-configs.txt
   rg -n 'verify_jwt\s*=\s*false' supabase/functions/*/config.toml > /tmp/edge-verify-jwt-false.txt || true
   ```
   For every `verify_jwt = false` entry, in step 5 confirm manual `getUser()` / `jose.jwtVerify` / signature verification exists. If missing → **CRITICAL**.

3. **Deno lint + fmt:**
   ```bash
   deno lint supabase/functions/ 2>&1 | tee /tmp/deno-lint.txt
   deno fmt --check supabase/functions/ 2>&1 | tee /tmp/deno-fmt.txt
   ```

4. **Run the 13 custom Semgrep rules:**
   ```bash
   semgrep --config "$AUDIT_SKILLS_PATH/tools/semgrep-edge-functions.yml" \
     --metrics=off --error --json supabase/functions/ \
     > /tmp/semgrep-edge.json 2> /tmp/semgrep-edge.err || true
   jq '[.results[] | {check_id, path, start: .start.line, severity: .extra.severity, msg: .extra.message}] | group_by(.check_id) | map({rule: .[0].check_id, count: length, hits: .})' \
     /tmp/semgrep-edge.json > /tmp/semgrep-edge-grouped.json
   ```
   Map findings to severities per the rule definitions:
   - ERROR: `supabase-edge-service-role-from-non-env`, `supabase-edge-hardcoded-service-role`, `supabase-edge-env-leaked-in-response`, `supabase-edge-rpc-string-concat`, `supabase-edge-jwt-decode-without-verify`
   - WARNING: `supabase-edge-cors-wildcard`, `supabase-edge-no-manual-jwt-verify`, `supabase-edge-log-sensitive-headers`, `supabase-edge-error-leaked-to-client`, `supabase-edge-ssrf-via-user-url`, `supabase-edge-deprecated-supabase-js-v1`
   - INFO: `supabase-edge-catch-all-returns-2xx`, `supabase-edge-auth-helpers-deprecated`

5. **Per-function manual walk** — for each `supabase/functions/<name>/index.ts`:
   ```bash
   for fn in $(cat /tmp/edge-fn-names.txt); do
     echo "=== $fn ==="
     # Imports — flag risky CDNs and v1
     rg -n 'from\s+["'"'"'](https?://|@supabase/)' "supabase/functions/$fn/" 2>/dev/null
     # createClient calls — key source must be Deno.env or pass-through JWT
     rg -nC2 'createClient\s*\(' "supabase/functions/$fn/" 2>/dev/null
     # Authorization header reads — must be paired with getUser() or jwtVerify
     rg -n 'headers\.get\(\s*["'"'"'][Aa]uthorization' "supabase/functions/$fn/" 2>/dev/null
     rg -n '\.auth\.getUser\(|jose\.jwtVerify\(|jwtVerify\(' "supabase/functions/$fn/" 2>/dev/null
     # rpc() call shape — args must be object, not template literal
     rg -nC1 '\.rpc\s*\(' "supabase/functions/$fn/" 2>/dev/null
     # Error reflection
     rg -n '\.stack|JSON\.stringify\(\s*err' "supabase/functions/$fn/" 2>/dev/null
     # External fetch — SSRF surface
     rg -n '\bfetch\s*\(' "supabase/functions/$fn/" 2>/dev/null
     # Module-scoped createClient (connection leak / tenant bleed)
     awk '/^import|^const|^let|^var/{prelude=1} /Deno\.serve|export default|serve\(/{prelude=0} prelude && /createClient/{print FILENAME":"NR": MODULE-SCOPED createClient"}' \
       "supabase/functions/$fn/index.ts" 2>/dev/null
     # CORS pattern
     rg -n 'Access-Control-Allow-Origin|corsHeaders' "supabase/functions/$fn/" 2>/dev/null
   done > /tmp/edge-walk.txt 2>&1
   ```

6. **Cross-function aggregate checks:**
   ```bash
   # All functions reading service_role
   rg -n 'SUPABASE_SERVICE_ROLE_KEY' supabase/functions/ > /tmp/edge-svc-role.txt || true
   # Deprecated packages
   rg -n '@supabase/supabase-js@1|@supabase/auth-helpers-' supabase/functions/ > /tmp/edge-deprecated.txt || true
   # eval / Function / dynamic import from request input (RCE)
   rg -nP '\b(eval|new\s+Function)\s*\(|import\s*\(\s*(req|request)' supabase/functions/ > /tmp/edge-rce.txt || true
   # CORS reflection of Origin
   rg -nC1 'headers\.get\(\s*["'"'"'][Oo]rigin' supabase/functions/ > /tmp/edge-cors-reflect.txt || true
   ```

7. **Verify configured secrets vs `Deno.env.get(...)` reads:**
   ```bash
   supabase secrets list 2>&1 | tee /tmp/edge-secrets.txt
   rg -noP 'Deno\.env\.get\(\s*["'"'"']\K[A-Z0-9_]+' supabase/functions/ \
     | awk -F: '{print $NF}' | sort -u > /tmp/edge-env-reads.txt
   ```
   Names read in code but not in `secrets list` → HIGH (runtime undefined → silent failure or fallback). Names listed but never read → INFO.

8. **`config.toml` `import_map` integrity (no untrusted CDNs without lock):**
   ```bash
   rg -n 'esm\.sh|cdn\.skypack\.dev|deno\.land/x' supabase/functions/ > /tmp/edge-cdn.txt || true
   ls supabase/functions/*/deno.lock 2>/dev/null > /tmp/edge-locks.txt
   ```
   CDN imports without a `deno.lock` next to them → MEDIUM.

9. **Write report** to `./audit-reports/07-supabase-edge-functions.md` following the agent file's output format. Required sections:
   - Header table (functions total, `verify_jwt true/false` counts, deprecated imports, deno lint/fmt status, Semgrep ERROR/WARNING/INFO counts)
   - Per-function block: `verify_jwt`, imports, `createClient` key source, manual JWT verify, CORS pattern, findings with `[SEVERITY] LXX: <msg> (rule <id>)`
   - Cross-function: count of `SUPABASE_SERVICE_ROLE_KEY` consumers, fetch SSRF surface count
   - Remediation summary (CRITICAL must-fix-before-launch, HIGH this-sprint)

OUTPUT
- File: `./audit-reports/07-supabase-edge-functions.md`
- Final stdout: `DONE | supabase-edge-functions | <CRITICAL> CRITICAL | <HIGH> HIGH | ./audit-reports/07-supabase-edge-functions.md`

AUTONOMY RULES (HARD)
- NEVER deploy, invoke, or `supabase functions serve`. Static analysis only.
- NEVER write or modify any file under `supabase/functions/`.
- NEVER push to git.
- NEVER write outside `./audit-reports/`, `/tmp/`.
- If `deno` or `semgrep` is missing after pre-flight install attempts, note "skipped: <tool> not installed" in the report and continue with remaining checks.
- Do not echo full file contents into the report — cite `path:line` only.

BEGIN.
