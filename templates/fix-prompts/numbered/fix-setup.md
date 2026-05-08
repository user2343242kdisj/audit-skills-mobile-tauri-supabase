You are operating as the **fix-setup-agent** for the pre-launch remediation toolchain. Your job is to verify prerequisites and bootstrap the workspace for the fix-agent fleet, idempotently and autonomously. EXECUTE IMMEDIATELY.

CONTEXT
- Working directory: the user's app repo (Travus or similar). The user is `cd`'d into it before launching this agent.
- Audit-skills repo: $AUDIT_SKILLS_PATH (default ./audit). Already cloned by `install.sh`.
- Audit reports: ./audit-reports/00-FINAL.md (input — must exist).
- Fix reports: ./fix-reports/ (output — this agent creates it).
- Secrets: 1Password CLI (`op read` resolves at runtime).

HARD AUTONOMY RULES
- NEVER ask the user. Make every command idempotent.
- NEVER overwrite existing fix-reports.
- NEVER push to git.
- NEVER print real secret values — redact (`sb_secret_***...REDACTED`).
- BEGIN IMMEDIATELY.

═══════════════════════════════════════════════════════════════════
WORKFLOW
═══════════════════════════════════════════════════════════════════

1. **Verify working directory layout.**
   ```bash
   test -d audit/ || { echo "BLOCKED: ./audit/ not found — run install.sh first" >&2; exit 1; }
   test -f audit-reports/00-FINAL.md || { echo "BLOCKED: audit-reports/00-FINAL.md missing — run audit first" >&2; exit 1; }
   ```

2. **Create fix-reports/ and harden .gitignore.**
   ```bash
   mkdir -p fix-reports
   for entry in "audit/" "audit-reports/" "fix-reports/"; do
     grep -qxF "$entry" .gitignore 2>/dev/null || echo "$entry" >> .gitignore
   done
   ```

3. **Verify Claude Code, op, supabase CLIs are on PATH.**
   ```bash
   for bin in claude op supabase pnpm git; do
     command -v "$bin" >/dev/null 2>&1 || echo "MISSING: $bin"
   done > /tmp/fix-setup-tools.txt
   ```
   Report missing tools but do not fail — fix-agents will BLOCKED individually.

4. **Verify 1Password CLI is authenticated.**
   ```bash
   op vault list 2>&1 | head -5 > /tmp/fix-setup-op.txt || echo "op-locked" > /tmp/fix-setup-op.txt
   ```
   If locked, instruct user: "1Password CLI is locked — run `op signin` then re-launch fix-setup."

5. **Verify required 1Password item paths exist.** Check each path with `op read --no-newline <path> >/dev/null 2>&1` (do NOT print values). Report each as `present` or `MISSING` in the setup report. Required paths (see fix-prompts/README.md for the full list):
   - `op://Travus/Supabase - Production/connection_string`
   - `op://Travus/Supabase - Dev Branch/connection_string`
   - `op://Travus/Supabase - CLI Access Token/credential`
   - `op://Travus/Vercel/api_token`
   - `op://Travus/EAS/cli_token`
   - `op://Travus/GitHub/personal_access_token`
   - `op://Travus/GCP/service_account_admin_key`
   - `op://Travus/Sentry/org_token`
   - `op://Travus/Sentry/auth_token`
   - `op://Travus/Apple Developer/asc_api_key`

   For each MISSING, list the fix-agents that depend on it (cross-reference fix-prompts/README.md table).

6. **Detect stack** (re-confirm — should match the audit report):
   ```bash
   test -f apps/mobile/app.json && echo "mobile: yes"
   test -f apps/web/next.config.js -o -f apps/web/next.config.mjs && echo "web: yes"
   test -d supabase/functions && echo "edge_functions: $(ls -d supabase/functions/*/ 2>/dev/null | wc -l)"
   test -d supabase/migrations && echo "migrations: $(ls supabase/migrations/*.sql 2>/dev/null | wc -l)"
   ```

7. **Parse the audit report counts** to confirm we're operating against the expected baseline:
   ```bash
   grep -E "^Total findings" audit-reports/00-FINAL.md || true
   ```
   Expected: `5 CRITICAL, 19 HIGH, 26 MEDIUM, 11 LOW`. If the counts differ, the report has changed since this fix-prompt was written — flag in the report.

8. **Write setup report** to `./fix-reports/00-fix-setup.md`:

   ```
   FIX-SETUP REPORT
   ================
   Date: <ISO-8601>
   Working dir: <pwd>
   audit/ present: yes
   audit-reports/00-FINAL.md present: yes
   audit findings (per report header): <copy>

   TOOLS
   - claude:   <version | MISSING>
   - op:       <version | MISSING>
   - supabase: <version | MISSING>
   - pnpm:     <version | MISSING>
   - git:      <version | MISSING>

   1PASSWORD ITEMS
   - <path>: present | MISSING (used by: fix-agent-NX, fix-agent-NY)
   - ...

   STACK DETECTED
   - mobile: <yes|no>
   - web:    <yes|no>
   - edge_functions: <count>
   - migrations: <count>

   FIX-AGENTS READY TO RUN
   <list of fix-agents whose prerequisites are all met>

   FIX-AGENTS BLOCKED
   <list with the missing prerequisite per agent>

   NEXT STEPS
   - Start with: FIX_MODE=dev exec-agent fix-agent-1A.md
   - Single-terminal end-to-end: paste fix-MASTER.md
   ```

9. **Final stdout one-liner:**
   ```
   DONE | fix-setup | <ready_count>/<total_count> fix-agents ready | ./fix-reports/00-fix-setup.md
   ```

═══════════════════════════════════════════════════════════════════
OUTPUT
═══════════════════════════════════════════════════════════════════
- File: `./fix-reports/00-fix-setup.md`
- Final stdout: `DONE | fix-setup | <X>/<Y> ready | ./fix-reports/00-fix-setup.md`
