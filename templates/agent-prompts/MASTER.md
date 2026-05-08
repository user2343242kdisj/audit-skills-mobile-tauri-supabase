# Terminal: MASTER Orchestrator (does EVERYTHING — single terminal)

Single prompt that runs Phase 1 (threat model), spawns 14 Phase-2 subagents in parallel via the Agent tool, then synthesises Phase 3 into `00-FINAL.md`. **One terminal, end-to-end audit.**

## Pre-flight (one-time, in your app repo)

```bash
cd ~/desktop/travus

# Clone audit-skills (once)
[ -d ../audit-skills ] || git clone https://github.com/user2343242kdisj/audit-skills-mobile-tauri-supabase.git ../audit-skills

mkdir -p audit-reports
grep -q "audit-reports/" .gitignore 2>/dev/null || echo "audit-reports/" >> .gitignore
grep -q ".audit-env" .gitignore 2>/dev/null || echo ".audit-env" >> .gitignore

# Create env file (only if missing — fill values yourself)
[ -f .audit-env ] || cat > .audit-env <<'EOF'
export AUDIT_SKILLS_PATH="../audit-skills"
export SUPABASE_DB_URL="postgresql://readonly:PASSWORD@db.<projectref>.supabase.co:5432/postgres?sslmode=verify-full"
export SUPABASE_PROJECT_REF="<projectref>"
export SUPABASE_ANON_KEY="sb_publishable_..."
export SUPABASE_ACCESS_TOKEN="<management-api-pat>"
export USER_A_JWT="<JWT for test user A>"
export USER_B_JWT="<JWT for test user B>"
export GITGUARDIAN_API_KEY="<from dashboard.gitguardian.com>"
EOF
chmod 600 .audit-env

source .audit-env
claude --dangerously-skip-permissions
```

## Paste this entire block into Claude Code

---

You are the **MASTER audit orchestrator** for the pre-launch security audit of a Tauri 2 desktop + mobile + Supabase stack located at `~/desktop/travus`. EXECUTE END-TO-END AUTONOMOUSLY.

CONTEXT
- Working directory: `~/desktop/travus` (the app repo).
- Audit-skills repo: `$AUDIT_SKILLS_PATH` (default `../audit-skills`).
- Reports directory: `./audit-reports/`.
- Reference docs: `$AUDIT_SKILLS_PATH/docs/` (MAS, Tauri 2, Supabase deep analyses).
- Env file already sourced (`.audit-env`).

ARCHITECTURE
- **Phase 1 (sequential, you run inline):** threat-modeler → `audit-reports/01-threat-model.md`.
- **Phase 2 (14 parallel subagents, dispatched via the Agent tool in ONE message):** see list below. Each writes `audit-reports/NN-name.md`.
- **Phase 3 (sequential, you run inline):** synthesise everything into `audit-reports/00-FINAL.md`.

HARD AUTONOMY RULES (apply to YOU and to every dispatched subagent)
- NEVER ask the user. Missing input → write `BLOCKED: <reason>` to the relevant report file and continue.
- NEVER run destructive operations (DROP/DELETE/force push/`rm -rf` outside `/tmp`).
- NEVER write outside `./audit-reports/`, `./threat-model.py`, `./sbom/`, `/tmp/`.
- NEVER push to git.
- NEVER pause for confirmation.

═══════════════════════════════════════════════════════════════════
PHASE 1 — Threat model (you execute inline)
═══════════════════════════════════════════════════════════════════

1. Read `$AUDIT_SKILLS_PATH/templates/agent-prompts/01-threat-modeler.md` and `$AUDIT_SKILLS_PATH/templates/claude-agents/threat-modeler.md` in full.
2. Adopt the threat-modeler role.
3. Execute the threat-model workflow against the current working directory.
4. Write the report to `./audit-reports/01-threat-model.md`.
5. Note the recommended MAS profile (L1/L2/R/P) and the ranked top-15 threats — you will pass these to Phase 2.

═══════════════════════════════════════════════════════════════════
PHASE 2 — 14 parallel subagents (single message, multiple Agent tool calls)
═══════════════════════════════════════════════════════════════════

After Phase 1, dispatch all 14 in ONE assistant message with 14 Agent tool calls (parallel execution). Use `subagent_type: "general-purpose"` for each.

For EACH subagent, the `prompt` parameter must be:

```
You are operating as the <NAME> auditor for the pre-launch security audit of a Tauri 2 desktop + mobile + Supabase stack.

WORKING DIRECTORY: ~/desktop/travus
AUDIT_SKILLS_PATH: ../audit-skills
ENV: already exported in the parent process (SUPABASE_*, USER_A_JWT, USER_B_JWT, GITGUARDIAN_API_KEY, AUDIT_SKILLS_PATH).

Read this terminal-prompt file in FULL and execute its workflow exactly:

  ../audit-skills/templates/agent-prompts/<NN>-<name>.md

That file tells you which agent definition (`templates/claude-agents/<name>.md`) to adopt, lists required env vars, and specifies the numbered workflow.

Threat-model context from Phase 1:
- MAS profile recommended: <copy from Phase 1 output>
- Top threats relevant to this domain: <copy the 2–5 top threats matching this agent's scope>

OUTPUT
- Write the full report to ./audit-reports/<NN>-<name>.md
- Return ONE LINE summary in this format: `DONE | <name> | <CRITICAL count> | <HIGH count> | <report path>`

AUTONOMY RULES
- Never ask the user. Missing env → write `BLOCKED: <reason>` to the report and stop.
- Never destructive ops. Never git push. Writes restricted to ./audit-reports/, /tmp/, ./sbom/.
- Never write outside the working directory tree.
- Be concise — quote the most important findings, do not dump full raw tool output unless it's evidence for a CRITICAL.

Begin.
```

The 14 subagents to dispatch (copy NAME and NN-name into each prompt):

| NN | name (file 02–15) | description (4-word) |
|----|---|---|
| 02 | secrets-scanner | "Secret scan + history" |
| 03 | sbom-vuln | "SBOM + dep vulns" |
| 04 | sast-dast | "SAST + DAST + BOLA" |
| 05 | supabase-rls | "Supabase RLS + pgTAP" |
| 06 | supabase-auth | "Supabase Auth + GoTrue CVEs" |
| 07 | supabase-edge-functions | "Edge Functions + 13 Semgrep rules" |
| 08 | supabase-postgres | "Postgres roles, grants, FDWs" |
| 09 | supabase-storage-realtime-network | "Storage + Realtime + TLS" |
| 10 | tauri-capabilities | "Tauri capability ACL audit" |
| 11 | tauri-ipc | "Tauri IPC + 6-class checklist" |
| 12 | tauri-config-and-distribution | "CSP + updater + binary hardening" |
| 13 | mobile-static | "Mobile APK/IPA static analysis" |
| 14 | mobile-dynamic | "Mobile Frida + Burp dynamic" |
| 15 | mobile-platform | "Deeplinks + Keychain + cert pinning" |

Important: dispatch ALL 14 in a single assistant message containing 14 `Agent` tool calls. Do not loop sequentially.

═══════════════════════════════════════════════════════════════════
PHASE 3 — Synthesis (you execute inline after all 14 return)
═══════════════════════════════════════════════════════════════════

1. Read every file in `./audit-reports/` (excluding `00-FINAL.md`):
   - `01-threat-model.md`
   - `02-secrets-scan.md` … `15-mobile-platform.md`

2. Adopt the orchestrator role from `$AUDIT_SKILLS_PATH/templates/claude-agents/audit-orchestrator.md` (its **Report template** section is the canonical output structure).

3. Synthesise:
   - Aggregate every CRITICAL / HIGH / MEDIUM / LOW finding with `<filename>:<section>` attribution.
   - Deduplicate cross-report by CVE/GHSA/Splinter/MASWE ID.
   - Identify launch blockers (every CRITICAL).
   - Note any subagent that returned `BLOCKED:` — add to "Remaining gaps" with reason.
   - List passed checks (anti-regression evidence).
   - Map findings to MAS profile coverage.

4. Write the final report to `./audit-reports/00-FINAL.md` following this skeleton:

   ```
   PRE-LAUNCH SECURITY AUDIT REPORT
   ================================
   Stack:        Mobile (iOS+Android) + Tauri 2 desktop + Supabase
   Profile:      <from Phase 1>
   Audit date:   <today>
   Subagents:    <list that returned cleanly + list that BLOCKED>

   EXECUTIVE SUMMARY
   - Total: X CRITICAL, Y HIGH, Z MEDIUM, W LOW
   - Launch blockers: <list of CRITICAL>
   - Posture vs MASVS L2+P: <%>
   - Posture vs OWASP ASVS v5: <%>

   CRITICAL (must fix before launch)
   …
   HIGH (must fix this sprint)
   …
   MEDIUM
   …
   LOW
   …

   PASSED CHECKS (anti-regression evidence)
   …

   REMAINING GAPS (no tool covered, or BLOCKED subagents)
   …

   NEXT STEPS (concrete, with owners if known)
   - [ ] …
   ```

5. Print the canonical final stdout line:

   ```
   DONE | MASTER | <total CRITICAL> CRITICAL | <total HIGH> HIGH | ./audit-reports/00-FINAL.md
   ```

═══════════════════════════════════════════════════════════════════
QUALITY BAR
═══════════════════════════════════════════════════════════════════

- Every finding cites `path:line`, CVE/GHSA/RUSTSEC ID, Splinter rule ID, or MASWE ID.
- Never invent findings. Only report what subagents returned.
- Quote subagent reports verbatim with attribution; do not paraphrase critical text.
- If a subagent returned `BLOCKED:`, document the missing input clearly so the user knows what to set + re-run.

BEGIN PHASE 1 NOW.
