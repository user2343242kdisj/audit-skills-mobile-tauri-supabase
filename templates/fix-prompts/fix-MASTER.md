# Terminal: fix-MASTER (single-terminal end-to-end remediation)

Single prompt that runs the entire pre-launch remediation pipeline against the Travus stack. Dispatches every fix-agent in dependency order via the Agent tool. **One terminal, end-to-end fix sweep.**

For per-fix-agent terminal execution (recommended for production), use `templates/fix-prompts/numbered/fix-agent-<id>.md` directly via `exec-agent`.

## Pre-flight (one-time, in your app repo)

```bash
cd ~/travus

# audit-skills + fix-prompts available (install.sh handles)
test -d ./audit/templates/fix-prompts/ \
  || curl -fsSL https://raw.githubusercontent.com/user2343242kdisj/audit-skills-mobile-tauri-supabase/main/install.sh | bash

# Setup (idempotent)
exec-agent fix-setup.md

# Decisions you must make BEFORE this MASTER runs:
export PRIVACY_MANIFEST_DECISION=B   # A=tracking on; B=AdvertisingData tracking off
export CLI_LOGIN_DECISION=defer       # lockdown | keep | defer
export ROTATION_LIST=supabase_service_role,gcp_firebase   # or "all"
export DAST_TARGET=dev                # dev | prod (5A-bola)
export INSTRUMENTED_DEVICE=android    # ios | android | both (5A-mobile-dynamic)

claude --dangerously-skip-permissions
```

## Paste this entire block into Claude Code

---

You are the **fix-MASTER orchestrator** for the pre-launch remediation pipeline of the Travus stack located at `~/travus`. EXECUTE END-TO-END AUTONOMOUSLY.

CONTEXT
- Working directory: `~/travus`.
- Audit-skills repo: `$AUDIT_SKILLS_PATH` (default `./audit`).
- Source audit: `./audit-reports/00-FINAL.md`.
- Output: `./fix-reports/`.
- Decisions provided via env: `PRIVACY_MANIFEST_DECISION`, `CLI_LOGIN_DECISION`, `ROTATION_LIST`, `DAST_TARGET`, `INSTRUMENTED_DEVICE`.

ARCHITECTURE
- **Phase 1 (BLOCKERS, parallel):** dispatch fix-agent-1A, 1B, 1C in MODE=dev → wait for sentinels → MODE=prod.
- **Phase 2 (HIGH, parallel after Phase 1):** dispatch fix-agent-2A..2H in MODE=dev → MODE=prod (with 2D depending on 2C+2G).
- **Phase 3 (MEDIUM):** dispatch fix-agent-3 in MODE=dev → MODE=prod.
- **Phase 4 (LOW):** dispatch fix-agent-4 in MODE=dev → MODE=prod.
- **Phase 5 (Coverage gaps, parallel with all phases):** dispatch fix-agent-5A-bola, 5A-mobile-platform, 5A-mobile-dynamic, 5A-network, 5A-secrets-rerun.
- **Phase 5B (parallel with all phases):** dispatch fix-agent-5B (new auditors) — runs against `audit-skills` repo, not Travus.
- **Phase 5C (final gate):** dispatch fix-agent-5C after all the above pass — produces GO/NO-GO verdict.

DISPATCH PATTERN
For each phase, use the Agent tool with `subagent_type=general-purpose` and the relevant fix-agent prompt as the message. The fix-agent file lives at `./audit/templates/fix-prompts/numbered/fix-agent-<id>.md` — read it via the Read tool, then pass its full contents as the agent prompt with `FIX_MODE` set appropriately.

WORKFLOW

1. **Pre-flight gate:**
   - Verify `./audit-reports/00-FINAL.md` exists.
   - Verify `./fix-reports/00-fix-setup.md` exists (run by `exec-agent fix-setup.md`).
   - Verify all required env vars are set (`PRIVACY_MANIFEST_DECISION`, `CLI_LOGIN_DECISION`, `ROTATION_LIST`, `DAST_TARGET`, `INSTRUMENTED_DEVICE`).
   - If any prerequisite is missing, BLOCKED + exit.

2. **Phase 1 BLOCKERS — dev (parallel via Agent tool, single message with 3 calls):**
   - fix-agent-1A with `FIX_MODE=dev`
   - fix-agent-1B with `FIX_MODE=dev`
   - fix-agent-1C with `FIX_MODE=dev` + `PRIVACY_MANIFEST_DECISION`
   Wait for all 3. Verify each emits the dev-verified sentinel. If any FAIL, STOP and write the failure summary; do NOT proceed to prod.

3. **Phase 1 BLOCKERS — prod (sequential, with traffic check between):**
   For each of 1A, 1B, 1C:
   - Dispatch with `FIX_MODE=prod`.
   - On result=PASS, monitor live traffic for 5-10 minutes (curl probe + Sentry error rate check). If error rate spike, ROLLBACK isn't supported by these fix-agents — flag as INCIDENT and stop.

4. **Phase 2 HIGH — dev (parallel, 8 agents via Agent tool):**
   - 2A pnpm sweep
   - 2B PL/pgSQL + SECDEF triage
   - 2C GoTrue PATCH
   - 2D legacy keys migration (PHASE=propagate; will defer revoke)
   - 2E Postgres hardening
   - 2F TLS hygiene
   - 2G secret rotation marathon (rotation list per env)
   - 2H GitHub supply chain
   Wait for sentinels. Note: 2D PHASE=propagate completes after 2C; sequence accordingly.

5. **Phase 2 HIGH — prod (sequential where mutation risk; parallel where idempotent):**
   - Sequential prod: 2B (DB), 2C (auth), 2D propagate, 2E (DB).
   - Parallel prod: 2A (PR), 2F (PR), 2G (rotation marathon — already idempotent), 2H (PR + GHAS toggle).

6. **Phase 3 MEDIUM:** fix-agent-3 dev → prod.

7. **Phase 4 LOW:** fix-agent-4 dev → prod.

8. **Phase 5 Coverage gaps (run in parallel with Phase 1+2 as soon as their sentinels land):**
   - 5A-bola (after Phase 1A in prod)
   - 5A-mobile-platform (after Phase 1C in prod, or anytime if mobile native unchanged)
   - 5A-mobile-dynamic (after Phase 1C in prod; only if `INSTRUMENTED_DEVICE != none`)
   - 5A-network (anytime)
   - 5A-secrets-rerun (after Phase 2G done)
   - 5B new auditors (anytime; runs against audit-skills, not Travus — switch context if implementing here)

9. **Phase 5C final gate:** fix-agent-5C, after all the above sentinels exist. Produces `./fix-reports/5C-result.md` with GO/NO-GO.

10. **Synthesize fix-MASTER report:**
    Write `./fix-reports/00-fix-MASTER.md`:
    ```
    FIX-MASTER RESULT
    =================
    Date: <ISO>
    Total fix-agents dispatched: <N>
    Total PASS: <N>
    Total FAIL/BLOCKED: <N>

    Phase 1 (BLOCKERS): <PASS_count>/3
    Phase 2 (HIGH): <PASS_count>/8
    Phase 3 (MEDIUM): <PASS|PARTIAL>
    Phase 4 (LOW): <PASS|PARTIAL>
    Phase 5A (coverage gaps): <PASS_count>/5
    Phase 5B (new auditors): <PASS|FAIL>
    Phase 5C (re-rank): <GO|NO-GO>

    LAUNCH GATE: <GO|NO-GO|BLOCKED>

    Per-agent results (link to each):
    - fix-reports/1A-result.md ... 5C-result.md
    ```

11. **Final stdout:**
    ```
    DONE | fix-MASTER | <GO|NO-GO> | <PASS>/<TOTAL> agents | ./fix-reports/00-fix-MASTER.md
    ```

HARD AUTONOMY RULES
- NEVER promote a fix-agent to MODE=prod without its dev-verified sentinel.
- NEVER skip Phase 5C — that's the launch gate. Without 5C, no GO verdict.
- NEVER continue past a BLOCKED fix-agent — STOP, write the summary, and let the user inspect.
- NEVER auto-merge any PR opened by sub-agents.
- Capture the Phase-1A-prod traffic baseline before promotion; if Sentry error rate exceeds baseline + 20% for 10 minutes, flag INCIDENT.
- BEGIN IMMEDIATELY.
