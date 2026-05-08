# Fix-Prompts — One Agent Per Terminal Remediation Workflow

Numbered, paste-direct prompts that **apply** the remediations identified by the audit (`audit-reports/00-FINAL.md`). Each terminal runs one command:

```
exec-agent fix-agent-1A.md
```

Mirrors the audit `templates/agent-prompts/` layout but for **write** operations. Each fix-agent is scoped to a single atomic deliverable (one DB migration, one PR, one Management-API PATCH, one secret rotation, one re-run).

## Layout

```
~/travus/                                ← your app repo (or ~/desktop/travus)
├── audit-reports/                       ← input: 00-FINAL.md from the audit
├── fix-reports/                         ← output: per-fix-agent NX-result.md
├── audit/                               ← cloned audit-skills (gitignored)
│   ├── templates/agent-prompts/numbered/{agent-0…16, exec}     ← audit prompts
│   ├── templates/fix-prompts/numbered/{fix-agent-*.md, exec}   ← fix prompts (this dir)
│   ├── templates/fix-prompts/raw/                              ← bare paste-text variants
│   └── tools/
└── .gitignore                           ← contains audit/, audit-reports/, fix-reports/
```

The fix-prompts share the same `exec` wrapper as the audit prompts (the script searches both `agent-prompts/numbered/` and `fix-prompts/numbered/`).

## Conventions

Every fix-agent follows the same shape:

1. **Persona** — "You are operating as the **fix-agent-NX** for the pre-launch remediation of …"
2. **Context** — working dir, audit-skills path, secrets via 1Password CLI, `$FIX_MODE`
3. **Scope** — finding IDs covered (e.g. `C-1, C-2, C-4, H-5, H-10, M-12, M-13`); explicit out-of-scope
4. **Pre-conditions** — sentinel files, env vars, audit-report presence
5. **Knowledge base** — exact remediation knowledge inlined (full SQL, full file paths, full classifications). Self-contained — no external file reads required.
6. **Workflow** — numbered, autonomous; pre-flight → generate → dev-apply → verify → write sentinel → (prod-apply) → verify → write report
7. **Output** — `./fix-reports/NX-<slug>.md` and a single-line stdout summary
8. **Hard autonomy rules** — when to STOP, what NOT to touch, how to handle BLOCKED states

## `$FIX_MODE` — dev-first safety

Every fix-agent honours `$FIX_MODE` (default `dev`). The agent:

| MODE | Behaviour |
|---|---|
| `dev` | Apply to dev branch / staging; run verification; on success write `./fix-reports/NX-dev-verified.sentinel`; STOP. Default. |
| `prod` | Require sentinel from prior `dev` run; apply to production; run post-deploy verification; report. |
| `dryrun` | Generate the change (migration file, diff, PATCH body) but apply nothing. Useful for review. |

This means each fix-agent is invoked **at least twice** in the normal workflow:

```bash
FIX_MODE=dev   exec-agent fix-agent-1A.md   # generate + dev-apply + verify
# review ./fix-reports/1A-result.md
FIX_MODE=prod  exec-agent fix-agent-1A.md   # prod-apply + verify
```

## Dependency map

```
Phase 1 (BLOCKERS) — parallel:
  1A: DB migration A (C-1+C-2+C-4+H-5+H-10+M-12+M-13)
  1B: pg_partman move (C-3)
  1C: Mobile native (C-5+H-14+H-15)

Phase 2 (HIGH) — parallel after Phase 1:
  2A: pnpm sweep (H-1 + M-1..M-7 + L-1)
  2B: DB migration C — PL/pgSQL + SECDEF triage (H-3+H-4)
  2C: GoTrue Mgmt-API PATCH (H-6+H-7+H-8+M-14..M-17)
  2D: Legacy keys migration (H-18) [needs 2C+2G done]
  2E: Postgres hardening (H-9+H-11+M-23+M-24)
  2F: TLS hygiene (H-12+H-13+M-26+L-6)
  2G: Secret rotation marathon (H-16+H-17 + extras)
  2H: GitHub supply chain (H-2+H-19)

Phase 3 (MEDIUM) — after Phase 2:
  3:  Standalone MEDIUMs (M-9, M-10, M-11, M-18..M-22, M-25, pgTAP, Semgrep)

Phase 4 (LOW) — after Phase 3:
  4:  Backlog batch (L-2..L-11; L-1 resolved by 2A)

Phase 5 (Coverage gaps) — parallel with all phases:
  5A-bola:            BOLA harness + Schemathesis re-run
  5A-mobile-platform: deeplinks + storage-crypto re-run
  5A-mobile-dynamic:  Frida-instrumented re-run
  5A-network:         testssl + Network Restrictions re-run
  5A-secrets-rerun:   ggshield + trufflehog re-run
  5B:                 Add 5 new auditor prompts to audit-skills/templates/claude-agents/
  5C:                 Re-run threat-model + re-rank top-15 DREAD
```

## Required 1Password items

Same as the audit prompts, plus:

| Path | Used by |
|---|---|
| `op://Travus/Supabase - Production/connection_string` | 1A, 1B, 2B, 2E, 5A-bola |
| `op://Travus/Supabase - Dev Branch/connection_string` | 1A, 1B, 2B, 2E (MODE=dev) |
| `op://Travus/Supabase - CLI Access Token/credential` | 2C, 2D, 2E |
| `op://Travus/Supabase - Service Role/legacy` | 2D (rotation) |
| `op://Travus/Vercel/api_token` | 2D, 2G |
| `op://Travus/EAS/cli_token` | 1C, 2D, 2G |
| `op://Travus/GitHub/personal_access_token` | 2H, 5B |
| `op://Travus/GCP/service_account_admin_key` | 2G |
| `op://Travus/Sentry/org_token`, `auth_token` | 2G |
| `op://Travus/Apple Developer/asc_api_key` | 1C, 5A-mobile-dynamic |
| `op://Travus/1Password Service Account/token` | optional, for 1Password write-back |

## Launch readiness gate

A launch is **ready** only when:

- [ ] All Phase 1 fix-agents reported `result=PASS` in MODE=prod
- [ ] All Phase 2 fix-agents reported `result=PASS` in MODE=prod
- [ ] `5A-bola` empirically proved cross-user RLS isolation (0 leaks across posts/messages/transactions/holdings/portfolios/ai_threads/notifications)
- [ ] `5A-mobile-platform` and `5A-mobile-dynamic` re-runs show 0 CRITICAL / 0 HIGH
- [ ] `5C` re-rank shows top-5 DREAD threats either mitigated or down-ranked

Phase 3, Phase 4, and Phase 5B may close post-launch with tracked tickets.

## Cheat sheet

```bash
# One-time (in your app repo):
cd ~/travus
curl -fsSL https://raw.githubusercontent.com/user2343242kdisj/audit-skills-mobile-tauri-supabase/main/install.sh | bash
exec-agent fix-setup.md          # bootstraps fix-reports/ + verifies prereqs

# Start with BLOCKERS:
FIX_MODE=dev  exec-agent fix-agent-1A.md && \
FIX_MODE=dev  exec-agent fix-agent-1B.md && \
FIX_MODE=dev  exec-agent fix-agent-1C.md
# review fix-reports/1A-result.md, 1B-result.md, 1C-result.md

# Promote to prod (one at a time, with traffic monitoring between):
FIX_MODE=prod exec-agent fix-agent-1A.md
FIX_MODE=prod exec-agent fix-agent-1B.md
FIX_MODE=prod exec-agent fix-agent-1C.md

# Continue with HIGH in parallel terminals:
# Terminal A:  FIX_MODE=dev exec-agent fix-agent-2A.md  &&  FIX_MODE=prod exec-agent fix-agent-2A.md
# Terminal B:  FIX_MODE=dev exec-agent fix-agent-2B.md  &&  FIX_MODE=prod exec-agent fix-agent-2B.md
# … etc
```

For a single-terminal end-to-end run, paste `fix-MASTER.md` instead — it dispatches all fix-agents in dependency order via the Agent tool.
