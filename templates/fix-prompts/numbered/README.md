# Numbered Fix-Agents — `exec-agent fix-agent-NX.md` UX

Numbered, paste-direct **remediation** prompts. Mirrors `templates/agent-prompts/numbered/` but for write operations (DB migrations, file edits, Management-API PATCHes, secret rotations) instead of read-only audits.

Each terminal runs one command:

```
exec-agent fix-agent-1A.md
```

The `exec` script (in `templates/agent-prompts/numbered/exec`) searches both audit and fix prompt directories.

## Layout (after `install.sh`)

```
~/travus/
├── audit-reports/                 ← input: 00-FINAL.md (must exist)
├── fix-reports/                   ← output: NX-result.md per fix-agent
├── audit/                         ← cloned audit-skills (gitignored)
│   ├── templates/agent-prompts/numbered/{agent-0..16, exec}     (audit)
│   └── templates/fix-prompts/numbered/{fix-agent-*.md, README.md}  (this dir)
└── .gitignore                     ← contains audit/, audit-reports/, fix-reports/
```

## Files in this directory

| File | Phase | Closes (audit finding IDs) | Lines |
|---|---|---|---|
| `fix-setup.md` | 0 | (prereq scaffolding) | ~110 |
| `fix-agent-1A.md` | 1 BLOCKER | C-1 + C-2 + C-4 + H-5 + H-10 + M-12 + M-13 | ~290 |
| `fix-agent-1B.md` | 1 BLOCKER | C-3 | ~140 |
| `fix-agent-1C.md` | 1 BLOCKER | C-5 + H-14 + H-15 | ~220 |
| `fix-agent-2A.md` | 2 HIGH | H-1 + M-1..M-7 + L-1 | ~140 |
| `fix-agent-2B.md` | 2 HIGH | H-3 + H-4 | ~190 |
| `fix-agent-2C.md` | 2 HIGH | H-6 + H-7 + H-8 + M-14..M-17 | ~170 |
| `fix-agent-2D.md` | 2 HIGH | H-18 | ~170 |
| `fix-agent-2E.md` | 2 HIGH | H-9 + H-11 + M-23 + M-24 | ~150 |
| `fix-agent-2F.md` | 2 HIGH | H-12 + H-13 + M-26 + L-6 | ~120 |
| `fix-agent-2G.md` | 2 HIGH | H-16 + H-17 + Sentry/FMP/OpenAI/Notion/MCP/Sonar | ~190 |
| `fix-agent-2H.md` | 2 HIGH | H-2 + H-19 | ~120 |
| `fix-agent-3.md` | 3 MEDIUM | M-9..M-22 + M-25 + pgTAP + Semgrep tighten | ~260 |
| `fix-agent-4.md` | 4 LOW | L-2..L-11 | ~190 |
| `fix-agent-5A-bola.md` | 5 GAP | DAST + RLS isolation proof | ~150 |
| `fix-agent-5A-mobile-platform.md` | 5 GAP | deeplinks + storage-crypto re-run | ~140 |
| `fix-agent-5A-mobile-dynamic.md` | 5 GAP | Frida + Burp re-run | ~140 |
| `fix-agent-5A-network.md` | 5 GAP | testssl + Network Restrictions re-run | ~140 |
| `fix-agent-5A-secrets-rerun.md` | 5 GAP | ggshield + trufflehog re-scan | ~140 |
| `fix-agent-5B.md` | 5 GAP | Add 5 new audit agents to audit-skills | ~190 |
| `fix-agent-5C.md` | 5 GATE | Re-rank top-15 DREAD; GO/NO-GO verdict | ~150 |

## `$FIX_MODE` — dev-first safety

```
dev     Apply to dev branch / staging; verify; on success write fix-reports/NX-dev-verified.sentinel
prod    Require sentinel; apply to production; verify
dryrun  Generate the change but apply nothing (review only)
```

Every fix-agent is invoked at least twice in the normal workflow:

```bash
FIX_MODE=dev   exec-agent fix-agent-1A.md
# review fix-reports/1A-result.md
FIX_MODE=prod  exec-agent fix-agent-1A.md
```

## Per-fix-agent decision env vars

| Env var | Required by | Values |
|---|---|---|
| `FIX_MODE` | all | `dev` (default) / `prod` / `dryrun` |
| `PRIVACY_MANIFEST_DECISION` | 1C | `A` (tracking on) / `B` (AdvertisingData tracking off) |
| `CLI_LOGIN_DECISION` | 2E | `lockdown` / `keep` / `defer` (default) |
| `ROTATION_LIST` | 2G | comma-separated subset, or `all` |
| `PHASE` | 2D | `propagate` (default) / `revoke` |
| `LEGAL_BUCKET_DECISION` | 3 | `private` (default) / `cdn` |
| `LEGACY_TRAFFIC_CONFIRMED` | 2D revoke | `clean` |
| `DAST_TARGET` | 5A-bola | `dev` (default) / `prod` |
| `INSTRUMENTED_DEVICE` | 5A-mobile-dynamic | `ios` / `android` / `both` |
| `SUPABASE_CA_PATH` | 2F | path to root CA bundle |
| `SITE_URL_OVERRIDE` | 2C | custom site_url for staging |

## Dependency order

```
Phase 1 — parallel:           1A, 1B, 1C
Phase 2 — parallel after 1:   2A, 2B (after 1A), 2C, 2E (after 1A), 2F, 2H
                              2G in parallel; 2D after 2C+2G
Phase 3 — after Phase 2:      3
Phase 4 — after Phase 3:      4
Phase 5 — parallel with all:  5A-bola (after 1A prod)
                              5A-mobile-platform (after 1C prod)
                              5A-mobile-dynamic (after 1C prod)
                              5A-network (anytime)
                              5A-secrets-rerun (after 2G)
                              5B (anytime — runs in audit-skills repo)
Phase 5C — final gate:        5C (after 5A-bola, 5A-mobile-*, all phase 1+2 prod-PASS)
```

## Launch readiness gate

```
GO iff:
  ✅ Phase 1 BLOCKERS prod-PASS = 3/3
  ✅ Phase 2 HIGH prod-PASS = 8/8
  ✅ 5A-bola PASS (0 leaks)
  ✅ 5A-mobile-platform 0 CRITICAL/HIGH
  ✅ 5A-mobile-dynamic 0 CRITICAL/HIGH
  ✅ 5C re-rank: 0 HIGH+ findings on top-5 DREAD threats
```

Phase 3, 4, and 5B are NOT launch gates — they may close post-launch with tickets.
