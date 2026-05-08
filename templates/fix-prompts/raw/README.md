# Raw Paste-Text Fix-Prompts

Each `.txt` here is the **bare prompt** — what you paste into Claude Code. The full `.md` files in `../numbered/` contain the prompt PLUS the inline knowledge base, full SQL bodies, full file lists, and hard-autonomy rules.

The raw `.txt` form is a thin wrapper that instructs Claude to read the full prompt from `numbered/`. Use raw when you want:
- Smaller initial paste (the full file is then read via the Read tool).
- Clean, ceremony-free invocation.

Use the full `.md` form (via `exec-agent`) when you want everything resolved up-front.

## Quickest copy

```bash
# Per-fix-agent (one terminal each):
pbcopy < ./audit/templates/fix-prompts/raw/1A-db-catalog-pii-secdef-rls.txt

# Single-terminal master orchestrator:
pbcopy < ./audit/templates/fix-prompts/raw/MASTER.txt
```

Then paste in Claude Code (Cmd+V).

## Files

| File | Phase | What it fixes (audit IDs) |
|---|---|---|
| `setup.txt` | 0 | Prereq checks + scaffold `fix-reports/` |
| `MASTER.txt` | All | Single-terminal end-to-end (dispatches all fix-agents in dependency order) |
| `1A-db-catalog-pii-secdef-rls.txt` | 1 BLOCKER | C-1 + C-2 + C-4 + H-5 + H-10 + M-12 + M-13 |
| `1B-pg-partman-schema.txt` | 1 BLOCKER | C-3 (pg_partman → extensions) |
| `1C-mobile-native.txt` | 1 BLOCKER | C-5 release keystore + H-14 App Attest + H-15 Privacy Manifest |
| `2A-deps-sweep.txt` | 2 HIGH | H-1 lodash + M-1..M-7 + L-1 |
| `2B-plpgsql-secdef-triage.txt` | 2 HIGH | H-3 (10 PL/pgSQL) + H-4 (123 SECDEF triage) |
| `2C-gotrue-mgmt-patch.txt` | 2 HIGH | H-6 + H-7 + H-8 + M-14..M-17 (single PATCH) |
| `2D-legacy-keys-migration.txt` | 2 HIGH | H-18 (sb_publishable_*/sb_secret_*) |
| `2E-postgres-hardening.txt` | 2 HIGH | H-9 pgaudit + H-11 cli_login + M-23 + M-24 |
| `2F-tls-hygiene.txt` | 2 HIGH | H-12 + H-13 + M-26 + L-6 |
| `2G-secrets-rotation.txt` | 2 HIGH | H-16 + H-17 + Sentry/FMP/OpenAI/Notion/MCP/Sonar |
| `2H-github-supply-chain.txt` | 2 HIGH | H-2 download-artifact + H-19 GHAS |
| `3-mediums.txt` | 3 MEDIUM | M-9 + M-10 + M-11 + M-18..M-22 + M-25 + pgTAP + Semgrep |
| `4-lows.txt` | 4 LOW | L-2..L-11 (L-1, L-6 covered earlier) |
| `5A-bola.txt` | 5 GAP | BOLA harness + Schemathesis re-run (highest-leverage gap) |
| `5A-mobile-platform.txt` | 5 GAP | mobile-deeplinks + mobile-storage-crypto re-run |
| `5A-mobile-dynamic.txt` | 5 GAP | Frida + Burp + 14-mobile-dynamic re-run |
| `5A-network.txt` | 5 GAP | testssl + Network Restrictions re-run |
| `5A-secrets-rerun.txt` | 5 GAP | ggshield + trufflehog --only-verified re-run |
| `5B-new-auditors.txt` | 5 GAP | Add 5 new audit agents to audit-skills (webhook, api-bola, auth-rate-limit, ai-prompt, ota-supply) |
| `5C-rerank-dread.txt` | 5 GATE | Re-rank top-15 DREAD; produce GO/NO-GO verdict |

## Per-terminal workflow (recommended)

```bash
# One terminal per fix-agent. Phase 1 BLOCKERS first (parallel terminals OK):
# Terminal 1:
FIX_MODE=dev exec-agent 1A-db-catalog-pii-secdef-rls.txt
# Terminal 2:
FIX_MODE=dev exec-agent 1B-pg-partman-schema.txt
# Terminal 3:
FIX_MODE=dev PRIVACY_MANIFEST_DECISION=B exec-agent 1C-mobile-native.txt

# Review fix-reports/1A-result.md, 1B-result.md, 1C-result.md
# Then promote each to prod (sequential is safer):
FIX_MODE=prod exec-agent 1A-db-catalog-pii-secdef-rls.txt
# ... etc.

# Once Phase 1 is in prod, fan out Phase 2 across 8 terminals…
```

## Single-terminal workflow

```bash
pbcopy < MASTER.txt   # paste into a single Claude Code terminal
# Make sure all decision env vars are exported beforehand.
```
