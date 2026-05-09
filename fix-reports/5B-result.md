FIX-AGENT-5B RESULT
===================
Mode: prod
Result: PASS

Closes coverage gaps in `audit-reports/00-FINAL.md` REMAINING GAPS section by adding 5 new audit agents to the Travus pre-launch audit pipeline.

## Threat-model coverage closed

| Agent | Threat-model items |
|---|---|
| `webhook-auditor` | E5.1 PayTabs HMAC (rank 3) + E5.2 Adapty replay/idempotency (rank 14) |
| `api-bola-auditor` | E3.3 MCP lethal trifecta (rank 4) + E2.3 BOLA via PostgREST `eq` (rank 15) |
| `auth-rate-limit-auditor` | E1.3 Clerk Bot Protection + Vercel Firewall (rank 5; TRVS-1433) |
| `ai-prompt-auditor` | LLM trifecta + prompt-injection on api-ai/sigma-* (OWASP LLM Top 10) |
| `ota-supply-auditor` | E8.2 OTA code-signing OFF — manifest hijack (rank 13) |

## New agents added

| File | Lines | Smoke-test |
|---|---|---|
| templates/claude-agents/webhook-auditor.md | 161 | yes |
| templates/claude-agents/api-bola-auditor.md | 196 | yes |
| templates/claude-agents/auth-rate-limit-auditor.md | 172 | yes |
| templates/claude-agents/ai-prompt-auditor.md | 183 | yes |
| templates/claude-agents/ota-supply-auditor.md | 172 | yes |

## New numbered prompts

`templates/agent-prompts/numbered/agent-17.md` (webhook), `agent-18.md` (api-bola), `agent-19.md` (auth-rate-limit), `agent-20.md` (ai-prompt), `agent-21.md` (ota-supply). Each is self-contained (knowledge + workflow inlined) and mirrors the agent-5.md canonical structure.

## New raw prompts

`templates/agent-prompts/raw/17-webhooks.txt`, `18-api-bola.txt`, `19-auth-rate-limit.txt`, `20-ai-prompt.txt`, `21-ota-supply.txt`. Bare paste-text variants that reference `templates/claude-agents/<name>-auditor.md`.

## Numbering scheme

- agent-16.md remains the synthesis-only orchestrator (Phase 3).
- numbered/agent-17.md..agent-21.md are the 5 new Phase-2 agents.
- Their report files continue from 15-mobile-platform.md → 16-webhooks.md, 17-api-bola.md, 18-auth-rate-limit.md, 19-ai-prompt.md, 20-ota-supply.md.
- Raw filenames keep the agent number (17-21).
- This minor offset is documented inline in MASTER.md and templates/agent-prompts/README.md.

## Orchestrator updates

| File | Change |
|---|---|
| `templates/agent-prompts/00-orchestrator.md` | Added expected-report-set listing 16-20 |
| `templates/agent-prompts/MASTER.md` | Phase 2 fan-out now lists 19 subagents (was 14) with the 5 new entries + numbering note |
| `templates/agent-prompts/numbered/agent-16.md` | Synthesis input list extended with 16-webhooks.md..20-ota-supply.md; routing reference table extended |
| `templates/agent-prompts/setup.md` | `.audit-env` scaffolds CLERK_SECRET_KEY, VERCEL_TOKEN, VERCEL_PROJECT_ID (for agent-19) |
| `templates/agent-prompts/numbered/agent-0.md` | 1Password required-paths list extended with `op://Travus/Clerk/admin_api_key`, `op://Travus/Vercel/firewall_token`, `op://Travus/Vercel/project_id` |
| `templates/claude-agents/audit-orchestrator.md` | Routing table + Phase 3 + Phase 4 fan-out updated |
| `templates/claude-agents/README.md` | Hierarchy updated to 26 agents (was 21) |
| `templates/agent-prompts/README.md` | Counts updated; new entries added |

## index.json

Not modified. `index.json` is the registry of `skills/<name>` directories (68 entries — `tools/validate-skill.py --all` → 68/68 PASS, unchanged). The 5 new files live under `templates/claude-agents/` and `templates/agent-prompts/`, which are the agent-prompt registry — not the skill registry. Adding template files to a `skills/` index would create invalid metadata. `tools/validate-skill.py` does not auto-regenerate `index.json` from templates.

## Smoke test

```
templates/claude-agents/webhook-auditor.md           161 lines   ok
templates/claude-agents/api-bola-auditor.md          196 lines   ok
templates/claude-agents/auth-rate-limit-auditor.md   172 lines   ok
templates/claude-agents/ai-prompt-auditor.md         183 lines   ok
templates/claude-agents/ota-supply-auditor.md        172 lines   ok
templates/agent-prompts/numbered/agent-17.md         184 lines   ok
templates/agent-prompts/numbered/agent-18.md         222 lines   ok
templates/agent-prompts/numbered/agent-19.md         195 lines   ok
templates/agent-prompts/numbered/agent-20.md         193 lines   ok
templates/agent-prompts/numbered/agent-21.md         186 lines   ok
templates/agent-prompts/raw/17-webhooks.txt           56 lines   ok
templates/agent-prompts/raw/18-api-bola.txt           68 lines   ok
templates/agent-prompts/raw/19-auth-rate-limit.txt    55 lines   ok
templates/agent-prompts/raw/20-ai-prompt.txt          64 lines   ok
templates/agent-prompts/raw/21-ota-supply.txt         75 lines   ok
tools/validate-skill.py --all                        68/68 PASS  ok
```

PR: https://github.com/user2343242kdisj/audit-skills-mobile-tauri-supabase/pull/1

Next agent: fix-agent-5C (re-run threat model + re-rank top-15 DREAD).
