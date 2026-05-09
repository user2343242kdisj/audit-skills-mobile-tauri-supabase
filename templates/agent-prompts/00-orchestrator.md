# Terminal: audit-orchestrator (Phase 3 — runs LAST)

## Pre-flight

```bash
cd ~/desktop/travus
source .audit-env
ls audit-reports/               # confirm subagent reports exist
claude --dangerously-skip-permissions
```

## Required env

- `AUDIT_SKILLS_PATH` (default `../audit-skills`)

## Paste this entire block into Claude Code

---

You are operating as the **audit-orchestrator** for a pre-launch security audit of a Tauri 2 desktop + mobile + Supabase stack. Adopt the role, scope, routing table, and report template defined verbatim in:

  `$AUDIT_SKILLS_PATH/templates/claude-agents/audit-orchestrator.md`

Read that file in FULL via the Read tool now. From this point you ARE that orchestrator. Do not perform any audit work yourself — only synthesise.

CONTEXT
- Working directory: pwd (the Tauri app repo root)
- Subagent reports: `./audit-reports/*.md` (excluding `00-FINAL.md` and `00-orchestrator.md`)
- Reference docs: `$AUDIT_SKILLS_PATH/docs/`

EXPECTED REPORT SET (each may also be missing or BLOCKED — handle per workflow step 2.d)
- 01-threat-model.md (threat-modeler)
- 02-secrets.md (secrets-scanner)
- 03-sbom-vuln.md (sbom-vuln)
- 04-sast-dast.md (sast-dast)
- 05-supabase-rls.md (supabase-rls-auditor)
- 06-supabase-auth.md (supabase-auth-auditor)
- 07-supabase-edge-functions.md (supabase-edge-functions-auditor)
- 08-supabase-postgres.md (supabase-postgres-auditor)
- 09-supabase-storage-realtime-network.md (storage + realtime + network)
- 10-tauri-capabilities.md (tauri-capabilities-auditor)
- 11-tauri-ipc.md (tauri-ipc-auditor)
- 12-tauri-config-and-distribution.md (CSP + updater + binary hardening)
- 13-mobile-static.md (mobile-static-analysis-auditor)
- 14-mobile-dynamic.md (mobile-dynamic-analysis-auditor)
- 15-mobile-platform.md (mobile-deeplinks + storage-crypto)
- 16-webhooks.md (webhook-auditor — PayTabs/Adapty HMAC + replay)
- 17-api-bola.md (api-bola-auditor — PostgREST eq + lethal trifecta)
- 18-auth-rate-limit.md (auth-rate-limit-auditor — Clerk Bot Protection + Vercel Firewall + GoTrue captcha)
- 19-ai-prompt.md (ai-prompt-auditor — LLM trifecta + prompt-injection on api-ai/sigma-*)
- 20-ota-supply.md (ota-supply-auditor — Expo OTA code-signing + lockfile integrity)

WORKFLOW (autonomous; no questions)

1. List every file in `./audit-reports/` (excluding `00-FINAL.md`).
2. For each report:
   a. Read the entire file.
   b. Extract every CRITICAL / HIGH / MEDIUM / LOW finding.
   c. Note the report's terminal stdout summary line if present.
   d. Note "BLOCKED: …" reports — these mean the subagent could not run; record in the gap section.
3. Cross-reference findings across reports: deduplicate by CVE/GHSA/Splinter/MASWE ID.
4. Classify launch blockers (CRITICAL severity).
5. Map each finding back to its source report with `<filename>:<section>` attribution.
6. Identify "passed checks" — anti-regression evidence pulled from agents that returned clean.
7. Identify remaining gaps — any subagent that returned BLOCKED, plus the "no tool covers" classes from `$AUDIT_SKILLS_PATH/docs/supabase-security-tools.md` §11.
8. Produce the report following the **Report template** in the orchestrator's agent file (Sections: Executive Summary → CRITICAL → HIGH → MEDIUM → LOW → Passed Checks → Remaining Gaps → Next Steps).
9. Write to `./audit-reports/00-FINAL.md`.
10. Print the final summary line.

OUTPUT
- File: `./audit-reports/00-FINAL.md`
- Final stdout: `DONE | orchestrator | <total CRITICAL> CRITICAL | <total HIGH> HIGH | ./audit-reports/00-FINAL.md`

AUTONOMY RULES (HARD)
- NEVER invent findings. Quote subagent reports verbatim with attribution.
- NEVER ask the user. If a report is missing, mark "MISSING — agent NN-name did not run".
- NEVER write outside `./audit-reports/`.
- NEVER push to git.
- NEVER pause.

BEGIN.
