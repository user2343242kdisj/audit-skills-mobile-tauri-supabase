You are operating as **fix-agent-5C** for the pre-launch remediation of the Travus stack. EXECUTE END-TO-END AUTONOMOUSLY.

CONTEXT
- Working directory: `~/travus`.
- Audit-skills repo: `$AUDIT_SKILLS_PATH` (default `./audit`).
- Source: `./audit-reports/01-threat-model.md` (original DREAD ranking).
- Output: `./fix-reports/`, `./audit-reports/01-threat-model-rerun.md`, `./audit-reports/00-FINAL-rerun.md`.

═══════════════════════════════════════════════════════════════════
SCOPE
═══════════════════════════════════════════════════════════════════

Re-rank top-15 DREAD threats after Phase 1-5 remediations. Validates the **launch readiness gate**:

1. Re-run the threat-modeler (`agent-1.md`) with updated mitigation evidence.
2. Dispatch the 5 new auditors from fix-agent-5B against the live stack.
3. Re-run the orchestrator-synthesis (`agent-16.md`) to produce a refreshed `00-FINAL-rerun.md`.
4. Compare top-5 DREAD ranks before vs after; declare launch ready iff:
   - 0 CRITICAL findings
   - 0 HIGH findings on rank-1..5 threats
   - BOLA empirically PASS (from fix-agent-5A-bola)
   - Mobile-platform + mobile-dynamic re-runs PASS

═══════════════════════════════════════════════════════════════════
PRE-CONDITIONS
═══════════════════════════════════════════════════════════════════
1. fix-agent-5A-bola PASS (`./fix-reports/5A-bola-result.md`).
2. fix-agent-5A-mobile-platform PASS.
3. fix-agent-5A-mobile-dynamic PASS.
4. fix-agent-5B merged into audit-skills (`$AUDIT_SKILLS_PATH/templates/claude-agents/{webhook,api-bola,auth-rate-limit,ai-prompt,ota-supply}-auditor.md` exist).
5. Phase 1 + Phase 2 fix-agents all in MODE=prod result=PASS.

═══════════════════════════════════════════════════════════════════
WORKFLOW
═══════════════════════════════════════════════════════════════════

**STEP 0 — Verify pre-conditions**
```bash
for sentinel in 5A-bola-dev-verified 5A-mobile-platform-dev-verified 5A-mobile-dynamic-dev-verified; do
  test -f "./fix-reports/$sentinel.sentinel" \
    || { echo "BLOCKED: missing sentinel $sentinel" > ./fix-reports/5C-result.md; exit 1; }
done

for new_agent in webhook api-bola auth-rate-limit ai-prompt ota-supply; do
  test -f "$AUDIT_SKILLS_PATH/templates/claude-agents/${new_agent}-auditor.md" \
    || { echo "BLOCKED: $new_agent-auditor.md not in audit-skills"; exit 1; }
done

# Phase 1 + Phase 2 prod-PASS
for fa in 1A 1B 1C 2A 2B 2C 2D 2E 2F 2G 2H; do
  grep -E "Mode: prod" ./fix-reports/$fa-result.md 2>/dev/null \
    | grep -q "Result: PASS" \
    || { echo "BLOCKED: fix-agent-$fa not prod-PASS"; exit 1; }
done
```

**STEP 1 — Re-run threat-modeler (agent-1)**

```bash
exec-agent agent-1.md
```
This writes `./audit-reports/01-threat-model-rerun.md` (or overwrites the original — back it up first):
```bash
cp ./audit-reports/01-threat-model.md ./audit-reports/01-threat-model.original.md
```

The threat-modeler should now reflect the post-remediation state (e.g., E2.4 service_role JWT leaked drops from rank 1 → rank N because catalog grants are revoked + rotation done; etc.).

**STEP 2 — Dispatch the 5 new auditors**

```bash
exec-agent agent-17.md   # webhook-auditor
exec-agent agent-18.md   # api-bola-auditor
exec-agent agent-19.md   # auth-rate-limit-auditor
exec-agent agent-20.md   # ai-prompt-auditor
exec-agent agent-21.md   # ota-supply-auditor
```

These produce `./audit-reports/{16,17,18,19,20}-*.md` (numbering per fix-agent-5B's assignments).

If any of the 5 produces CRITICAL or HIGH findings on rank-1..5 threats, the launch gate FAILS — that's the point of this re-run.

**STEP 3 — Re-run orchestrator-synthesis**

```bash
exec-agent agent-16.md
```

This synthesizes everything into `./audit-reports/00-FINAL-rerun.md`. Compare against the original `00-FINAL.md`:
```bash
diff -u ./audit-reports/00-FINAL.md ./audit-reports/00-FINAL-rerun.md \
  > ./fix-reports/5C-final-diff.txt
```

**STEP 4 — Re-rank delta analysis**

Parse both threat models (original + re-run). For each of the original top-15 threats, capture:
- Original DREAD score and rank
- Original linkage (CRITICAL/HIGH/uncovered)
- Re-run DREAD score and rank
- Re-run linkage
- Verdict: MITIGATED | DOWN-RANKED | UNCHANGED | UP-RANKED

Write to `./fix-reports/5C-rerank.md`:
```
DREAD RE-RANK (post-remediation)
================================

| Original Rank | Threat ID | Original Score | Re-run Score | Re-run Rank | Verdict |
|---|---|---|---|---|---|
| 1 | E2.4 service_role JWT leaked | 9.5 | <X> | <N> | MITIGATED (catalog grants revoked + key rotated) |
| 2 | E2.1 RLS-off public-schema   | 9.0 | <X> | <N> | UNCHANGED (PASSED in original; preserved) |
| 3 | E5.1 PayTabs HMAC weak        | 8.5 | <X> | <N> | <verdict; depends on webhook-auditor finding> |
| 4 | E3.3 MCP lethal trifecta     | 8.5 | <X> | <N> | <verdict; depends on api-bola-auditor> |
| 5 | E1.3 Clerk Bot Protection    | 8.5 | <X> | <N> | <verdict; depends on auth-rate-limit-auditor> |
| ... | ... | ... | ... | ... | ... |

LAUNCH READINESS GATE
- top-5 DREAD threats with HIGH+ findings: <count>     (gate: 0)
- BOLA empirical PASS: yes | no                         (gate: yes)
- Mobile-platform CRITICAL/HIGH: <count>                 (gate: 0)
- Mobile-dynamic CRITICAL/HIGH: <count>                  (gate: 0)
- Phase 1 BLOCKERS prod-PASS: <count>/5                  (gate: 5/5)
- Phase 2 HIGH prod-PASS: <count>/19                     (gate: 19/19)

VERDICT: GO | NO-GO

If NO-GO, the still-open issues are:
- <list>
```

**STEP 5 — Sentinel + report**

```bash
cat > ./fix-reports/5C-dev-verified.sentinel <<EOF
fix-agent-5C PASSED at $(date -u +%Y-%m-%dT%H:%M:%SZ)
verdict: <GO | NO-GO>
EOF
```

`./fix-reports/5C-result.md`:
```
FIX-AGENT-5C RESULT
===================
Result: GO | NO-GO | BLOCKED

Re-run reports:
- ./audit-reports/01-threat-model-rerun.md  (DREAD re-rank)
- ./audit-reports/16-webhooks.md            (new)
- ./audit-reports/17-api-bola.md            (new)
- ./audit-reports/18-auth-rate-limit.md     (new)
- ./audit-reports/19-ai-prompt.md           (new)
- ./audit-reports/20-ota-supply.md          (new)
- ./audit-reports/00-FINAL-rerun.md         (synthesis)

Diff vs original 00-FINAL: ./fix-reports/5C-final-diff.txt

Re-rank summary: ./fix-reports/5C-rerank.md

Top-5 DREAD threats with open HIGH+ findings: <count>
Verdict: <GO | NO-GO>

If GO: stack is launch-ready per the gate. Ship it.
If NO-GO: see "still-open issues" in 5C-rerank.md.
```

**STEP 6 — Final stdout:**
```
DONE | fix-agent-5C | <verdict> | open=<N> | ./fix-reports/5C-result.md
```

═══════════════════════════════════════════════════════════════════
HARD AUTONOMY RULES
═══════════════════════════════════════════════════════════════════
- NEVER declare GO if any sentinel pre-condition is missing.
- NEVER edit the audit reports directly — only synthesize / diff.
- If the re-run finds a new CRITICAL not in the original audit, write `EMERGENCY: new CRITICAL — <description>` and verdict NO-GO.
- BEGIN IMMEDIATELY.
