You are operating as **fix-agent-5A-bola** for the pre-launch remediation of the Travus stack. EXECUTE END-TO-END AUTONOMOUSLY.

CONTEXT
- Working directory: `~/travus`.
- Source audit: `./audit-reports/04-sast-dast.md` (DAST gap section).
- Output: `./fix-reports/`, `./audit-reports/04-sast-dast-rerun.md`.
- Audit-skills repo: `$AUDIT_SKILLS_PATH` (default `./audit`).
- Tools: `./audit/tools/bola-harness.py`, Schemathesis (pip), Docker (optional for ZAP).

═══════════════════════════════════════════════════════════════════
SCOPE
═══════════════════════════════════════════════════════════════════
**Highest-leverage gap closure.** The audit's BOLA harness, Schemathesis, and OWASP ZAP were all SKIPPED — empirical RLS isolation was NEVER proven. This agent stands up the missing prerequisites and re-runs the DAST phase.

| Gap | What |
|---|---|
| BOLA harness | `./audit/tools/bola-harness.py` with two distinct user JWTs |
| Schemathesis | OpenAPI fuzzing as anon + user A |
| OWASP ZAP | active scan against staging URLs |

This agent does NOT modify production code — it only generates evidence (re-runs the audit DAST phase).

═══════════════════════════════════════════════════════════════════
PRE-CONDITIONS
═══════════════════════════════════════════════════════════════════
1. 1Password items required:
   - `op://Travus/Test Users/user_a_jwt`
   - `op://Travus/Test Users/user_b_jwt`
   - `op://Travus/Supabase - Production/anon_key` (or `publishable_key` post-2D)
2. Tools: `python3`, `pip`. Docker is OPTIONAL (only for ZAP).
3. The BOLA harness and Schemathesis are read-only DAST — they hit the live API. Run against **dev branch** if available, NOT production by default. Set `$DAST_TARGET=prod` only if explicitly authorized.

═══════════════════════════════════════════════════════════════════
WORKFLOW
═══════════════════════════════════════════════════════════════════

**STEP 0 — Resolve secrets**

```bash
USER_A_JWT=$(op read "op://Travus/Test Users/user_a_jwt")
USER_B_JWT=$(op read "op://Travus/Test Users/user_b_jwt")
SUPABASE_ANON_KEY=$(op read "op://Travus/Supabase - Production/publishable_key" 2>/dev/null \
                || op read "op://Travus/Supabase - Production/anon_key")
SUPABASE_URL=$(op read "op://Travus/Supabase - Production/url" 2>/dev/null \
            || echo "https://$(op read 'op://Travus/Supabase - Production/server' \
                              | sed -E 's/^db\.([a-z0-9]+)\.supabase\.co$/\1/').supabase.co")
[ -z "$USER_A_JWT$USER_B_JWT$SUPABASE_ANON_KEY" ] && {
  echo "BLOCKED: missing test user JWTs or anon key in 1Password" \
    > ./fix-reports/5A-bola-result.md
  exit 1
}
export USER_A_JWT USER_B_JWT SUPABASE_ANON_KEY SUPABASE_URL
```

**STEP 1 — Install Schemathesis**
```bash
pip install --quiet schemathesis
```

**STEP 2 — Run BOLA harness**

```bash
python3 ./audit/tools/bola-harness.py \
  --base-url "$SUPABASE_URL/rest/v1" \
  --apikey "$SUPABASE_ANON_KEY" \
  --user-a-jwt "$USER_A_JWT" \
  --user-b-jwt "$USER_B_JWT" \
  --output /tmp/5A-bola-out.json \
  --tables posts,messages,transactions,holdings,portfolios,ai_threads,ai_messages,notifications \
  2>&1 | tee /tmp/5A-bola.log
```

Parse `/tmp/5A-bola-out.json`. Each table has cross-user attempt result (status code, row count). Expected: 0 leaks (every cross-user GET returns 0 rows OR 401/403; every cross-user PATCH returns 0 rows updated OR 401/403/404).

**STEP 3 — Run Schemathesis (anon + user A)**

```bash
# fetch OpenAPI from PostgREST root
curl -fsSL "$SUPABASE_URL/rest/v1/" \
  -H "apikey: $SUPABASE_ANON_KEY" -o /tmp/5A-openapi.json

schemathesis run /tmp/5A-openapi.json \
  --base-url "$SUPABASE_URL/rest/v1" \
  --header "apikey: $SUPABASE_ANON_KEY" \
  --checks all --hypothesis-max-examples 100 \
  --report /tmp/5A-schemathesis-anon.json 2>&1 | tee /tmp/5A-schemathesis-anon.log

schemathesis run /tmp/5A-openapi.json \
  --base-url "$SUPABASE_URL/rest/v1" \
  --header "apikey: $SUPABASE_ANON_KEY" \
  --header "Authorization: Bearer $USER_A_JWT" \
  --checks all --hypothesis-max-examples 100 \
  --report /tmp/5A-schemathesis-userA.json 2>&1 | tee /tmp/5A-schemathesis-userA.log
```

**STEP 4 — Run OWASP ZAP (optional)**

If Docker is available:
```bash
docker run --rm -v $(pwd):/zap/wrk:rw -t ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t "$SUPABASE_URL/rest/v1/" \
  -J /zap/wrk/5A-zap.json 2>&1 | tee /tmp/5A-zap.log
```
If Docker is missing, write `ZAP_SKIPPED: Docker not installed` and continue.

**STEP 5 — Synthesize report**

`./audit-reports/04-sast-dast-rerun.md`:
```
DAST RE-RUN (post-fix-agent-1A/1B + key rotation)
=================================================
Date: <ISO>
DAST_TARGET: dev | prod
Test Users: A=<sub_claim>, B=<sub_claim>

BOLA HARNESS RESULTS
--------------------
| Table | Cross-user GET (rows seen) | Cross-user PATCH (rows updated) | Verdict |
|---|---|---|---|
| posts | 0 | 0 | PASS |
| messages | 0 | 0 | PASS |
| transactions | 0 | 0 | PASS |
| ... | | | |

Total tables tested: <N>
Leaks: <count>
Verdict: PASS (0 leaks) | FAIL (<count> leaks at <tables>)

SCHEMATHESIS RESULTS (anon)
---------------------------
Total endpoints fuzzed: <N>
Failures: <count>
Top failures (by severity): <list>

SCHEMATHESIS RESULTS (user A)
-----------------------------
Total endpoints fuzzed: <N>
Failures: <count>
Top failures: <list>
Cross-user reach (user A reading user B data): <0 expected>

ZAP RESULTS (if Docker)
-----------------------
Active findings: <count>
By severity: <breakdown>

REGRESSION VS PRE-FIX BASELINE
------------------------------
- audit-reports/00-FINAL.md noted: BOLA harness skipped, RLS isolation NOT empirically proven.
- This re-run: <PASS / FAIL> empirically proves cross-user isolation.

LAUNCH GATE STATUS
------------------
Pre-launch DAST gate (per fix-prompts/README.md): <PASS / FAIL>
```

**STEP 6 — Sentinel + final report**

```bash
cat > ./fix-reports/5A-bola-dev-verified.sentinel <<EOF
fix-agent-5A-bola PASSED at $(date -u +%Y-%m-%dT%H:%M:%SZ)
target: $DAST_TARGET
bola_leaks: <count>
schemathesis_anon_failures: <count>
schemathesis_userA_failures: <count>
EOF
```

`./fix-reports/5A-bola-result.md`:
```
FIX-AGENT-5A-BOLA RESULT
========================
Mode: dev | prod | dryrun
Result: PASS | FAIL | BLOCKED
Target: dev | prod

BOLA leaks: <count>  (target: 0)
Schemathesis anon failures: <count>
Schemathesis userA failures: <count>
ZAP: PASS | SKIPPED (Docker not installed)

Detailed re-run report: ./audit-reports/04-sast-dast-rerun.md

Launch gate: <PASS / FAIL>
```

**STEP 7 — Final stdout:**
```
DONE | fix-agent-5A-bola | <result> | bola_leaks=<N> | ./fix-reports/5A-bola-result.md
```

═══════════════════════════════════════════════════════════════════
HARD AUTONOMY RULES
═══════════════════════════════════════════════════════════════════
- NEVER run against production unless `$DAST_TARGET=prod` is explicit.
- NEVER print full JWTs — redact to first 12 chars.
- NEVER skip the BOLA harness — that's the empirical RLS proof. ZAP is optional; BOLA is not.
- BEGIN IMMEDIATELY.
