You are operating as **fix-agent-5A-network** for the pre-launch remediation of the Travus stack. EXECUTE END-TO-END AUTONOMOUSLY.

CONTEXT
- Working directory: `~/travus`.
- Audit-skills repo: `$AUDIT_SKILLS_PATH` (default `./audit`).
- Source audit: `./audit-reports/09-supabase-storage-realtime-network.md` (steps 10/11/12 SKIPPED — Docker; steps 13/14 NOT-AVAILABLE — SUPABASE_ACCESS_TOKEN).
- Output: `./fix-reports/`, `./audit-reports/10-supabase-network.md`.

═══════════════════════════════════════════════════════════════════
SCOPE
═══════════════════════════════════════════════════════════════════
Re-run network DAST that was skipped in the original audit:

| Skip | What |
|---|---|
| testssl on API endpoint | `https://<ref>.supabase.co/rest/v1/` |
| testssl on db endpoint | `db.<ref>.supabase.co:5432` |
| testssl on pooler | `aws-0-eu-west-1.pooler.supabase.com:6543` |
| Network Restrictions | GET `/v1/projects/<ref>/network-restrictions` |
| Region/plan checks | GET `/v1/projects/<ref>` |

═══════════════════════════════════════════════════════════════════
PRE-CONDITIONS
═══════════════════════════════════════════════════════════════════
1. Docker available (or local `testssl.sh` install).
2. 1Password: `op://Travus/Supabase - CLI Access Token/credential` (Management API PAT).
3. Project ref derivable from `op://Travus/Supabase - Production/server`.

═══════════════════════════════════════════════════════════════════
WORKFLOW
═══════════════════════════════════════════════════════════════════

**STEP 0 — Resolve secrets, derive endpoints**
```bash
SBP_TOKEN=$(op read "op://Travus/Supabase - CLI Access Token/credential")
SBP_SERVER=$(op read "op://Travus/Supabase - Production/server")
PROJECT_REF=$(echo "$SBP_SERVER" | sed -E 's/^db\.([a-z0-9]+)\.supabase\.co$/\1/')
API_HOST="$PROJECT_REF.supabase.co"
DB_HOST="$SBP_SERVER"  # db.<ref>.supabase.co
POOLER_HOST="aws-0-eu-west-1.pooler.supabase.com"   # confirm region from project info
```

Fallback if `op read` fails on the PAT: `Network Restrictions + region checks SKIPPED`.

**STEP 1 — testssl on API**

If Docker:
```bash
docker run --rm -t drwetter/testssl.sh:3.2 \
  --color 0 --quiet --severity HIGH \
  "https://$API_HOST/rest/v1/" > /tmp/5A-network-api.txt
```

If `testssl.sh` is on PATH:
```bash
testssl.sh --color 0 --quiet --severity HIGH \
  "https://$API_HOST/rest/v1/" > /tmp/5A-network-api.txt
```

Extract HIGH+ findings (TLS 1.0/1.1 enabled, weak ciphers, missing HSTS, etc.).

**STEP 2 — testssl on db endpoint (5432)**

Postgres uses STARTTLS; testssl supports it via `--starttls postgres`:
```bash
docker run --rm -t drwetter/testssl.sh:3.2 \
  --starttls postgres --color 0 --quiet --severity HIGH \
  "$DB_HOST:5432" > /tmp/5A-network-db.txt
```

Even though direct DB access from public Internet is rate-limited / IP-restricted on Supabase, the chain check is still useful.

**STEP 3 — testssl on pooler (6543)**

```bash
docker run --rm -t drwetter/testssl.sh:3.2 \
  --starttls postgres --color 0 --quiet --severity HIGH \
  "$POOLER_HOST:6543" > /tmp/5A-network-pooler.txt
```

**STEP 4 — Network Restrictions via Management API**

```bash
[ -n "$SBP_TOKEN" ] && {
  curl -fsSL -H "Authorization: Bearer $SBP_TOKEN" \
    "https://api.supabase.com/v1/projects/$PROJECT_REF/network-restrictions" \
    > /tmp/5A-network-restrictions.json
  curl -fsSL -H "Authorization: Bearer $SBP_TOKEN" \
    "https://api.supabase.com/v1/projects/$PROJECT_REF" \
    > /tmp/5A-network-project.json
}
```

Parse: `region`, `subscription_tier`, `db_postgres_version`, network restrictions count + IP allow-list.

**STEP 5 — Synthesize**

`./audit-reports/10-supabase-network.md`:
```
SUPABASE NETWORK AUDIT (re-run)
===============================
Date: <ISO>

ENDPOINT: https://<ref>.supabase.co/rest/v1/ (API)
- TLS versions: <list>          target: TLS 1.2+ only
- HSTS: <max-age value>         target: max-age >= 31536000
- HIGH-severity findings: <list>

ENDPOINT: db.<ref>.supabase.co:5432 (DB direct)
- TLS versions:
- HIGH-severity findings:

ENDPOINT: aws-0-eu-west-1.pooler.supabase.com:6543 (pooler)
- TLS versions:
- HIGH-severity findings:

NETWORK RESTRICTIONS
- enabled: <yes | no>
- IP allow-list: <count>; entries: <list>
- recommendation: enable + restrict to Vercel IP ranges + EAS build runners

PROJECT
- region: <region>
- plan: <Free | Pro | Team | Enterprise>
- pg_version: <17.6>
- pooler enabled: <yes | no>

RECOMMENDATIONS
- <list of any HIGH/MEDIUM findings>

LAUNCH GATE
- PASS | FAIL
```

**STEP 6 — Sentinel + report**

```bash
cat > ./fix-reports/5A-network-dev-verified.sentinel <<EOF
fix-agent-5A-network PASSED at $(date -u +%Y-%m-%dT%H:%M:%SZ)
high_findings: <N>
EOF
```

`./fix-reports/5A-network-result.md`:
```
FIX-AGENT-5A-NETWORK RESULT
===========================
Result: PASS | FAIL | BLOCKED | DOCKER_MISSING
HIGH findings on TLS endpoints: <N>
Network restrictions enabled: yes | no
Detailed report: ./audit-reports/10-supabase-network.md
```

**STEP 7 — Final stdout:**
```
DONE | fix-agent-5A-network | <result> | high=<N> | ./fix-reports/5A-network-result.md
```

═══════════════════════════════════════════════════════════════════
HARD AUTONOMY RULES
═══════════════════════════════════════════════════════════════════
- NEVER attempt active scans (vuln scanner) — testssl is passive.
- If Docker AND testssl.sh are both missing, BLOCKED with installation instructions.
- BEGIN IMMEDIATELY.
