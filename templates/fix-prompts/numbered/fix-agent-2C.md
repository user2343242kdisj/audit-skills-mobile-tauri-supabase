You are operating as **fix-agent-2C** for the pre-launch remediation of the Travus stack. EXECUTE END-TO-END AUTONOMOUSLY.

CONTEXT
- Working directory: the user's app repo (`~/travus`).
- Source audit: `./audit-reports/00-FINAL.md`, `./audit-reports/06-supabase-auth.md`.
- Output: `./fix-reports/`.
- Mode: `$FIX_MODE` (default `dev`; valid `dev` | `prod` | `dryrun`).
- Note: GoTrue dev branch is the same as prod GoTrue config in Supabase (no per-branch GoTrue). For this agent, "dev" means "verify config + write desired state to report"; "prod" means "PATCH it for real".
- Secrets: 1Password CLI.

═══════════════════════════════════════════════════════════════════
SCOPE
═══════════════════════════════════════════════════════════════════
Single Supabase Management API PATCH on `/v1/projects/<ref>/config/auth` to harden the dormant GoTrue surface. Closes:

| ID | What |
|---|---|
| H-6 | Drop 127.0.0.1 + Vercel-preview wildcards from `uri_allow_list` |
| H-7 | Pin `site_url` to production custom domain |
| H-8 | Harden dormant flags (autoconfirm, password policy, captcha, sessions) |
| M-14 | mailer/phone autoconfirm off |
| M-15 | password_min_length=12 + classes + HIBP |
| M-16 | hCaptcha on |
| M-17 | session timebox + reauth on password change |

OUT OF SCOPE
- Legacy anon/service_role JWT migration (H-18) → fix-agent-2D.
- Clerk-side hardening (TRVS-1433) → not in scope this audit.

═══════════════════════════════════════════════════════════════════
PRE-CONDITIONS
═══════════════════════════════════════════════════════════════════
1. `op://Travus/Supabase - CLI Access Token/credential` resolves to a Management API PAT with project-config write scope.
2. Project ref available (read from `op://Travus/Supabase - Production/server` and parse `db.<ref>.supabase.co`).
3. `MODE=prod` requires `./fix-reports/2C-dev-verified.sentinel`.

═══════════════════════════════════════════════════════════════════
KNOWLEDGE BASE — desired state
═══════════════════════════════════════════════════════════════════

```json
{
  "site_url": "https://travus.finance",
  "uri_allow_list": "https://travus.finance/auth/callback",
  "mailer_autoconfirm": false,
  "phone_autoconfirm": false,
  "password_min_length": 12,
  "password_required_characters": "lower:upper:digit:symbol",
  "password_hibp_enabled": true,
  "security_captcha_enabled": true,
  "security_captcha_provider": "hcaptcha",
  "sessions_timebox": 2592000,
  "sessions_inactivity_timeout": 1209600,
  "security_update_password_require_reauthentication": true
}
```

If `$SITE_URL_OVERRIDE` env is set, use that instead of `https://travus.finance` (e.g. for staging-with-custom-domain).

═══════════════════════════════════════════════════════════════════
WORKFLOW
═══════════════════════════════════════════════════════════════════

**STEP 0 — Resolve secrets, parse project ref, sentinel**
```bash
SBP_TOKEN=$(op read "op://Travus/Supabase - CLI Access Token/credential")
SBP_SERVER=$(op read "op://Travus/Supabase - Production/server")  # e.g. db.abc123.supabase.co
PROJECT_REF=$(echo "$SBP_SERVER" | sed -E 's/^db\.([a-z0-9]+)\.supabase\.co$/\1/')
[ -z "$PROJECT_REF" ] && { echo "BLOCKED: cannot parse project ref from $SBP_SERVER"; exit 1; }

[ "$FIX_MODE" = "prod" ] && {
  test -f ./fix-reports/2C-dev-verified.sentinel \
    || { echo "BLOCKED: dev verification sentinel missing"; exit 1; }
}

API="https://api.supabase.com/v1/projects/$PROJECT_REF/config/auth"
HDR="Authorization: Bearer $SBP_TOKEN"
```

**STEP 1 — GET current config (snapshot)**
```bash
curl -fsSL -H "$HDR" "$API" > /tmp/2C-auth-before.json
```

Capture key fields: `site_url`, `uri_allow_list`, `mailer_autoconfirm`, `phone_autoconfirm`, `password_min_length`, `password_required_characters`, `password_hibp_enabled`, `security_captcha_enabled`, `sessions_timebox`, `sessions_inactivity_timeout`, `security_update_password_require_reauthentication`, `disable_signup`, `external_*_enabled`, `auth.users` count (separate query).

**STEP 2 — Build desired-state payload**

```bash
SITE_URL="${SITE_URL_OVERRIDE:-https://travus.finance}"
cat > /tmp/2C-desired.json <<EOF
{
  "site_url": "$SITE_URL",
  "uri_allow_list": "${SITE_URL}/auth/callback",
  "mailer_autoconfirm": false,
  "phone_autoconfirm": false,
  "password_min_length": 12,
  "password_required_characters": "lower:upper:digit:symbol",
  "password_hibp_enabled": true,
  "security_captcha_enabled": true,
  "security_captcha_provider": "hcaptcha",
  "sessions_timebox": 2592000,
  "sessions_inactivity_timeout": 1209600,
  "security_update_password_require_reauthentication": true
}
EOF
```

**STEP 3 — Diff & dryrun gate**

Compute diff between `/tmp/2C-auth-before.json` and `/tmp/2C-desired.json` (focus on the keys we manage). Write the diff to `./fix-reports/2C-result.md`.

If `MODE=dryrun`, exit `result=DRYRUN`.

If `MODE=dev`, also exit `result=DRYRUN_AS_DEV` (since GoTrue config is single-instance — there's no dev environment to safely test). The "dev" verification is human review of the diff. The user inspects, then runs `MODE=prod`.

Write sentinel after writing the diff (this models "dev verification = user review of the diff in the report").

**STEP 4 — PATCH (MODE=prod only)**

```bash
HTTP_CODE=$(curl -fsSL -o /tmp/2C-patch-resp.json -w "%{http_code}" \
  -X PATCH -H "$HDR" -H "Content-Type: application/json" \
  --data @/tmp/2C-desired.json "$API")
[ "$HTTP_CODE" = "200" ] || { echo "PATCH failed: $HTTP_CODE"; exit 1; }
```

**STEP 5 — Verify**

```bash
curl -fsSL -H "$HDR" "$API" > /tmp/2C-auth-after.json

for k in site_url uri_allow_list mailer_autoconfirm phone_autoconfirm \
         password_min_length password_hibp_enabled \
         security_captcha_enabled \
         sessions_timebox sessions_inactivity_timeout \
         security_update_password_require_reauthentication; do
  before=$(jq -r ".$k" /tmp/2C-auth-before.json)
  after=$(jq  -r ".$k" /tmp/2C-auth-after.json)
  expect=$(jq -r ".$k" /tmp/2C-desired.json)
  [ "$after" = "$expect" ] || echo "MISMATCH: $k → before=$before, after=$after, expected=$expect"
done > /tmp/2C-verify.log
```

**STEP 6 — CI guard recommendation**

Output a snippet for `.github/workflows/auth-config-guard.yml` (do NOT auto-write to the user's repo from this agent — flag for manual addition):
```yaml
on:
  schedule: [{ cron: "17 6 * * *" }]
jobs:
  drift-check:
    steps:
      - run: |
          curl -fsSL -H "Authorization: Bearer $SUPABASE_PAT" \
            "https://api.supabase.com/v1/projects/$REF/config/auth" > /tmp/auth.json
          jq -e '.disable_signup == true and (.external_email_enabled // false) == false' \
            /tmp/auth.json
```

**STEP 7 — Sentinel + report**

`./fix-reports/2C-result.md`:
```
FIX-AGENT-2C RESULT
===================
Mode: dev | prod | dryrun
Result: PASS | FAIL | DRYRUN | DRYRUN_AS_DEV | BLOCKED | PATCH_FAILED | VERIFY_MISMATCH
Project ref: <ref>

GoTrue config diff (managed keys):
  site_url:                                <before>  →  <after>
  uri_allow_list:                          <before>  →  <after>
  mailer_autoconfirm:                      <before>  →  <after>
  phone_autoconfirm:                       <before>  →  <after>
  password_min_length:                     <before>  →  <after>
  password_required_characters:            <before>  →  <after>
  password_hibp_enabled:                   <before>  →  <after>
  security_captcha_enabled:                <before>  →  <after>
  security_captcha_provider:               <before>  →  <after>
  sessions_timebox:                        <before>  →  <after>
  sessions_inactivity_timeout:             <before>  →  <after>
  security_update_password_require_reauthentication: <before>  →  <after>

Other keys observed (informational):
  disable_signup: <value>
  auth.users count: <value>
  external_*_enabled flips to true: <list>

CI guard recommended (do NOT auto-add): .github/workflows/auth-config-guard.yml

Next agent: fix-agent-2D (legacy keys migration) — depends on 2C + 2G.
```

```bash
cat > ./fix-reports/2C-dev-verified.sentinel <<EOF
fix-agent-2C dev verification PASSED at $(date -u +%Y-%m-%dT%H:%M:%SZ)
diff_reviewed: yes
EOF
```

(Write the sentinel only after the user has had a chance to review — model: this fix-agent in MODE=dev produces the diff, and writing the sentinel is the user's signal that they reviewed. If you want stricter, gate on `2C_REVIEWED=1` env var.)

**STEP 8 — Final stdout:**
```
DONE | fix-agent-2C | <mode> | <result> | ./fix-reports/2C-result.md
```

═══════════════════════════════════════════════════════════════════
HARD AUTONOMY RULES
═══════════════════════════════════════════════════════════════════
- NEVER PATCH on MODE=dev (no separate GoTrue env to test against).
- NEVER add to `.github/workflows/` from this agent — flag for manual.
- NEVER print the PAT token. Redact in any logs.
- BEGIN IMMEDIATELY.
