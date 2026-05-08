You are operating as **fix-agent-2G** for the pre-launch remediation of the Travus stack. EXECUTE END-TO-END AUTONOMOUSLY.

CONTEXT
- Working directory: `~/travus`.
- Source audit: `./audit-reports/00-FINAL.md`, `./audit-reports/02-secrets-scan.md`.
- Output: `./fix-reports/`.
- Mode: `$FIX_MODE` (default `dev`; valid `dev` | `prod` | `dryrun`).
- Secrets: 1Password CLI.

═══════════════════════════════════════════════════════════════════
SCOPE
═══════════════════════════════════════════════════════════════════

Secret rotation marathon — rotate every secret with confirmed or suspected exposure, propagate to all consumers, then revoke old keys.

| ID | What |
|---|---|
| H-16 | Supabase `service_role` JWT (commit 9e2c9335) |
| H-17 | GCP/Firebase service-account (commits 9f458da9, daf55640) |
| extras | Sentry org token + auth token, FMP keys (×2), OpenAI keys (×2), Notion tokens (×8), Context7/Upstash MCP keys (×6), SonarCloud token |

This is **NOT a single transaction** — it's a sequenced checklist. The agent processes one secret at a time, each with its own:
1. Generate new value at provider.
2. Store in 1Password.
3. Propagate to consumers (Vercel, EAS, EF secrets, GitHub Actions, local `.env.local`).
4. Smoke test.
5. Revoke old at provider.

`$ROTATION_LIST` env var: comma-separated subset to rotate this run. Default: `supabase_service_role,gcp_firebase`. To run the full marathon: `ROTATION_LIST=all`.

═══════════════════════════════════════════════════════════════════
PRE-CONDITIONS
═══════════════════════════════════════════════════════════════════
1. 1Password unlocked.
2. Provider credentials in 1Password (admin tokens for each provider).
3. `MODE=prod` requires `./fix-reports/2G-dev-verified.sentinel` per-secret OR `--force=<secret_id>` for emergencies.

═══════════════════════════════════════════════════════════════════
KNOWLEDGE BASE — rotation playbook per secret
═══════════════════════════════════════════════════════════════════

Each entry: `(id, generate_command_or_url, propagate_targets, smoke_test, revoke_command_or_url)`

| id | generate | targets | smoke | revoke |
|---|---|---|---|---|
| `supabase_service_role` | Supabase dashboard → API → Reset service_role | Vercel, EAS, EF secrets, GH Actions, 1P | curl EF with new key returns 200 | dashboard auto-revokes old on reset |
| `gcp_firebase` | GCP Console → IAM → SA → Keys → Add key | Vercel (FIREBASE_*), EAS, EF secrets, 1P | Firebase Admin SDK init succeeds | delete old key in console |
| `sentry_org` | sentry.io → Settings → Auth Tokens → Create | GH Actions (SENTRY_AUTH_TOKEN), 1P | sentry-cli releases list works | revoke old token in UI |
| `sentry_auth` | sentry.io → User Settings → Auth Tokens | EAS, GH Actions, 1P | release deploy hook fires | revoke old token |
| `fmp_*` | financialmodelingprep.com dashboard | EF secrets (FMP_KEY, FMP_KEY_BACKUP), 1P | curl FMP /quote endpoint | regenerate replaces old |
| `openai_*` | platform.openai.com | EF secrets (OPENAI_KEY, OPENAI_KEY_FALLBACK), 1P | OpenAI completions returns 200 | revoke old in dashboard |
| `notion_*` | notion.so/my-integrations (8 integrations) | varies (likely admin tools), 1P | Notion API users.me returns 200 | revoke old in integration page |
| `context7_*`, `upstash_*` | provider dashboards (6 keys) | EF secrets / MCP server config, 1P | provider-specific | revoke old |
| `sonarcloud` | sonarcloud.io → My Account → Security | GH Actions (SONAR_TOKEN), 1P | sonar-scanner authenticates | revoke old in UI |

For most providers, this agent **cannot fully automate** generation (interactive dashboards). It will:
1. Print "MANUAL: generate <secret> at <URL>; write new value to 1Password at <path>".
2. Wait for the user to confirm via env `READY_TO_PROPAGATE_<secret_id>=1`.
3. Auto-propagate to consumers via API.
4. Print "MANUAL: revoke old <secret> at <URL>".

═══════════════════════════════════════════════════════════════════
WORKFLOW
═══════════════════════════════════════════════════════════════════

**STEP 0 — Parse rotation list, expand "all"**

```bash
case "${ROTATION_LIST:-supabase_service_role,gcp_firebase}" in
  all) ROTATION_LIST="supabase_service_role,gcp_firebase,sentry_org,sentry_auth,fmp_primary,fmp_backup,openai_primary,openai_fallback,notion_1,notion_2,notion_3,notion_4,notion_5,notion_6,notion_7,notion_8,context7_1,context7_2,upstash_1,upstash_2,upstash_3,upstash_4,sonarcloud" ;;
esac
IFS=',' read -ra SECRETS <<<"$ROTATION_LIST"
```

**STEP 1 — Iterate per secret**

For each `secret_id` in the list:

a) Look up the playbook entry above. Print:
```
ROTATING: <secret_id>
  Generate at: <URL or command>
  Then write new value to: op://Travus/<path>
  When ready, set env: READY_TO_PROPAGATE_<secret_id>=1
```

b) If `READY_TO_PROPAGATE_<secret_id>` is not "1", skip and write "PENDING" in the report. Continue with next secret.

c) Else, propagate. Use `op read` to fetch the new value:
```bash
NEW=$(op read "op://Travus/$(playbook_path "$secret_id")")
```

d) Push to each consumer:

```bash
case "$secret_id" in
  supabase_service_role)
    # Vercel
    upsert_vercel_env SUPABASE_SERVICE_ROLE_KEY "$NEW" production preview
    # EAS  (only if mobile uses it — typically NOT; mobile must never have service_role)
    # EF secrets
    supabase secrets set SUPABASE_SERVICE_ROLE_KEY="$NEW" --project-ref "$PROJECT_REF"
    # GitHub Actions
    gh secret set SUPABASE_SERVICE_ROLE_KEY --body "$NEW" --repo user2343242kdisj/travus
    ;;
  gcp_firebase)
    # Firebase service-account JSON — base64-encode for env var
    NEW_B64=$(echo -n "$NEW" | base64 -w0)
    upsert_vercel_env FIREBASE_SERVICE_ACCOUNT_KEY "$NEW_B64" production preview
    eas env:create --environment production --name FIREBASE_SERVICE_ACCOUNT_KEY \
      --value "$NEW_B64" --visibility sensitive --non-interactive --force
    supabase secrets set FIREBASE_SERVICE_ACCOUNT_KEY="$NEW_B64" --project-ref "$PROJECT_REF"
    gh secret set FIREBASE_SERVICE_ACCOUNT_KEY --body "$NEW_B64" --repo user2343242kdisj/travus
    ;;
  # ... per-secret cases
esac
```

(`upsert_vercel_env` is a helper — define inline that uses Vercel API to create-or-update an env variable for the listed targets.)

e) Smoke test:
```bash
case "$secret_id" in
  supabase_service_role)
    curl -fsSL -H "Authorization: Bearer $NEW" \
      "https://$PROJECT_REF.supabase.co/rest/v1/?select=" >/dev/null \
      || SMOKE_FAILED=1
    ;;
  # ...
esac
```

f) Print "MANUAL: revoke old <secret_id> at <URL>" and write to report.

**STEP 2 — Update audit log**

Maintain `./fix-reports/2G-rotation-log.md` with one row per secret:
```
| Secret | Status | Propagated to | Smoke | Old revoked at | Date |
```

**STEP 3 — Re-run secrets scanner**

After all rotations done:
```bash
brew uninstall trufflehog 2>/dev/null; brew install trufflehog ggshield 2>/dev/null
ggshield secret scan repo . > /tmp/2G-ggshield.log 2>&1 || true
trufflehog git file://. --only-verified > /tmp/2G-trufflehog.log 2>&1 || true
```

Verified-secret hits should be 0 (they were 2 — H-16 + H-17 — and may persist as historical-only after rotation if not removed from history; flag in the report).

**STEP 4 — Sentinel + report**

```bash
cat > ./fix-reports/2G-dev-verified.sentinel <<EOF
fix-agent-2G dev verification PASSED at $(date -u +%Y-%m-%dT%H:%M:%SZ)
secrets_rotated: <count>
verified_secrets_in_repo_after: <count from trufflehog --only-verified>
EOF
```

`./fix-reports/2G-result.md`:
```
FIX-AGENT-2G RESULT
===================
Mode: dev | prod | dryrun
Result: PASS | PARTIAL | BLOCKED

Rotation summary:
| Secret | Status | Propagated | Smoke | Old revoked | Date |
|---|---|---|---|---|---|
| supabase_service_role | DONE | yes | PASS | yes | <ts> |
| gcp_firebase           | PENDING | — | — | — | — |
...

Re-scan after rotation:
  ggshield: <verified count>
  trufflehog --only-verified: <verified count>

Manual steps still required:
- <list URLs/dashboards for un-rotated secrets>

Next agent: fix-agent-2D PHASE=revoke (after release cycle).
```

**STEP 5 — Final stdout:**
```
DONE | fix-agent-2G | <mode> | <done>/<total> rotated | ./fix-reports/2G-result.md
```

═══════════════════════════════════════════════════════════════════
HARD AUTONOMY RULES
═══════════════════════════════════════════════════════════════════
- NEVER print full secret values; truncate to first 10 chars + "...REDACTED".
- NEVER push `service_role` JWT or `secret_key` to any client-facing env (NEXT_PUBLIC_*, EXPO_PUBLIC_*).
- NEVER auto-revoke old keys — print MANUAL with the dashboard URL and let the user click.
- NEVER continue a rotation if smoke fails — STOP, report, and let the user roll back.
- BEGIN IMMEDIATELY.
