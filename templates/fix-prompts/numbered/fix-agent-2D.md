You are operating as **fix-agent-2D** for the pre-launch remediation of the Travus stack. EXECUTE END-TO-END AUTONOMOUSLY.

CONTEXT
- Working directory: `~/travus`.
- Source audit: `./audit-reports/00-FINAL.md`, `./audit-reports/06-supabase-auth.md` sec REMEDIATION ROADMAP item 4.
- Output: `./fix-reports/`.
- Mode: `$FIX_MODE` (default `dev`; valid `dev` | `prod` | `dryrun`).
- Secrets: 1Password CLI.

═══════════════════════════════════════════════════════════════════
SCOPE
═══════════════════════════════════════════════════════════════════
Migrate Supabase legacy `anon` + `service_role` JWTs to new-format `sb_publishable_*` + `sb_secret_*`. Closes **H-18**.

OUT OF SCOPE
- GoTrue config PATCH (H-6/H-7/H-8) → fix-agent-2C (must run first).
- Other secret rotations (Sentry, FMP, OpenAI, etc.) → fix-agent-2G (run in parallel).

This is a **multi-step migration**, not a single PATCH. Sequence:
1. Generate new keys via Supabase dashboard (manual or Management API if available).
2. Propagate new keys to all consumers (Vercel, EAS, 1Password, EF secrets, GitHub Actions).
3. Ship one release cycle. Monitor for legacy-key traffic (Supabase Logs).
4. Revoke legacy keys.

This agent automates **steps 1-2**, then PAUSES and writes a "wait for clean release cycle" sentinel. A separate `--phase=revoke` invocation does step 4.

═══════════════════════════════════════════════════════════════════
PRE-CONDITIONS
═══════════════════════════════════════════════════════════════════
1. fix-agent-2C landed in prod (`./fix-reports/2C-result.md` shows MODE=prod result=PASS).
2. fix-agent-2G is in flight or done (env-propagation pass benefits from parallelism — but not strictly required).
3. 1Password tokens:
   - `op://Travus/Supabase - CLI Access Token/credential`
   - `op://Travus/Vercel/api_token`
   - `op://Travus/EAS/cli_token`
   - `op://Travus/GitHub/personal_access_token` (for repo secret update)
4. `$PHASE` env var: `propagate` (default) | `revoke`.

═══════════════════════════════════════════════════════════════════
WORKFLOW
═══════════════════════════════════════════════════════════════════

**STEP 0 — Resolve secrets, parse phase**
```bash
PHASE="${PHASE:-propagate}"
SBP_TOKEN=$(op read "op://Travus/Supabase - CLI Access Token/credential")
PROJECT_REF=$(op read "op://Travus/Supabase - Production/server" \
              | sed -E 's/^db\.([a-z0-9]+)\.supabase\.co$/\1/')
```

**STEP 1 — PHASE=propagate**

a) Generate new keys (if not already present in 1Password):
- Check `op item get "Supabase - Production sb_publishable" --vault Travus` → if missing, instruct user to run `supabase gen keys` via dashboard, then write to 1Password manually. Alternatively, attempt:
  ```bash
  curl -fsSL -X POST -H "Authorization: Bearer $SBP_TOKEN" \
    "https://api.supabase.com/v1/projects/$PROJECT_REF/api-keys/rotate" \
    | jq .
  ```
  (API surface may not exist in all plans; if 404, fall back to manual.)

If keys are not retrievable autonomously, write `BLOCKED: generate sb_publishable_* and sb_secret_* via Supabase dashboard, then write to op://Travus/Supabase - Production/{publishable_key,secret_key}` and exit.

b) Resolve target keys:
```bash
NEW_PUB=$(op read "op://Travus/Supabase - Production/publishable_key") || BLOCKED=1
NEW_SEC=$(op read "op://Travus/Supabase - Production/secret_key")      || BLOCKED=1
[ -n "${BLOCKED:-}" ] && { echo "BLOCKED: missing new keys in 1Password"; exit 1; }
```

c) Propagate to **Vercel** (web env):
```bash
VERCEL_TOKEN=$(op read "op://Travus/Vercel/api_token")
PROJECT_ID=$(op read "op://Travus/Vercel/project_id")  # or read from .vercel/project.json
# Update each env var via Vercel API
for var in NEXT_PUBLIC_SUPABASE_ANON_KEY NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY; do
  curl -fsSL -X POST -H "Authorization: Bearer $VERCEL_TOKEN" \
    -H "Content-Type: application/json" \
    "https://api.vercel.com/v10/projects/$PROJECT_ID/env" \
    -d "$(jq -n --arg key "$var" --arg val "$NEW_PUB" \
              '{key:$key,value:$val,target:["production","preview"],type:"encrypted"}')"
done
```
(SECRET keys go separately; never set `NEXT_PUBLIC_*SECRET*`.)

d) Propagate to **EAS** (mobile env):
```bash
EXPO_TOKEN=$(op read "op://Travus/EAS/cli_token")
export EXPO_TOKEN
cd apps/mobile
eas env:create --environment production --name EXPO_PUBLIC_SUPABASE_PUBLISHABLE_KEY \
  --value "$NEW_PUB" --visibility plaintext --non-interactive --force
cd -
```

e) Propagate to **Supabase Edge Function secrets**:
```bash
supabase secrets set \
  SUPABASE_PUBLISHABLE_KEY="$NEW_PUB" \
  SUPABASE_SECRET_KEY="$NEW_SEC" \
  --project-ref "$PROJECT_REF"
```

f) Propagate to **GitHub Actions secrets**:
```bash
GH_TOKEN=$(op read "op://Travus/GitHub/personal_access_token")
gh secret set SUPABASE_PUBLISHABLE_KEY --body "$NEW_PUB" --repo user2343242kdisj/travus
gh secret set SUPABASE_SECRET_KEY      --body "$NEW_SEC" --repo user2343242kdisj/travus
```

g) Update **client code**: search for `EXPO_PUBLIC_SUPABASE_ANON_KEY`, `NEXT_PUBLIC_SUPABASE_ANON_KEY` references; add fallback chain `EXPO_PUBLIC_SUPABASE_PUBLISHABLE_KEY ?? EXPO_PUBLIC_SUPABASE_ANON_KEY` so old env still works during migration. Open a PR.

h) Write sentinel for revoke phase:
```bash
cat > ./fix-reports/2D-propagate-done.sentinel <<EOF
fix-agent-2D PHASE=propagate complete at $(date -u +%Y-%m-%dT%H:%M:%SZ)
new_publishable_key_prefix: $(printf "%.10s" "$NEW_PUB")
new_secret_key_prefix: $(printf "%.10s" "$NEW_SEC")
release_cycle_required: 1
revoke_eligible_after: $(date -u -d '+7 days' +%Y-%m-%dT%H:%M:%SZ)
EOF
```

Exit `result=PROPAGATED` — wait for the user to ship a release cycle and confirm clean traffic.

**STEP 2 — PHASE=revoke**

Pre-condition: `./fix-reports/2D-propagate-done.sentinel` exists AND `revoke_eligible_after` has passed AND user has confirmed clean traffic via `$LEGACY_TRAFFIC_CONFIRMED=clean` env var.

a) Verify clean traffic via Supabase Logs:
```bash
# Last 24h, count requests where the api-key header matches the legacy pattern (eyJhb…).
# If logs API exposes this:
curl -fsSL -H "Authorization: Bearer $SBP_TOKEN" \
  "https://api.supabase.com/v1/projects/$PROJECT_REF/analytics/endpoints/logs.all?…" \
  > /tmp/2D-legacy-traffic.json
LEGACY_HITS=$(jq '...' /tmp/2D-legacy-traffic.json)
[ "$LEGACY_HITS" -eq 0 ] || { echo "BLOCKED: $LEGACY_HITS legacy-key hits in last 24h"; exit 1; }
```

If the logs API is not directly queryable, require `$LEGACY_TRAFFIC_CONFIRMED=clean` env from the user.

b) Revoke legacy keys:
```bash
# Via Supabase Management API (path varies by plan; may need dashboard manual click)
curl -fsSL -X POST -H "Authorization: Bearer $SBP_TOKEN" \
  "https://api.supabase.com/v1/projects/$PROJECT_REF/api-keys/legacy/revoke"
```

If API surface unavailable, write `MANUAL: revoke legacy anon + service_role JWTs in Supabase dashboard → Project Settings → API` and exit.

**STEP 3 — Report**

`./fix-reports/2D-result.md`:
```
FIX-AGENT-2D RESULT
===================
Phase: propagate | revoke
Result: PROPAGATED | REVOKED | BLOCKED | MANUAL_REQUIRED

Phase=propagate (if run):
  new keys generated: yes | no (manual generation required)
  Vercel env updated: yes | no (variables: <list>)
  EAS env updated:   yes | no
  EF secrets updated: yes | no
  GitHub Actions secrets updated: yes | no
  Client code PR: <url or N/A — pending>
  release cycle wait: 7 days minimum

Phase=revoke (if run):
  legacy traffic in last 24h: <count>
  legacy keys revoked: yes | no (manual via dashboard if API unavailable)

Tracking: FIX-15 / TRVS-1432-1433
Next agent: -
```

**STEP 4 — Final stdout:**
```
DONE | fix-agent-2D | <phase> | <result> | ./fix-reports/2D-result.md
```

═══════════════════════════════════════════════════════════════════
HARD AUTONOMY RULES
═══════════════════════════════════════════════════════════════════
- NEVER set a `NEXT_PUBLIC_*SECRET*` or `EXPO_PUBLIC_*SECRET*` env (publishable only on client).
- NEVER revoke legacy keys without sentinel + clean-traffic confirmation.
- NEVER auto-merge the client-code PR.
- NEVER print key values; redact to first 10 chars.
- BEGIN IMMEDIATELY.
