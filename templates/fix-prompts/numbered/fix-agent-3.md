You are operating as **fix-agent-3** for the pre-launch remediation of the Travus stack. EXECUTE END-TO-END AUTONOMOUSLY.

CONTEXT
- Working directory: `~/travus`.
- Source audit: `./audit-reports/00-FINAL.md`.
- Output: `./fix-reports/`.
- Mode: `$FIX_MODE` (default `dev`; valid `dev` | `prod` | `dryrun`).
- Secrets: 1Password CLI.

═══════════════════════════════════════════════════════════════════
SCOPE
═══════════════════════════════════════════════════════════════════

Standalone MEDIUMs not bundled into Phase 1/2:

| ID | What | Domain |
|---|---|---|
| M-9 | Confirm `get-legal-document` EF runs HTML through `sanitize-html >=2.17.3`; add if missing | Web/EF |
| M-10 | Flip `legal-documents` Storage bucket private + signed URLs (or CDN+CSP) | Storage |
| M-11 | Narrow `app_config_read_authenticated` policy to documented allowlist | DB/RLS |
| M-18 | `BackgroundFetchTask.ts:398` createClient auth options (persistSession=false, etc.) | Mobile |
| M-19 | Set `ADAPTY_STRICT_HMAC=1` in prod EF env | EF env |
| M-20 | Drop `Bearer ${SUPABASE_SERVICE_ROLE_KEY}` compare path in `send-policy-update-email` | EF |
| M-21 | Replace raw `err.message` with `errorResponse('Internal error', 500)` in 2 EF routes | EF |
| M-22 | Replace module-scoped `createClient` in `integrity-agent` with `_shared/supabaseAdmin.createServiceClient()` | EF |
| M-25 | Tighten `travusfinance://` deeplink scheme — add android:host or pathPattern | Mobile |
| pgTAP | Generate scaffolds for 8 highest-value tables × 3 personas × 4 actions | DB |
| Semgrep | Tighten `error-leaked-to-client` + `no-manual-jwt-verify` rules (FP rate 100%) | Tools |

`MODE=dev`: apply all eligible edits + lint + typecheck. `MODE=prod`: open PR(s).

═══════════════════════════════════════════════════════════════════
PRE-CONDITIONS
═══════════════════════════════════════════════════════════════════
1. Phase 2 fix-agents landed where applicable (specifically 2A for sanitize-html bump).
2. Working tree clean.
3. `MODE=prod` requires `./fix-reports/3-dev-verified.sentinel`.

═══════════════════════════════════════════════════════════════════
WORKFLOW (iterate; one section per finding)
═══════════════════════════════════════════════════════════════════

For each finding, follow the inner pattern: read → edit → test. Track a per-finding result code in `/tmp/3-status.tsv`.

**M-9 — sanitize-html on legal pages**

```bash
# Inspect both legal pages
grep -nE "dangerouslySetInnerHTML" \
  apps/web/src/app/\[locale\]/privacy-policy/page.tsx \
  apps/web/src/app/\[locale\]/terms-of-service/page.tsx

# Inspect get-legal-document EF for sanitization
grep -nE "sanitize-html|sanitize\(|DOMPurify" supabase/functions/get-legal-document/
```

If sanitization is **already** present in the EF (or DB trigger that populates `legal_documents.content_html`) and uses `>=2.17.3`, mark M-9 as NOOP.

Otherwise, add to the EF (preferred — sanitize once at write or fetch boundary):
```ts
import sanitizeHtml from "npm:sanitize-html@^2.17.3";

// In the EF response builder:
const safe = sanitizeHtml(rawHtml, { allowedTags: sanitizeHtml.defaults.allowedTags, allowedAttributes: { "*": ["class", "id", "href", "title"] } });
return jsonResponse({ content_html: safe });
```

**M-10 — legal-documents bucket private**

Decision branch on `$LEGAL_BUCKET_DECISION`:
- `private`: flip bucket to private + change client to use `createSignedUrl(900)`.
- `cdn`: keep public but front via Vercel/CDN with strong CSP (more work; leave as MANUAL).
- default `private`.

Migration:
```sql
update storage.buckets set public = false where id = 'legal-documents';
```

Client change: search `apps/web/src/app/[locale]/{privacy-policy,terms-of-service}/page.tsx` for `getPublicUrl` on this bucket; replace with `createSignedUrl(path, 900)`.

**M-11 — app_config_read_authenticated narrow**

```sql
-- Inspect the keys actually consumed by authed clients (search apps/{mobile,web}/src for app_config keys)
-- Add allowlist similar to anon policy:
alter policy app_config_read_authenticated on system.app_config
  using (key in ('legal','onboarding_config','launchConfig','appGates','demoContent','welcome_enabled',
                 '<other-keys-actually-needed-by-authed-clients>'));
```

Generate the migration file in `./supabase/migrations/`. The agent must derive the allowlist by searching `apps/` for `app_config` reads and intersecting with the table's actual keys.

**M-18 — BackgroundFetchTask createClient**

```diff
- // apps/mobile/src/services/bundledData/BackgroundFetchTask.ts:398
- const sb = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);
+ const sb = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
+   auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
+ });
```

Also append to `apps/mobile/scripts/guard-conventions.sh` (or wherever the convention guard lives — search):
```bash
# Forbid bare createClient(url, key) — must include auth options that disable session persistence
git ls-files 'apps/mobile/src/**/*.ts' 'apps/mobile/src/**/*.tsx' \
  | xargs grep -l 'createClient(' \
  | xargs grep -L "persistSession" \
  | grep -v -E '__tests__|\.test\.tsx?$' \
  | tee /dev/stderr | { read -r line && [ -n "$line" ] && exit 1 || exit 0; }
```

**M-19 — ADAPTY_STRICT_HMAC=1**

```bash
supabase secrets set ADAPTY_STRICT_HMAC=1 --project-ref "$PROJECT_REF"
```

Verify:
```bash
supabase secrets list --project-ref "$PROJECT_REF" | grep -i ADAPTY_STRICT_HMAC
```

**M-20 — send-policy-update-email cleanup**

Read `supabase/functions/send-policy-update-email/index.ts`. Locate lines 84-89 (the `constantTimeEqual(authHeader, "Bearer ${serviceRoleKey}")` check). Remove that branch entirely; keep only `validateSchedulerAuth`.

```diff
- if (constantTimeEqual(authHeader, `Bearer ${serviceRoleKey}`)) { /* ... */ }
- ...
- await validateSchedulerAuth(...);
+ await validateSchedulerAuth(...);
```

**M-21 — errorResponse cleanup**

Two files:
- `supabase/functions/api-market/routes/insiderTrading.ts:122`
- `supabase/functions/analyze-transactions/sessionActionTypes.ts:37`

```diff
- return c.json({ error: err instanceof Error ? err.message : 'Internal error' }, 500);
+ logger.error('insiderTrading error', { err });
+ return errorResponse('Internal error', 500);
```

```diff
- return forwardedErrorResponse({ error: err.message }, ...);
+ logger.error('analyze-transactions session error', { err });
+ return errorResponse('Internal error', 500);
```

Verify the `errorResponse` and `logger` are imported (likely from `_shared/`).

**M-22 — integrity-agent module-scoped createClient**

Three files:
- `supabase/functions/integrity-agent/adapters/supabaseDatabase.ts:29,35`
- `supabase/functions/integrity-agent/adapters/clerkAuth.ts:21`

```diff
- const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);
+ // moved into request handler; uses the rotation-friendly singleton
+ import { createServiceClient } from "../../_shared/supabaseAdmin.ts";
+ // ... inside handler:
+ const supabase = createServiceClient();
```

Inspect `_shared/supabaseAdmin.ts` to confirm `createServiceClient()` exists and returns a request-scoped client. If not, BLOCKED.

**M-25 — deeplink scheme tightening**

Read `apps/mobile/android/app/src/main/AndroidManifest.xml`. Find the MainActivity intent-filter for `travusfinance` scheme. Add `android:host` or `android:pathPattern` to scope the schema:

```xml
<intent-filter android:autoVerify="true">
  <action android:name="android.intent.action.VIEW" />
  <category android:name="android.intent.category.DEFAULT" />
  <category android:name="android.intent.category.BROWSABLE" />
  <data android:scheme="travusfinance"
        android:host="open" />            <!-- restrict to travusfinance://open/* -->
</intent-filter>
```

Then ensure JS router validates origin/state token. Search `apps/mobile/src/` for the deeplink handler (likely `Linking.addEventListener` or expo-router) and confirm validation. If missing, FLAG in report (do NOT auto-add — risk of breaking existing flows).

**pgTAP scaffolds**

Generate one test file per high-value table at `supabase/tests/<schema>_<table>.test.sql`:
- `user.users`
- `portfolio.transactions`
- `portfolio.portfolios`
- `portfolio.holdings`
- `ai.ai_threads`
- `ai.ai_messages`
- `billing.subscriptions`
- `billing.paytabs_transactions`

Pattern (use basejump helpers per agent-5.md knowledge base):
```sql
begin;
select plan(12);

select tests.create_supabase_user('alice');
select tests.create_supabase_user('bob');

-- Setup: insert one row owned by alice, one by bob
-- ...

-- alice sees her row only (SELECT)
select tests.authenticate_as('alice');
select results_eq(...);

-- alice cannot SELECT bob's row
select results_eq(...);

-- alice cannot UPDATE bob's row
select throws_ok(...);

-- alice cannot INSERT a row pointing at bob
select throws_ok(...);

-- anon cannot SELECT
select tests.clear_authentication();
select results_eq(...);

-- (12 assertions covering 3 personas × 4 actions, with edge cases)

select * from finish();
rollback;
```

The full bodies require knowing each table's columns. This agent generates **stubs** — runs once, dies on the first assertion needing real column names. The user fills in details. Stub generation: replace `<column_list>` placeholders with `select column_name from information_schema.columns where table_schema=:s and table_name=:t order by ordinal_position`.

**Semgrep tighten**

Read `tools/semgrep-edge-functions.yml`. The two rules:
- `error-leaked-to-client` — current FP rate 100% (per audit). Tighten to match only `c.json({ error: err.message }, 500)` style with `err.message` literal in the response. Exclude `errorResponse(...)` calls.
- `no-manual-jwt-verify` — current FP rate 100%. Tighten to match only manual `jwt.verify` or `JSON.parse(atob(...))` patterns, exclude `verifyClerkJwt` calls.

```yaml
# proposed tighter rule (sketch — actual YAML in tools/semgrep-edge-functions.yml)
- id: error-leaked-to-client-strict
  pattern-either:
    - pattern: c.json({ error: $ERR.message }, 500)
    - pattern: c.json({ error: $ERR }, 500)
  pattern-not-inside: |
    function $F(...) { ... errorResponse(...) ... }
  message: "Raw err.message returned to client — use errorResponse()"
  severity: WARNING
```

Push as a separate PR; do NOT bundle with code fixes (separates concerns).

═══════════════════════════════════════════════════════════════════
WORKFLOW (outer)
═══════════════════════════════════════════════════════════════════

**STEP 0 — Resolve secrets, sentinel**
```bash
PROJECT_REF=$(op read "op://Travus/Supabase - Production/server" \
              | sed -E 's/^db\.([a-z0-9]+)\.supabase\.co$/\1/')
[ "$FIX_MODE" = "prod" ] && {
  test -f ./fix-reports/3-dev-verified.sentinel || { echo "BLOCKED"; exit 1; }
}
```

**STEP 1 — Iterate findings**

For each finding (M-9, M-10, M-11, M-18, M-19, M-20, M-21, M-22, M-25, pgTAP, Semgrep):
1. Run the per-finding logic (above).
2. Capture result: `PASS | NOOP | FAIL | SKIPPED | MANUAL`.
3. Append to `/tmp/3-status.tsv`:
   ```
   <id>\t<result>\t<details>
   ```

**STEP 2 — Lint + typecheck**

```bash
pnpm tsc --noEmit 2>&1 | tee /tmp/3-tsc.log
pnpm lint           2>&1 | tee /tmp/3-lint.log
deno check supabase/functions/**/*.ts 2>&1 | tee /tmp/3-deno.log
```

**STEP 3 — Open PRs (MODE=prod)**

Group by domain:
- PR-1 EF: M-19, M-20, M-21, M-22
- PR-2 Web/Storage: M-9, M-10
- PR-3 DB: M-11 + pgTAP scaffolds (might be split)
- PR-4 Mobile: M-18, M-25
- PR-5 Tools: Semgrep tighten

Use `gh pr create` per group with the relevant body excerpt from `./fix-reports/3-result.md`.

**STEP 4 — Sentinel + report**

```bash
cat > ./fix-reports/3-dev-verified.sentinel <<EOF
fix-agent-3 dev verification PASSED at $(date -u +%Y-%m-%dT%H:%M:%SZ)
findings_resolved: <count>/11
EOF
```

`./fix-reports/3-result.md`:
```
FIX-AGENT-3 RESULT
==================
Mode: dev | prod | dryrun
Result: PASS | PARTIAL | BLOCKED

Per-finding:
| ID | Result | Notes |
|---|---|---|
| M-9 | PASS | Sanitization in get-legal-document EF; sanitize-html ^2.17.3 |
| M-10 | PASS | bucket private; client uses createSignedUrl(900) |
| M-11 | PASS | allowlist of <N> keys; migration: <file> |
| M-18 | PASS | BackgroundFetchTask + guard-conventions.sh |
| M-19 | PASS | ADAPTY_STRICT_HMAC=1 set in EF env |
| M-20 | PASS | bearer branch removed |
| M-21 | PASS | both routes use errorResponse() |
| M-22 | PASS | integrity-agent uses createServiceClient() |
| M-25 | PARTIAL | manifest tightened; JS router validation FLAGGED for review |
| pgTAP | STUB | 8 stubs created at supabase/tests/; user fills in column lists |
| Semgrep | PASS | rules tightened; new FP rate <flagged in TSC log> |

PRs (MODE=prod): <list URLs>

Next agent: fix-agent-4 (LOW backlog).
```

**STEP 5 — Final stdout:**
```
DONE | fix-agent-3 | <mode> | <pass>/<total> | ./fix-reports/3-result.md
```

═══════════════════════════════════════════════════════════════════
HARD AUTONOMY RULES
═══════════════════════════════════════════════════════════════════
- NEVER auto-edit deeplink JS router code (M-25) — flag for review.
- NEVER fill in pgTAP column-specific assertions — generate stubs only.
- NEVER auto-merge PRs.
- BEGIN IMMEDIATELY.
