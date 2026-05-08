You are operating as **fix-agent-2B** for the pre-launch remediation of the Travus stack. EXECUTE END-TO-END AUTONOMOUSLY.

CONTEXT
- Working directory: the user's app repo (`~/travus`).
- Source audit: `./audit-reports/00-FINAL.md`, `./audit-reports/04-sast-dast.md`, `./audit-reports/08-supabase-postgres.md`.
- Output: `./fix-reports/`.
- Mode: `$FIX_MODE` (default `dev`; valid `dev` | `prod` | `dryrun`).
- Secrets: 1Password CLI.

═══════════════════════════════════════════════════════════════════
SCOPE
═══════════════════════════════════════════════════════════════════
DB migration C — fix the 10 PL/pgSQL function errors **and** triage 123 authenticated-callable SECDEF RPCs.

| ID | What |
|---|---|
| H-3 | 10 PL/pgSQL function errors (subset of 20 reported by `plpgsql_check`) |
| H-4 | 123 SECDEF functions are authenticated-callable; revoke trigger-only/internal helpers |

OUT OF SCOPE
- 32 anon-callable SECDEFs (C-4) → already closed by fix-agent-1A.
- pg_partman move (C-3) → fix-agent-1B.
- pgaudit install (H-9) → fix-agent-2E.

═══════════════════════════════════════════════════════════════════
PRE-CONDITIONS
═══════════════════════════════════════════════════════════════════
1. fix-agent-1A landed in prod (`./fix-reports/1A-result.md` shows MODE=prod result=PASS).
2. `MODE=prod` requires `./fix-reports/2B-dev-verified.sentinel`.
3. 1Password: dev or prod connection_string per MODE.

═══════════════════════════════════════════════════════════════════
KNOWLEDGE BASE
═══════════════════════════════════════════════════════════════════

### H-3 — the 10 PL/pgSQL function errors
Per `04-sast-dast.md` sec 2.4 + sec HIGH:

| Function | Schema | Error |
|---|---|---|
| `update_transaction` | `public` | references nonexistent column `broker` on `portfolio.transactions` |
| `get_portfolio_list_with_metrics` | `public` | references nonexistent `holdings.current_value` |
| `recompute_trending_scores` | `public` | references nonexistent `posts.is_trending` |
| `cleanup_stale_trending` | `public` | references nonexistent `posts.is_trending` |
| `update_portfolio_performance` | `public` | `ON CONFLICT` mismatches schema |
| `reverse_debit_credits` | `public` | boolean = integer operator error |
| `refund_topup_credits` | `public` | boolean = integer operator error |
| `store_payment_token` | `public` | service-role EXECUTE on `_crypto_aead_det_noncegen` denied |
| `reapply_constraints_proc` | `public` | uninitialised record `v_row` |
| `simulate_holdings_at_dates` | `portfolio` | references temp relation `_sim_out` never declared |

Each is a stale function body. Most need either: (a) drop the broken function (if no caller), (b) update the body to reference the current schema, or (c) for `store_payment_token`, grant EXECUTE on `_crypto_aead_det_noncegen` to `service_role`.

### H-4 — the 123 SECDEF triage classification
Three buckets:

**(a) Intentional RPC** — keep `authenticated` EXECUTE. Examples: any function the mobile/web client calls via `supabase.rpc(...)` on the path. Search `apps/{mobile,web,admin}/src/` for `.rpc('<name>'`.

**(b) Trigger-only** — fires from trigger machinery; never called as RPC. Revoke from `public, anon, authenticated, service_role`. Patterns:
- `after_*_change`, `dispatch_*_notification`, `enforce_*_limit`, `set_content_held_on_change`,
  `stamp_held_since`, `sync_username_to_lookup`, `trg_ensure_default_*`,
  `trigger_comment_moderation`, `update_*_count`, `update_follow_counts`,
  `update_comment_likes_count`, `users_view_{insert,update,delete}` (called by view rules), …

**(c) Internal cleanup / privileged** — runs from cron as `postgres`/owner; never called as RPC. Revoke from all client roles. Examples: `cleanup_expired_invites`, `cleanup_old_records`, `cleanup_old_scheduler_logs`, `delete_all_snapshots`, `delete_asset_cascade`, `delete_snapshots_from_date`, `recalculate_holdings`, `recalculate_portfolio`, `recompute_portfolio_cash`, `sync_is_subscriber`, `sync_verified_on_plan_change`.

═══════════════════════════════════════════════════════════════════
WORKFLOW
═══════════════════════════════════════════════════════════════════

**STEP 0 — Resolve secrets, sentinel, ensure 1A landed**
```bash
case "${FIX_MODE:-dev}" in
  dev)    DB_URL=$(op read "op://Travus/Supabase - Dev Branch/connection_string") ;;
  prod)   DB_URL=$(op read "op://Travus/Supabase - Production/connection_string") ;;
  dryrun) DB_URL="" ;;
esac

[ "$FIX_MODE" = "prod" ] && {
  test -f ./fix-reports/2B-dev-verified.sentinel \
    || { echo "BLOCKED: dev verification sentinel missing"; exit 1; }
}

# Verify 1A is in prod (anon-EXECUTE-on-SECDEF count == 1)
[ "$FIX_MODE" = "prod" ] && {
  grep -E "Result: PASS" ./fix-reports/1A-result.md \
    || { echo "BLOCKED: fix-agent-1A has not landed in prod"; exit 1; }
}
```

**STEP 1 — Export the 123 SECDEF list**

```sql
copy (
  select n.nspname, p.proname, pg_get_function_identity_arguments(p.oid) as args
  from pg_proc p join pg_namespace n on n.oid=p.pronamespace
  where p.prosecdef
    and has_function_privilege('authenticated', p.oid, 'EXECUTE')
    and n.nspname = 'public'
  order by p.proname
) to '/tmp/2B-secdef-123.csv' with (format csv, header true);
```

(Or use `psql -At --csv` if `copy` requires server-side path.)

Read the result. Verify count == 123 (per audit). If significantly different, the audit baseline has drifted; flag in the report.

**STEP 2 — Classify each function**

For each row in `/tmp/2B-secdef-123.csv`:
1. Search `apps/{mobile,web,admin}/src/**/*.{ts,tsx,js}` for `.rpc('<name>'` or `.rpc("<name>"`.
   - HIT → bucket (a) intentional RPC.
2. Search `pg_trigger.tgfoid` for any trigger pointing at this function:
   ```sql
   select 1 from pg_trigger where tgfoid = (
     select oid from pg_proc where proname=:name and pronamespace='public'::regnamespace
   ) limit 1;
   ```
   - HIT → bucket (b) trigger-only.
3. Search `cron.job.command` for the function name.
   - HIT → bucket (c) internal cleanup (called from cron context as `postgres`).
4. Patterns from KB above (last fallback) → bucket (b) or (c).
5. Anything left over → bucket (a) intentional, but FLAG for review (likely a programmatic admin RPC; user confirms).

Write classification to `/tmp/2B-classification.csv` with columns: `name, args, bucket, evidence`.

**STEP 3 — Generate migration file**

`./supabase/migrations/$(date +%Y%m%d%H%M%S)_fix_2B_plpgsql_and_secdef_triage.sql`:

```sql
-- fix-agent-2B: PL/pgSQL function fixes + 123 SECDEF triage
-- Closes audit findings: H-3, H-4

begin;

-- =========================================================
-- H-3: 10 PL/pgSQL function fixes
-- =========================================================
-- public.update_transaction — drop nonexistent column reference
create or replace function public.update_transaction(...) returns ... as $$
  -- updated body without 'broker' column
  ...
$$ language plpgsql security definer set search_path = public, pg_temp;

-- public.get_portfolio_list_with_metrics — fix holdings.current_value
-- public.recompute_trending_scores — fix posts.is_trending (or drop)
-- public.cleanup_stale_trending — fix posts.is_trending (or drop)
-- public.update_portfolio_performance — fix ON CONFLICT
-- public.reverse_debit_credits — fix boolean=integer
-- public.refund_topup_credits — fix boolean=integer
-- public.store_payment_token — grant service_role EXECUTE on _crypto_aead_det_noncegen
grant execute on function vault._crypto_aead_det_noncegen(...) to service_role;
-- public.reapply_constraints_proc — initialise v_row record
-- portfolio.simulate_holdings_at_dates — declare _sim_out properly

-- (Each function body needs the actual current source. Use pg_get_functiondef to dump,
--  edit, and reapply. The agent must read each via:
--     select pg_get_functiondef(oid) from pg_proc where proname=:name and pronamespace='public'::regnamespace;
--  ... and emit a fixed version.)

-- =========================================================
-- H-4: 123 SECDEF triage
-- =========================================================
-- bucket (b) trigger-only — revoke from all client roles:
revoke execute on function public.<trigger_fn>(<args>) from public, anon, authenticated, service_role;
-- ... (one line per (b)-bucket function)

-- bucket (c) internal cleanup — revoke from all client roles:
revoke execute on function public.<cleanup_fn>(<args>) from public, anon, authenticated;
-- (keep service_role if cron runs as service_role; otherwise revoke too)
-- ... (one line per (c)-bucket function)

-- bucket (a) intentional RPC — no change.

commit;
```

If `MODE=dryrun`, write the migration file path + counts (X buckets a, Y bucket b, Z bucket c) to the report and exit `result=DRYRUN`.

**STEP 4 — Apply + verify**

```bash
psql "$DB_URL" -v ON_ERROR_STOP=1 -f "$MIGRATION_FILE" 2>&1 | tee /tmp/2B-apply.log
```

Verification:
```bash
# H-3 verify: supabase db lint clean
supabase db lint --db-url "$DB_URL" 2>&1 | tee /tmp/2B-dblint.log
# expect: no PL/pgSQL errors among the 10 function names
```

```sql
-- H-4 verify: count authenticated-EXECUTE-on-SECDEF after
select count(*) from pg_proc p where p.prosecdef
  and has_function_privilege('authenticated', p.oid, 'EXECUTE')
  and pronamespace='public'::regnamespace;
-- expected: significantly less than 123 (only bucket (a) intentional RPCs left)
```

**STEP 5 — Add CI guard**

Append to `.github/workflows/db-guards.yml` (created by 1A):
```yaml
- name: assert authenticated-EXECUTE-on-SECDEF allow-list
  run: |
    psql "$PROD_URL" -At -c "
      select count(*) from pg_proc p where p.prosecdef
        and has_function_privilege('authenticated', p.oid, 'EXECUTE')
        and pronamespace='public'::regnamespace;
    " > /tmp/secdef-count
    test "$(cat /tmp/secdef-count)" = "<intentional-RPC count>" \
      || { echo "Drift in authenticated SECDEF allow-list" >&2; exit 1; }
```

**STEP 6 — Sentinel + report**

```bash
cat > ./fix-reports/2B-dev-verified.sentinel <<EOF
fix-agent-2B dev verification PASSED at $(date -u +%Y-%m-%dT%H:%M:%SZ)
plpgsql_errors_before: 10
plpgsql_errors_after: 0
secdef_authenticated_before: 123
secdef_authenticated_after: <N>
EOF
```

`./fix-reports/2B-result.md`:
```
FIX-AGENT-2B RESULT
===================
Mode: dev | prod | dryrun
Result: PASS | FAIL | DRYRUN | BLOCKED | APPLY_FAILED | LINT_FAILED
Migration file: supabase/migrations/<ts>_fix_2B_*.sql

H-3 PL/pgSQL fixes:
  fixed: <count>/10
  remaining: <list>
  supabase db lint: clean | <errors>

H-4 SECDEF triage:
  total before: 123
  bucket (a) intentional RPC: <count>      (kept authenticated EXECUTE)
  bucket (b) trigger-only: <count>          (revoked from all client roles)
  bucket (c) internal cleanup: <count>      (revoked from anon, authenticated)
  total after: <count>                      (= bucket (a) count)
  classification CSV: /tmp/2B-classification.csv

CI guard added: .github/workflows/db-guards.yml (authenticated-EXECUTE-on-SECDEF allow-list)

Manual review required:
  - <list any "fallback (a)" functions flagged for confirmation>

Next agent: any of fix-agent-2C..2H in parallel.
```

**STEP 7 — Final stdout:**
```
DONE | fix-agent-2B | <mode> | <result> | ./fix-reports/2B-result.md
```

═══════════════════════════════════════════════════════════════════
HARD AUTONOMY RULES
═══════════════════════════════════════════════════════════════════
- NEVER bucket-(a) a function that has no `.rpc(` callsite — flag for manual review.
- NEVER drop a PL/pgSQL function without confirming no caller exists.
- NEVER auto-roll-back. If `supabase db lint` still shows errors post-migration, leave state and report.
- BEGIN IMMEDIATELY.
