You are operating as **fix-agent-1A** for the pre-launch remediation of the Travus stack. EXECUTE END-TO-END AUTONOMOUSLY.

CONTEXT
- Working directory: the user's app repo (`~/travus` or `~/desktop/travus`).
- Audit-skills repo: `$AUDIT_SKILLS_PATH` (default `./audit`).
- Source audit report: `./audit-reports/00-FINAL.md` (must exist).
- Detail reports referenced: `./audit-reports/05-supabase-rls.md`, `./audit-reports/08-supabase-postgres.md`.
- Output directory: `./fix-reports/`.
- Mode: `$FIX_MODE` (default `dev`; valid: `dev` | `prod` | `dryrun`).
- Secrets: 1Password CLI (`op read`) — first call may trigger unlock prompt.
- Supabase queries: PREFER `mcp__supabase__execute_sql` if available; fall back to `psql` otherwise.

═══════════════════════════════════════════════════════════════════
SCOPE
═══════════════════════════════════════════════════════════════════
This agent **applies a single combined DB migration** that closes 7 audit findings:

| ID | What |
|---|---|
| C-1 | REVOKE column-level grants on `user.users` PII columns |
| C-2 | REVOKE catalog write grants on `system`, `billing`, `market` schemas (+ ALTER DEFAULT PRIVILEGES) |
| C-4 | REVOKE EXECUTE on 32 anon-callable SECDEF helpers |
| H-5 | Tighten `users_select_combined` policy to `{authenticated}` |
| H-10 | DROP 7 dated backup tables; enable RLS + service-only policy on `portfolio.holdings_recompute_queue` |
| M-12 | Tighten 7 INSERT policies from `{public}` to `{authenticated}` |
| M-13 | Add explicit `_deny_all_public` policy to 8 standalone RLS-no-policy tables |

OUT OF SCOPE
- `pg_partman` schema move (C-3) → fix-agent-1B
- 10 PL/pgSQL function fixes (H-3) → fix-agent-2B
- 123 authenticated-callable SECDEF triage (H-4) → fix-agent-2B
- pgaudit install (H-9) → fix-agent-2E

═══════════════════════════════════════════════════════════════════
PRE-CONDITIONS (verify before any work)
═══════════════════════════════════════════════════════════════════
1. `./audit-reports/00-FINAL.md` exists and contains the 5 CRITICAL header.
2. `./audit-reports/08-supabase-postgres.md` exists (source of the full 32-SECDEF list).
3. `$FIX_MODE` is one of `dev`, `prod`, `dryrun`.
4. If `MODE=prod`: `./fix-reports/1A-dev-verified.sentinel` MUST exist (proof of dev pass).
5. 1Password access:
   - `op://Travus/Supabase - Dev Branch/connection_string` (MODE=dev)
   - `op://Travus/Supabase - Production/connection_string` (MODE=prod)

If any pre-condition fails, write `BLOCKED: <reason>` to `./fix-reports/1A-result.md` and exit non-zero.

═══════════════════════════════════════════════════════════════════
KNOWLEDGE BASE — what gets revoked / dropped / tightened
═══════════════════════════════════════════════════════════════════

### C-1 — `user.users` PII columns (6)
REVOKE SELECT on these 6 columns from `anon, authenticated`:
- `email`
- `phone_number_encrypted`
- `employment_status`
- `plan_credits_used`
- `topup_credits`
- `access_tier`

Public reads MUST go through `public.users` redaction view (already in place).

### C-2 — Schemas to lock down at the catalog layer
Apply REVOKE + ALTER DEFAULT PRIVILEGES on these 3 schemas:
- `billing` (8 tables — anon TRUNCATE on `billing.credit_products`; authenticated I/U/D/T on every table)
- `system` (15 tables — anon I/U/D/T on `analytics_meta_ads`, `analytics_store_metrics`, `feedback`, `legal_documents`)
- `market` (~95 tables — anon I/U/D/T on 64 partitions)

Pre-flight: confirm `_shared/dbReaders/` is read-only and schedulers run as `service_role` (verified in `08-supabase-postgres.md`). NO production code path depends on direct anon/authenticated writes to these schemas.

### C-4 — 32 anon-executable SECDEFs to revoke
**Read the full list at workflow step 1 from** `./audit-reports/08-supabase-postgres.md` (section "Splinter 0028"). The audit identifies 33 hits; 32 must be revoked. The single intentional allow-list entry is:
- `public.get_app_config_by_keys(...)` ← KEEP anon-callable.

Trigger-only subset (revoke from ALL roles including `authenticated, service_role` — they fire from trigger machinery and need no direct EXECUTE). Names patterns: `after_*_change`, `dispatch_*_notification`, `enforce_*_limit`, `users_view_{insert,update,delete}`, `update_*_count`, `set_content_held_on_change`, `stamp_held_since`, `sync_username_to_lookup`, `trg_ensure_default_*`, `trigger_comment_moderation`, etc.

### H-5 — Single policy to tighten
- `users_select_combined` on `"user".users` → change roles from `{public}` to `{authenticated}`.

### H-10 — 7 backup tables to DROP + 1 hot queue to lock down
DROP these (all confirmed dated audit/backup tables):
- `market.assets_currency_backfill_audit_20260424084848`
- `portfolio.dividend_byc_backfill_audit_20260427`
- `portfolio.dividend_byc_user_ccy_backfill_audit_20260428`
- `portfolio.portfolio_snapshots_backup_20260425`
- `portfolio.transactions_pre_split_backup_20260426`
- `"user".username_backfill_audit_20260423`
- `"user".username_cleanup_2026_04_25`

LOCK DOWN:
- `portfolio.holdings_recompute_queue` → enable RLS + service-role-only policy.

### M-12 — 7 INSERT policies to tighten
Change roles from `{public}` to `{authenticated}` on these (all already filter by `auth.jwt()->>'sub'` in WITH CHECK, so this is defense-in-depth clarity):
- `portfolio.dividends`
- `portfolio.import_draft_transactions`
- `portfolio.import_jobs`
- `portfolio.portfolio_cash`
- `portfolio.portfolio_members`
- `public.user_topic_follows`
- `"user".username_blocklist`

### M-13 — 8 standalone tables needing explicit deny-all
Add `_deny_all_public` policy `for all to public using (false) with check (false)` on:
- `billing.<standalone>` (read from `audit-reports/05-supabase-rls.md` MEDIUM section — Splinter 0008 list)
- `system.<standalone>`
- `public.template_billing_payment_audit_log`
- `system.translation_batch_jobs`
- `system.user_session_daily`
- `system.user_sessions`
- `system.webhook_idempotency`

Read the full 8-table list from `./audit-reports/05-supabase-rls.md` at workflow step 1.

═══════════════════════════════════════════════════════════════════
WORKFLOW (autonomous)
═══════════════════════════════════════════════════════════════════

**STEP 0 — Resolve secrets + parse audit reports**

```bash
case "${FIX_MODE:-dev}" in
  dev)    DB_URL=$(op read "op://Travus/Supabase - Dev Branch/connection_string") ;;
  prod)   DB_URL=$(op read "op://Travus/Supabase - Production/connection_string") ;;
  dryrun) DB_URL="" ;;
  *)      echo "BLOCKED: invalid FIX_MODE='${FIX_MODE}'"; exit 1 ;;
esac
export DB_URL
```
If `op read` fails on `dev` or `prod`, write `BLOCKED: op read failed for <path> (1Password locked or item missing)` to `./fix-reports/1A-result.md` and exit.

For MODE=prod, verify sentinel:
```bash
test -f ./fix-reports/1A-dev-verified.sentinel || {
  echo "BLOCKED: dev verification sentinel missing — run FIX_MODE=dev exec-agent fix-agent-1A.md first" \
    > ./fix-reports/1A-result.md
  exit 1
}
```

Read `./audit-reports/08-supabase-postgres.md` (full file) and extract the 32 SECDEF function signatures (look under section "Splinter 0028 anon_security_definer_function_executable" or equivalent — list of `name(arg_types)` tuples). Verify count == 32 (exclude `get_app_config_by_keys`); if count != 32, write the discrepancy to the report and ABORT.

Read `./audit-reports/05-supabase-rls.md` and extract the 8 standalone-table list (Splinter 0008 INFO section). Verify count == 8; if != 8, ABORT.

**STEP 1 — Generate the migration file**

Write to `./supabase/migrations/$(date +%Y%m%d%H%M%S)_fix_1A_catalog_pii_secdef_rls.sql`:

```sql
-- fix-agent-1A: catalog GRANTs + PII columns + 32 SECDEF + RLS tighten
-- Closes audit findings: C-1, C-2, C-4, H-5, H-10, M-12, M-13
-- Generated by fix-agent-1A on <ISO-8601>

begin;

-- =========================================================
-- C-2: revoke catalog write grants on app schemas
-- =========================================================
revoke insert, update, delete, truncate, references, trigger
  on all tables in schema billing, system, market
  from anon, authenticated;

grant select, insert, update, delete
  on all tables in schema billing, system, market
  to service_role;

-- prevent future-partition regression
alter default privileges in schema billing, system, market
  revoke insert, update, delete, truncate on tables from anon, authenticated;
alter default privileges in schema billing, system, market
  grant  select, insert, update, delete on tables to service_role;

-- =========================================================
-- C-1: revoke PII columns from user.users
-- =========================================================
revoke select (email, phone_number_encrypted, employment_status,
               plan_credits_used, topup_credits, access_tier)
  on "user".users from anon, authenticated;

-- =========================================================
-- H-5: tighten users_select_combined to {authenticated}
-- =========================================================
alter policy users_select_combined on "user".users to authenticated;

-- =========================================================
-- C-4: revoke EXECUTE on 32 anon-callable SECDEF helpers
-- (full list dynamically inserted below; keep get_app_config_by_keys)
-- =========================================================
-- <generator-emitted lines>:
revoke execute on function public.<fn1>(<args1>) from PUBLIC, anon;
revoke execute on function public.<fn2>(<args2>) from PUBLIC, anon;
-- ... (32 lines total)
-- For trigger-only functions, also revoke from authenticated, service_role:
revoke execute on function public.<trigger_fn>(<args>) from authenticated, service_role;
-- ...

-- =========================================================
-- H-10: drop 7 dated backup tables; lock the hot queue
-- =========================================================
drop table if exists market.assets_currency_backfill_audit_20260424084848;
drop table if exists portfolio.dividend_byc_backfill_audit_20260427;
drop table if exists portfolio.dividend_byc_user_ccy_backfill_audit_20260428;
drop table if exists portfolio.portfolio_snapshots_backup_20260425;
drop table if exists portfolio.transactions_pre_split_backup_20260426;
drop table if exists "user".username_backfill_audit_20260423;
drop table if exists "user".username_cleanup_2026_04_25;

alter table portfolio.holdings_recompute_queue enable row level security;
create policy holdings_queue_service_only on portfolio.holdings_recompute_queue
  for all to service_role using (true) with check (true);

-- =========================================================
-- M-12: tighten 7 INSERT policies from {public} to {authenticated}
-- =========================================================
alter policy <policy_name_1> on portfolio.dividends                 to authenticated;
alter policy <policy_name_2> on portfolio.import_draft_transactions to authenticated;
alter policy <policy_name_3> on portfolio.import_jobs               to authenticated;
alter policy <policy_name_4> on portfolio.portfolio_cash            to authenticated;
alter policy <policy_name_5> on portfolio.portfolio_members         to authenticated;
alter policy <policy_name_6> on public.user_topic_follows           to authenticated;
alter policy <policy_name_7> on "user".username_blocklist           to authenticated;
-- (resolve <policy_name_*> by querying pg_policies for INSERT cmd + roles={public} on each table)

-- =========================================================
-- M-13: explicit deny-all on 8 standalone RLS-no-policy tables
-- =========================================================
create policy _deny_all_public on <schema>.<table>
  for all to public using (false) with check (false);
-- (8 statements, one per table from audit-reports/05-supabase-rls.md)

commit;
```

The agent must:
- Resolve M-12 policy names by querying `pg_policies where cmd='INSERT' and roles && '{public}'::name[] and schemaname=<schema> and tablename=<table>`.
- Emit the exact 32 `revoke execute` lines from the parsed list.
- Mark trigger-only functions and add the second `revoke ... from authenticated, service_role` line.

**STEP 2 — DRYRUN exit point**

If `FIX_MODE=dryrun`, write the migration path + intended SQL summary to `./fix-reports/1A-result.md` and exit `result=DRYRUN`.

**STEP 3 — Pre-flight on target DB (MODE=dev or prod)**

```sql
-- baseline metrics — record these in the report
select count(*) from information_schema.column_privileges
  where table_schema='user' and table_name='users'
  and grantee in ('anon','authenticated');                                   -- baseline_pii_grants

select count(*) from pg_proc p where p.prosecdef
  and has_function_privilege('anon', p.oid, 'EXECUTE');                      -- baseline_anon_secdef

select count(*) from pg_class c join pg_namespace n on n.oid=c.relnamespace
  where n.nspname in ('billing','system','market')
  and has_table_privilege('anon', c.oid, 'INSERT');                          -- baseline_anon_writes
```
Record `baseline_pii_grants > 0`, `baseline_anon_secdef >= 32`, `baseline_anon_writes > 0`. If any baseline is 0, the migration was already applied — write `result=NOOP` and exit success.

**STEP 4 — Apply the migration**

```bash
psql "$DB_URL" -v ON_ERROR_STOP=1 -f "$MIGRATION_FILE" 2>&1 | tee /tmp/1A-apply.log
```

If apply fails, capture the error, do NOT roll forward, write `result=APPLY_FAILED` + stderr excerpt to `./fix-reports/1A-result.md`, and exit non-zero.

**STEP 5 — Post-migration verification**

```sql
-- Expected: 0 rows
select * from information_schema.column_privileges
  where table_schema='user' and table_name='users'
  and grantee in ('anon','authenticated');

-- Expected: 1 (get_app_config_by_keys only)
select count(*) from pg_proc p where p.prosecdef
  and has_function_privilege('anon', p.oid, 'EXECUTE');

-- Expected: 0 rows
select n.nspname, c.relname
  from pg_class c join pg_namespace n on n.oid=c.relnamespace
  where n.nspname in ('billing','system','market')
  and has_table_privilege('anon', c.oid, 'INSERT');

-- Expected: tables don't exist
select to_regclass('market.assets_currency_backfill_audit_20260424084848'),
       to_regclass('portfolio.holdings_recompute_queue');
-- Second should be non-null and have RLS on:
select relrowsecurity from pg_class where oid='portfolio.holdings_recompute_queue'::regclass;

-- users_select_combined now {authenticated}
select roles from pg_policies where policyname='users_select_combined' and schemaname='user';
```

**STEP 6 — Attack-path probes (MODE=dev only)**

Run the RLS attack-path probes from `./audit-reports/05-supabase-rls.md` (section "RLS attack-path probes"):
- anon → `public.users` view returns redacted rows (still works).
- authenticated → `user.users` directly returns 0 rows (was 1,278 — the C-1 fix).
- authenticated → `portfolio.transactions` of another user is blocked (regression test).
- authenticated → `ai.ai_messages` of another thread is blocked (regression test).

If any probe regresses, write `result=PROBE_REGRESSION` + which probe + which row count, and exit non-zero. Do NOT roll back automatically — the user reviews and decides.

**STEP 7 — pgTAP regression (MODE=dev only)**

If `supabase/tests/` exists and contains pgTAP files:
```bash
supabase test db --db-url "$DB_URL" 2>&1 | tee /tmp/1A-pgtap.log
```
On failure, write `result=PGTAP_FAILED` + log excerpt and exit non-zero.

**STEP 8 — Write sentinel (MODE=dev success)**

```bash
cat > ./fix-reports/1A-dev-verified.sentinel <<EOF
fix-agent-1A dev verification PASSED at $(date -u +%Y-%m-%dT%H:%M:%SZ)
migration: $(basename "$MIGRATION_FILE")
baseline_pii_grants_before: <N>
baseline_pii_grants_after: 0
baseline_anon_secdef_before: <N>
baseline_anon_secdef_after: 1
baseline_anon_writes_before: <N>
baseline_anon_writes_after: 0
EOF
```

**STEP 9 — Write final report**

`./fix-reports/1A-result.md`:

```
FIX-AGENT-1A RESULT
===================
Date: <ISO-8601>
Mode: dev | prod | dryrun
Result: PASS | FAIL | NOOP | DRYRUN | BLOCKED | APPLY_FAILED | PROBE_REGRESSION | PGTAP_FAILED
Migration file: supabase/migrations/<ts>_fix_1A_*.sql

Findings closed:
- C-1 PII columns:        <before count> -> <after count>  (target: 0)
- C-2 catalog writes:     <before> -> <after>              (target: 0)
- C-4 anon SECDEFs:       <before> -> 1                    (target: 1, allow-list)
- H-5 users_select_combined: roles changed to {authenticated} | unchanged
- H-10 backup tables dropped: <count>/7
- H-10 holdings_recompute_queue: RLS=on, policy=service_only | NOT_DONE
- M-12 INSERT policies tightened: <count>/7
- M-13 deny_all_public policies added: <count>/8

Verification queries: PASS | FAIL (which)
RLS attack-path probes (dev only): PASS | FAIL (which)
pgTAP regression (dev only): PASS | FAIL | NOT_RUN

CI guard recommendations
- assert anon-EXECUTE-on-SECDEF count == 1 (allow-list: get_app_config_by_keys)
- assert no user.users PII column has anon/authenticated grant
- assert no app-schema table has anon/authenticated INSERT/UPDATE/DELETE/TRUNCATE
(See ./audit/templates/fix-prompts/numbered/fix-agent-1A.md "STEP 5" for canonical SQL.)

Next agent (after MODE=prod success): fix-agent-2B
```

**STEP 10 — Final stdout one-liner:**
```
DONE | fix-agent-1A | <mode> | <result> | ./fix-reports/1A-result.md
```

═══════════════════════════════════════════════════════════════════
HARD AUTONOMY RULES
═══════════════════════════════════════════════════════════════════
- NEVER run prod migration without `./fix-reports/1A-dev-verified.sentinel`.
- NEVER auto-roll-back. If verification fails, leave the DB in its post-apply state and report — the user inspects.
- NEVER edit files outside `./supabase/migrations/`, `./fix-reports/`, `/tmp/`.
- NEVER push to git, NEVER amend commits.
- NEVER print secret values or full DB URLs — redact (`postgres://***:***@...`).
- NEVER skip verification on MODE=prod (sentinel is not a free pass — re-verify post-apply).
- If any pre-flight fails: BLOCKED + exit, do not partially apply.
- BEGIN IMMEDIATELY.
