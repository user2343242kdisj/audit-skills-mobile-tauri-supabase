You are operating as **fix-agent-1B** for the pre-launch remediation of the Travus stack. EXECUTE END-TO-END AUTONOMOUSLY.

CONTEXT
- Working directory: the user's app repo (`~/travus`).
- Audit-skills repo: `$AUDIT_SKILLS_PATH` (default `./audit`).
- Source audit: `./audit-reports/00-FINAL.md`.
- Output: `./fix-reports/`.
- Mode: `$FIX_MODE` (default `dev`; valid `dev` | `prod` | `dryrun`).
- Secrets: 1Password CLI.

═══════════════════════════════════════════════════════════════════
SCOPE
═══════════════════════════════════════════════════════════════════
Move `pg_partman` extension from `public` to `extensions` schema. Closes finding **C-3** (Splinter rule 0014).

OUT OF SCOPE
- Anything else in Phase 1 (separate fix-agents 1A, 1C).

═══════════════════════════════════════════════════════════════════
PRE-CONDITIONS
═══════════════════════════════════════════════════════════════════
1. `./audit-reports/00-FINAL.md` exists.
2. `$FIX_MODE` valid.
3. If `MODE=prod`: `./fix-reports/1B-dev-verified.sentinel` MUST exist.
4. Connection string available:
   - `op://Travus/Supabase - Dev Branch/connection_string` (dev)
   - `op://Travus/Supabase - Production/connection_string` (prod)

═══════════════════════════════════════════════════════════════════
KNOWLEDGE BASE
═══════════════════════════════════════════════════════════════════

`pg_partman` currently sits in `public` (Splinter 0014). It exposes 21+ functions (`part_config*`, `apply_constraints`, `run_maintenance_proc`, etc.) reachable via PostgREST. Moving the extension to a dedicated `extensions` schema removes them from PostgREST exposure.

**Risk surface**: partition templates may reference `public.pg_partman_*` functions or `public.part_config` directly. After the move, those references must resolve via `extensions.pg_partman_*` (Postgres rewrites `pg_extension` reference but not literal text in templates).

**Single command**:
```sql
alter extension pg_partman set schema extensions;
```

**Dev verification gates before sentinel**:
1. Snapshot `extensions.part_config` post-move (row count, column names).
2. Trigger a maintenance run: `call extensions.run_maintenance_proc();` (or whatever Travus uses — search `cron.job.command` for the canonical invocation).
3. Verify a fresh partition is created on the next-due parent table.
4. Verify existing parent triggers still fire (run an INSERT on a partitioned table; expect it to land in the right child).

═══════════════════════════════════════════════════════════════════
WORKFLOW
═══════════════════════════════════════════════════════════════════

**STEP 0 — Resolve secrets + sentinel check**
```bash
case "${FIX_MODE:-dev}" in
  dev)    DB_URL=$(op read "op://Travus/Supabase - Dev Branch/connection_string") ;;
  prod)   DB_URL=$(op read "op://Travus/Supabase - Production/connection_string") ;;
  dryrun) DB_URL="" ;;
  *) echo "BLOCKED: invalid FIX_MODE"; exit 1 ;;
esac
[ "$FIX_MODE" = "prod" ] && {
  test -f ./fix-reports/1B-dev-verified.sentinel \
    || { echo "BLOCKED: dev verification sentinel missing" > ./fix-reports/1B-result.md; exit 1; }
}
```

**STEP 1 — Generate migration file**

`./supabase/migrations/$(date +%Y%m%d%H%M%S)_fix_1B_pg_partman_schema.sql`:

```sql
-- fix-agent-1B: move pg_partman from public to extensions
-- Closes audit finding: C-3 (Splinter 0014)

begin;
alter extension pg_partman set schema extensions;
commit;
```

If `MODE=dryrun`, write the migration path to `./fix-reports/1B-result.md` and exit `result=DRYRUN`.

**STEP 2 — Pre-flight (MODE=dev or prod)**

Capture baseline:
```sql
-- baseline: extension lives in public
select e.extname, n.nspname as schema
from pg_extension e join pg_namespace n on n.oid=e.extnamespace
where e.extname='pg_partman';
-- expected: schema=public

-- inventory partition templates and parent tables
select * from public.part_config order by parent_table;       -- snapshot to /tmp/1B-part_config-before.csv
```

Inventory cron jobs that invoke partman (read `cron.job` rows):
```sql
select jobid, jobname, command from cron.job
  where command ilike '%partman%' or command ilike '%part_config%';
```
Save to `/tmp/1B-cron-partman.csv`.

If schema is already `extensions`, write `result=NOOP` and exit success.

**STEP 3 — Apply migration**

```bash
psql "$DB_URL" -v ON_ERROR_STOP=1 -f "$MIGRATION_FILE" 2>&1 | tee /tmp/1B-apply.log
```

**STEP 4 — Post-migration verification**

```sql
-- extension now in extensions schema
select n.nspname from pg_extension e join pg_namespace n on n.oid=e.extnamespace
where e.extname='pg_partman';
-- expected: extensions

-- part_config still reachable, same row count
select count(*) from extensions.part_config;
-- compare with /tmp/1B-part_config-before.csv

-- trigger a maintenance run (only on dev)
-- (skip on prod — let cron handle it next tick)
```

If MODE=dev, run the maintenance call using the same invocation pattern from `/tmp/1B-cron-partman.csv` (typically `select extensions.run_maintenance_proc();`). Capture stderr; any error means partition templates need re-pointing — record the error and exit `result=PARTMAN_TEMPLATE_BROKEN`.

**STEP 5 — Cron-job sanity (MODE=dev only)**

After the migration, verify any cron job that invoked `public.pg_partman_*` still resolves. Postgres normally rewrites the reference, but if a cron command has the literal string `public.run_maintenance_proc(`, it will silently 404 next tick. Grep saved CSV:
```bash
grep -E "public\.(run_maintenance_proc|part_config|apply_constraints)" /tmp/1B-cron-partman.csv \
  && echo "WARN: hard-coded public.* reference in cron commands — needs manual update"
```

**STEP 6 — Sentinel + report**

On dev success:
```bash
cat > ./fix-reports/1B-dev-verified.sentinel <<EOF
fix-agent-1B dev verification PASSED at $(date -u +%Y-%m-%dT%H:%M:%SZ)
extension_schema_before: public
extension_schema_after: extensions
part_config_rows: <N>
maintenance_run: PASS
hard_coded_public_refs_in_cron: <count>
EOF
```

`./fix-reports/1B-result.md`:
```
FIX-AGENT-1B RESULT
===================
Date: <ISO-8601>
Mode: dev | prod | dryrun
Result: PASS | FAIL | NOOP | DRYRUN | BLOCKED | APPLY_FAILED | PARTMAN_TEMPLATE_BROKEN
Migration file: supabase/migrations/<ts>_fix_1B_pg_partman_schema.sql

extension pg_partman:
  before: public
  after:  extensions
part_config row count: <N> (unchanged)
maintenance_run (dev only): PASS | FAIL | SKIPPED
cron commands with hard-coded public.pg_partman refs: <count>
  <list any hits — these need manual update>

Next agent: fix-agent-2B (DB migration C — PL/pgSQL + SECDEF triage)
```

**STEP 7 — Final stdout:**
```
DONE | fix-agent-1B | <mode> | <result> | ./fix-reports/1B-result.md
```

═══════════════════════════════════════════════════════════════════
HARD AUTONOMY RULES
═══════════════════════════════════════════════════════════════════
- NEVER run prod migration without `./fix-reports/1B-dev-verified.sentinel`.
- NEVER auto-roll-back. If `run_maintenance_proc()` errors post-migration, leave state as-is and report.
- NEVER edit files outside `./supabase/migrations/`, `./fix-reports/`, `/tmp/`.
- If any cron command has hard-coded `public.pg_partman_*` literal string, flag in report — do NOT auto-edit cron.job.
- BEGIN IMMEDIATELY.
