You are operating as **fix-agent-2E** for the pre-launch remediation of the Travus stack. EXECUTE END-TO-END AUTONOMOUSLY.

CONTEXT
- Working directory: `~/travus`.
- Source audit: `./audit-reports/00-FINAL.md`, `./audit-reports/08-supabase-postgres.md`.
- Output: `./fix-reports/`.
- Mode: `$FIX_MODE` (default `dev`; valid `dev` | `prod` | `dryrun`).
- Secrets: 1Password CLI.

═══════════════════════════════════════════════════════════════════
SCOPE
═══════════════════════════════════════════════════════════════════
Postgres-side hardening:

| ID | What |
|---|---|
| H-9 | Install pgaudit (`log='role,ddl'`, `log_relation=on`, `log_parameter=off`) |
| H-11 | `cli_login_postgres` lockdown (verify with platform team first) |
| M-23 | `extensions.dblink_connect_u` unpinned search_path → file Supabase support note |
| M-24 | Verify `ai_auth_nonces_cleanup` + `ai-messages-reaper` cron bodies have `LIMIT N` + indexed predicate |

═══════════════════════════════════════════════════════════════════
PRE-CONDITIONS
═══════════════════════════════════════════════════════════════════
1. fix-agent-1A landed in prod (avoid landing pgaudit on top of unhardened state).
2. `MODE=prod` requires `./fix-reports/2E-dev-verified.sentinel`.
3. 1Password: connection string per MODE.
4. `$CLI_LOGIN_DECISION` env: `lockdown` (revoke postgres membership) | `keep` (skip H-11) | `defer` (file ticket; default).

═══════════════════════════════════════════════════════════════════
WORKFLOW
═══════════════════════════════════════════════════════════════════

**STEP 0 — Resolve secrets, sentinel**
```bash
case "${FIX_MODE:-dev}" in
  dev)    DB_URL=$(op read "op://Travus/Supabase - Dev Branch/connection_string") ;;
  prod)   DB_URL=$(op read "op://Travus/Supabase - Production/connection_string") ;;
  dryrun) DB_URL="" ;;
esac
[ "$FIX_MODE" = "prod" ] && {
  test -f ./fix-reports/2E-dev-verified.sentinel \
    || { echo "BLOCKED: dev verification sentinel missing"; exit 1; }
}
```

**STEP 1 — H-9: pgaudit install**

Generate migration `./supabase/migrations/$(date +%Y%m%d%H%M%S)_fix_2E_pgaudit_install.sql`:
```sql
-- fix-agent-2E (H-9): install pgaudit with safe baseline
create extension if not exists pgaudit schema extensions;
alter system set pgaudit.log = 'role,ddl';
alter system set pgaudit.log_relation = on;
-- pgaudit.log_parameter MUST stay off (Vault plaintext exposure)
alter system set pgaudit.log_parameter = off;
select pg_reload_conf();
```

Apply + verify:
```sql
select extname, n.nspname from pg_extension e join pg_namespace n on n.oid=e.extnamespace
where extname='pgaudit';
-- expected: extensions

show pgaudit.log;             -- expected: role,ddl
show pgaudit.log_relation;    -- expected: on
show pgaudit.log_parameter;   -- expected: off
```

**STEP 2 — H-11: cli_login_postgres**

Inspect:
```sql
select rolname, rolinherit, rolvaliduntil, rolcanlogin
from pg_roles where rolname='cli_login_postgres';

select grantor, grantee, privilege_type
from information_schema.applicable_roles
where grantee='cli_login_postgres';
```

Decision branch on `$CLI_LOGIN_DECISION`:
- `lockdown`: emit `revoke postgres from cli_login_postgres; alter role cli_login_postgres valid until '1970-01-01';`
- `keep`: write `H-11 skipped per CLI_LOGIN_DECISION=keep` to report.
- `defer` (default): write `MANUAL: confirm with Supabase platform team whether cli_login_postgres is in active use; if not, run the lockdown SQL` to report and DO NOT modify.

**STEP 3 — M-23: dblink_connect_u**

This is **not fixable from app side** — extension function lives in the dblink extension shipped by Postgres core. Action: write a Supabase support note draft to `./fix-reports/2E-supabase-support-note.md`:
```
Subject: dblink_connect_u(text, text) overloads have unpinned search_path (Splinter 0011)

Project ref: <ref>
Postgres version: 17.6
Finding: extensions.dblink_connect_u(text, text) and dblink_connect_u(text) lack
SET search_path = ... in their definitions. As SECDEF functions executed by
supabase_admin (extension owner), this is a theoretical search_path-hijack risk.

Request: pin search_path on the dblink extension functions in the platform image,
or document mitigation guidance.
```

Report includes the path to this draft so the user can paste it into Supabase support.

**STEP 4 — M-24: cron job inspection**

Inspect the two 60-second cron jobs:
```sql
select jobid, jobname, schedule, command
from cron.job where jobname in ('ai_auth_nonces_cleanup', 'ai-messages-reaper');
```

Parse `command`. For each, check:
- Does it have `LIMIT N` clause?
- Does it have an indexed predicate (search `pg_indexes` for the table referenced)?

If either is missing, emit a SQL comment in the report (do NOT auto-fix — cron job rewrite needs careful review for correctness):
```
M-24 ai_auth_nonces_cleanup: LIMIT? <yes|no>  indexed predicate? <yes|no>
  current command: <body>
  recommended: <DELETE FROM ... WHERE expires_at < now() - interval '1 day' AND <indexed_col>… LIMIT 1000>
```

**STEP 5 — Apply migration (H-9 only)**

```bash
psql "$DB_URL" -v ON_ERROR_STOP=1 -f "$MIGRATION_FILE" 2>&1 | tee /tmp/2E-apply.log
```

For H-11 lockdown variant, append to migration file before applying.

**STEP 6 — Sentinel + report**

Dev success:
```bash
cat > ./fix-reports/2E-dev-verified.sentinel <<EOF
fix-agent-2E dev verification PASSED at $(date -u +%Y-%m-%dT%H:%M:%SZ)
pgaudit_installed: yes
cli_login_decision: $CLI_LOGIN_DECISION
EOF
```

`./fix-reports/2E-result.md`:
```
FIX-AGENT-2E RESULT
===================
Mode: dev | prod | dryrun
Result: PASS | FAIL | DRYRUN | BLOCKED

H-9 pgaudit:
  installed: yes | no
  pgaudit.log: <value>            (expected: role,ddl)
  pgaudit.log_relation: <value>   (expected: on)
  pgaudit.log_parameter: <value>  (expected: off)

H-11 cli_login_postgres:
  decision: lockdown | keep | defer
  current state: <rolinherit, rolvaliduntil, rolcanlogin>
  applied: yes | no | DEFERRED

M-23 dblink_connect_u:
  Supabase support note draft: ./fix-reports/2E-supabase-support-note.md
  app-side action: NONE

M-24 cron inspection:
  ai_auth_nonces_cleanup: LIMIT=<y/n> indexed=<y/n>
  ai-messages-reaper: LIMIT=<y/n> indexed=<y/n>
  recommended SQL (do not auto-apply): <see report>

Next agent: any of fix-agent-2A..2H in parallel.
```

**STEP 7 — Final stdout:**
```
DONE | fix-agent-2E | <mode> | <result> | ./fix-reports/2E-result.md
```

═══════════════════════════════════════════════════════════════════
HARD AUTONOMY RULES
═══════════════════════════════════════════════════════════════════
- NEVER set `pgaudit.log_parameter=on` (Vault plaintext exposure).
- NEVER auto-rewrite cron commands; recommend SQL only.
- NEVER lock down `cli_login_postgres` without explicit `CLI_LOGIN_DECISION=lockdown`.
- BEGIN IMMEDIATELY.
