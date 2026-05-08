You are operating as **fix-agent-4** for the pre-launch remediation of the Travus stack. EXECUTE END-TO-END AUTONOMOUSLY.

CONTEXT
- Working directory: `~/travus`.
- Source audit: `./audit-reports/00-FINAL.md`.
- Output: `./fix-reports/`.
- Mode: `$FIX_MODE` (default `dev`; valid `dev` | `prod` | `dryrun`).

═══════════════════════════════════════════════════════════════════
SCOPE
═══════════════════════════════════════════════════════════════════

LOW backlog batch (11 items). All low-risk, low-effort.

| ID | What |
|---|---|
| L-1 | Resolved by fix-agent-2A (verify only) |
| L-2 | Accept `@tootallnate/once` until jest-expo upgrades — write deferred-decision note |
| L-3 | Split `supabase/functions/stream-ai-message/index.ts` (879 LOC) — clears Semgrep timeout + ADR-016 |
| L-4 | Add lifecycle/cleanup scheduler or DELETE policy on `ai-audio` Storage bucket |
| L-5 | Posture note (Supabase manages storage tables; no force-rls) |
| L-6 | Resolved by fix-agent-2F (verify only) |
| L-7 | `cron.unschedule(jobid)` for 7 inactive jobs |
| L-8 | Consolidate 13 cron jobs (`net.http_post`) into `public.invoke_edge_function` helper |
| L-9 | Document `SYSTEM_ALERT_WINDOW` use case in Play Console submission notes |
| L-10 | Re-run `expo prebuild` before tagging release (manifest reconciliation) |
| L-11 | Move `docs/guides/diogo-setup-prompt.md` out of git or strip env values; remove dead old-dev anon key (`qhljwpvnewwwohoirfyc`) |

═══════════════════════════════════════════════════════════════════
PRE-CONDITIONS
═══════════════════════════════════════════════════════════════════
1. Phase 1, 2, 3 fix-agents have all landed where applicable.
2. Working tree clean.
3. `MODE=prod` requires `./fix-reports/4-dev-verified.sentinel`.

═══════════════════════════════════════════════════════════════════
WORKFLOW
═══════════════════════════════════════════════════════════════════

**STEP 0 — Sentinel (MODE=prod)**
```bash
[ "$FIX_MODE" = "prod" ] && {
  test -f ./fix-reports/4-dev-verified.sentinel || { echo "BLOCKED"; exit 1; }
}
```

**Per-finding logic:**

**L-1** — Verify `pnpm audit` reports no `icu-minify` LOW. If still present, escalate; else NOOP.

**L-2** — Write `./fix-reports/4-l2-accept.md` documenting the decision to accept `@tootallnate/once` until jest-expo upgrades. Include CVE link + dev-only justification.

**L-3** — Read `supabase/functions/stream-ai-message/index.ts` (879 LOC). Identify natural split points (handler, OpenAI streaming logic, error handling). Split into 3-4 files under `supabase/functions/stream-ai-message/`:
- `index.ts` (router + entry)
- `streaming.ts` (OpenAI streaming logic)
- `auth.ts` (Clerk JWT verification)
- `errors.ts` (error mapping)

Verify `deno check` and unit tests still pass after split.

**L-4** — Add `ai-audio` lifecycle migration:
```sql
-- delete ai-audio objects older than 30 days
create or replace function system.cleanup_ai_audio_old() returns void as $$
begin
  delete from storage.objects
  where bucket_id = 'ai-audio' and created_at < now() - interval '30 days';
end;
$$ language plpgsql security definer set search_path = public, pg_temp, storage;

revoke execute on function system.cleanup_ai_audio_old() from public, anon, authenticated;
grant execute on function system.cleanup_ai_audio_old() to service_role;

-- schedule via pg_cron
select cron.schedule('cleanup_ai_audio_old', '0 4 * * *',
                     'select system.cleanup_ai_audio_old();');
```

**L-5** — Write `./fix-reports/4-l5-posture-note.md` documenting that `storage.objects`/`storage.buckets` `forcerowsecurity` is managed by Supabase. No app-side action.

**L-6** — Verify scripts/restore-dev-branch.sh:81 has `?sslmode=verify-full`. NOOP if so.

**L-7** — Inspect `cron.job` for jobs in the audit's L-7 list:
```sql
select jobid, jobname, active from cron.job
where jobname in (
  'compute-trending-scores', 'cleanup-stale-trending', 'etf-data-job',
  'bulk-etf-all-0', 'bulk-etf-all-500', 'bulk-etf-all-1000', 'bulk-etf-all-1500'
);
```

For each (only if `active=false` per audit), unschedule:
```sql
select cron.unschedule(jobid) from cron.job where jobname=:name;
```

**L-8** — Consolidate. List the 13 jobs first:
```sql
select jobid, jobname, command from cron.job
where command ilike '%net.http_post%'
  and (jobname ilike 'asset-logos-%' or jobname ilike 'crypto-logos-weekly%');
```

For each, replace `net.http_post(...)` body with `select public.invoke_edge_function(...)` (signature mirrors). Generate one migration that updates `cron.job.command` for all 13.

This requires reading `public.invoke_edge_function` definition first to map args.

**L-9** — Write `./fix-reports/4-l9-play-console-note.md`:
```
Play Console submission note — SYSTEM_ALERT_WINDOW permission

Used by Travus for: <use case description; usually in-app overlay for alerts/notifications>
Reviewed in audit: 13-mobile-static.md sec LOW.
Impact: minimal — overlay is dismissable, used only for native push alerts.
```
The user pastes this into the Play Console Data safety / declaration section.

**L-10** — Add a release-prep note to the runbook (search `docs/release*.md` or `RELEASE.md`):
```diff
+ ## Pre-tag checklist
+ - [ ] Run `cd apps/mobile && npx expo prebuild --clean --platform all` to reconcile manifest drift
+   between app.json (versionCode/versionName) and the on-disk native projects.
+ - [ ] Verify `apps/mobile/android/app/build.gradle` `versionCode` and `versionName` match `app.json`.
```

**L-11** — Two actions:
1. Move `docs/guides/diogo-setup-prompt.md` out of git (`git rm` + put under `~/.travus-private/` or similar):
   ```bash
   git rm docs/guides/diogo-setup-prompt.md
   ```
   OR strip env-var values from the file using sed (replace JWT-shaped strings with `<REDACTED — see 1Password>`).
2. Remove the dead old-dev anon key from anywhere it appears:
   ```bash
   grep -rn 'qhljwpvnewwwohoirfyc' . --exclude-dir={node_modules,.git,audit,audit-reports,fix-reports} \
     | tee /tmp/4-l11-stale.tsv
   ```
   For each hit, replace the literal with the redaction marker via Edit tool.

═══════════════════════════════════════════════════════════════════

**STEP 1 — Iterate; capture results**

```bash
: > /tmp/4-status.tsv
for L in L-1 L-2 L-3 L-4 L-5 L-6 L-7 L-8 L-9 L-10 L-11; do
  # ... per-L logic above
  echo -e "$L\t<result>\t<notes>" >> /tmp/4-status.tsv
done
```

**STEP 2 — Open PRs (MODE=prod)**

Group:
- PR-1: L-3 (file split) + L-10 (release runbook)
- PR-2: L-4 + L-7 + L-8 (DB cleanup migration)
- PR-3: L-11 (secret hygiene in docs)
- PR-4: L-2 + L-5 + L-9 (decision notes only — single PR adding `./docs/security-audit-decisions/`)

**STEP 3 — Sentinel + report**

```bash
cat > ./fix-reports/4-dev-verified.sentinel <<EOF
fix-agent-4 dev verification PASSED at $(date -u +%Y-%m-%dT%H:%M:%SZ)
lows_resolved: <count>/11
EOF
```

`./fix-reports/4-result.md`:
```
FIX-AGENT-4 RESULT
==================
Mode: dev | prod | dryrun
Result: PASS | PARTIAL | BLOCKED

| ID | Result | Notes |
|---|---|---|
| L-1 | NOOP | resolved by fix-agent-2A |
| L-2 | DEFERRED | decision note: ./fix-reports/4-l2-accept.md |
| L-3 | PASS | stream-ai-message split into 4 files |
| L-4 | PASS | ai-audio lifecycle scheduler installed |
| L-5 | DOCUMENTED | posture note: ./fix-reports/4-l5-posture-note.md |
| L-6 | NOOP | resolved by fix-agent-2F |
| L-7 | PASS | <N>/7 inactive cron jobs unscheduled |
| L-8 | PASS | <N>/13 cron jobs consolidated |
| L-9 | DOCUMENTED | Play Console note: ./fix-reports/4-l9-play-console-note.md |
| L-10 | PASS | release runbook updated |
| L-11 | PASS | docs/guides/diogo-setup-prompt.md handled; <count> stale anon-key references redacted |

PRs (MODE=prod): <urls>

Next: fix-agent-5A-* (coverage gaps) and fix-agent-5B (new auditor prompts).
```

**STEP 4 — Final stdout:**
```
DONE | fix-agent-4 | <mode> | <pass>/<total> | ./fix-reports/4-result.md
```

═══════════════════════════════════════════════════════════════════
HARD AUTONOMY RULES
═══════════════════════════════════════════════════════════════════
- NEVER unschedule cron jobs marked `active=true`.
- NEVER auto-merge PRs.
- For L-3 split, do NOT change behaviour — pure refactor; if any test fails post-split, revert.
- BEGIN IMMEDIATELY.
