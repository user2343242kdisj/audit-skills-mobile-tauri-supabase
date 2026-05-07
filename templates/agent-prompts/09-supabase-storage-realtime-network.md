# Terminal: supabase-storage + realtime + network (merged) (Phase 2 — parallel)

This terminal runs three merged subagents in a single autonomous pass:
- `supabase-storage-auditor`
- `supabase-realtime-auditor`
- `supabase-network-auditor`

## Pre-flight

```bash
cd ~/desktop/travus
source .audit-env
mkdir -p audit-reports
brew install postgresql jq 2>/dev/null
brew install --cask docker 2>/dev/null   # for testssl.sh
docker info >/dev/null 2>&1 || open -a Docker
claude --dangerously-skip-permissions
```

## Required env

- `SUPABASE_DB_URL` — read-only role recommended
- `SUPABASE_PROJECT_REF` — the `<ref>` portion of `<ref>.supabase.co`
- `SUPABASE_ACCESS_TOKEN` — optional; required only for Network Restrictions + region check via Management API
- `AUDIT_SKILLS_PATH`

## Paste this entire block into Claude Code

---

You are operating as **three merged subagents in one terminal**: `supabase-storage-auditor`, `supabase-realtime-auditor`, and `supabase-network-auditor`. Adopt all three roles, knowledge bases, and output formats defined verbatim in:

  `$AUDIT_SKILLS_PATH/templates/claude-agents/supabase-storage-auditor.md`
  `$AUDIT_SKILLS_PATH/templates/claude-agents/supabase-realtime-auditor.md`
  `$AUDIT_SKILLS_PATH/templates/claude-agents/supabase-network-auditor.md`

Read all three files in FULL via the Read tool now. Also Read `$AUDIT_SKILLS_PATH/docs/supabase-security-tools.md` sections covering Splinter 0025, broadcast/presence authorization, Network Restrictions, region/encryption posture, and platform compliance.

REQUIRED INPUT
- `$SUPABASE_DB_URL` and `$SUPABASE_PROJECT_REF`. If either unset, write `BLOCKED: SUPABASE_DB_URL or SUPABASE_PROJECT_REF not set` to `./audit-reports/09-supabase-storage-realtime-network.md` and exit.
- `$SUPABASE_ACCESS_TOKEN` is optional. If unset, mark Network Restrictions + region check as `not-available (no Management API token)` and continue.

WORKFLOW (autonomous)

### A. STORAGE

1. **Bucket inventory:**
   ```bash
   psql "$SUPABASE_DB_URL" -At --csv \
     -c "select id, name, owner, public, allowed_mime_types::text, file_size_limit, created_at
         from storage.buckets order by name" > /tmp/storage-buckets.csv
   ```
   Flag every bucket where `public=true` → **MEDIUM**, `allowed_mime_types is null or '{}'` → **HIGH** (XSS/phishing primitive via uploaded HTML/SVG), `file_size_limit is null` → **LOW** (upload-DoS).

2. **Policies on `storage.objects`:**
   ```bash
   psql "$SUPABASE_DB_URL" -At --csv \
     -c "select policyname, cmd, roles::text, qual, with_check
         from pg_policies
         where schemaname='storage' and tablename='objects'
         order by policyname" > /tmp/storage-policies.csv
   ```
   For each: missing `bucket_id = ...` filter in `qual` → policy bleeds across buckets → **HIGH**. `qual = 'true'` or null on SELECT for `authenticated` → **CRITICAL**.

3. **Splinter rule 0025 (public_bucket_allows_listing):**
   ```bash
   curl -fsSL https://raw.githubusercontent.com/supabase/splinter/main/splinter.sql -o /tmp/splinter.sql
   psql "$SUPABASE_DB_URL" -f /tmp/splinter.sql > /dev/null 2>&1
   psql "$SUPABASE_DB_URL" -At --csv \
     -c "select name, level, title, detail from splinter
         where name = '0025_public_bucket_allows_listing'" > /tmp/splinter-storage.csv
   ```
   Any hit → **HIGH** (mass enumeration risk).

4. **`storage.buckets` RLS itself:**
   ```bash
   psql "$SUPABASE_DB_URL" -At --csv \
     -c "select relrowsecurity, relforcerowsecurity
         from pg_class where relname='buckets' and relnamespace='storage'::regnamespace" \
     > /tmp/storage-buckets-rls.csv
   ```
   If `relrowsecurity=false` → anon can list every bucket name → **MEDIUM** (info disclosure).

5. **Signed-URL TTL audit + Tauri convertFileSrc usage in client code:**
   ```bash
   rg -n "createSignedUrl\s*\(" . --glob '!node_modules' --glob '!dist' \
     -A 1 > /tmp/signed-url-sites.txt 2>/dev/null
   rg -n "createSignedUploadUrl\s*\(" . --glob '!node_modules' --glob '!dist' \
     -A 1 >> /tmp/signed-url-sites.txt 2>/dev/null
   rg -n "convertFileSrc\s*\(" . --glob '!node_modules' --glob '!target' \
     > /tmp/convert-file-src.txt 2>/dev/null
   ```
   Parse `expiresIn:` numerics. Any > 604800 (7 days) → **MEDIUM**. Any unbounded `createSignedUploadUrl` (no `fileSizeLimit` / `contentType` arg) → **HIGH**.

### B. REALTIME

6. **Channel sites in client code:**
   ```bash
   rg -nA 8 "supabase\.channel\s*\(" . \
     --glob '!node_modules' --glob '!dist' --glob '!target' \
     > /tmp/realtime-channels.txt 2>/dev/null
   ```
   For each match, classify:
   - `private: true` present? (regex on the 8-line context window)
   - Channel name: static literal vs interpolated `${...}` (user-derived)
   - Event types: `broadcast` / `presence` / `postgres_changes`
   Any channel without `private: true` → **HIGH** (public channel; any anon client with the URL joins).

7. **`realtime.messages` RLS policies:**
   ```bash
   psql "$SUPABASE_DB_URL" -At --csv \
     -c "select policyname, cmd, roles::text, qual, with_check
         from pg_policies
         where schemaname='realtime' and tablename='messages'
         order by policyname" > /tmp/realtime-policies.csv
   ```
   Zero policies + private channels in code → channels deny-by-default (functional bug, not security) but flag as **MEDIUM** misconfig. Any policy with `qual='true'` on SELECT for `authenticated` → **CRITICAL** (every authenticated user reads every broadcast).

8. **Realtime publication membership (postgres-changes leak surface):**
   ```bash
   psql "$SUPABASE_DB_URL" -At --csv \
     -c "select pubname, pubowner::regrole, puballtables, pubinsert, pubupdate, pubdelete
         from pg_publication where pubname='supabase_realtime'" > /tmp/realtime-pub.csv
   psql "$SUPABASE_DB_URL" -At --csv \
     -c "select schemaname, tablename
         from pg_publication_tables where pubname='supabase_realtime'
         order by schemaname, tablename" > /tmp/realtime-pub-tables.csv
   ```
   `puballtables=true` → **CRITICAL** (every change in every table fan-outs to subscribers).

9. **For each table in `supabase_realtime`, verify RLS is on:**
   ```bash
   psql "$SUPABASE_DB_URL" -At --csv \
     -c "select t.schemaname, t.tablename, t.rowsecurity
         from pg_publication_tables p
         join pg_tables t
           on t.schemaname=p.schemaname and t.tablename=p.tablename
         where p.pubname='supabase_realtime'
         order by 1,2" > /tmp/realtime-table-rls.csv
   ```
   Any `rowsecurity=false` row → **CRITICAL** (every change broadcast to every subscriber).

### C. NETWORK / TLS / PLATFORM

10. **TLS posture, API endpoint (`<ref>.supabase.co:443`):**
    ```bash
    docker run --rm drwetter/testssl.sh:latest --quiet \
      --severity HIGH --jsonfile-pretty /tmp/api.json \
      "${SUPABASE_PROJECT_REF}.supabase.co" > /tmp/testssl-api.log 2>&1
    ```

11. **TLS posture, Postgres direct (`db.<ref>.supabase.co:5432`):**
    ```bash
    docker run --rm drwetter/testssl.sh:latest --quiet --starttls postgres \
      --severity HIGH --jsonfile-pretty /tmp/db5432.json \
      "db.${SUPABASE_PROJECT_REF}.supabase.co:5432" > /tmp/testssl-5432.log 2>&1
    ```

12. **TLS posture, Supavisor pooler (`db.<ref>.supabase.co:6543`):**
    ```bash
    docker run --rm drwetter/testssl.sh:latest --quiet --starttls postgres \
      --severity HIGH --jsonfile-pretty /tmp/db6543.json \
      "db.${SUPABASE_PROJECT_REF}.supabase.co:6543" > /tmp/testssl-6543.log 2>&1
    ```
    For each of 10–12: parse JSON. Flag any TLS 1.0/1.1 enabled → **HIGH**, any cert-chain error → **CRITICAL**, no HSTS preload on 443 → **LOW**, weak cipher (RC4/3DES/CBC<128) → **HIGH**.

13. **Network Restrictions (Pro+) via Management API:**
    ```bash
    if [ -n "$SUPABASE_ACCESS_TOKEN" ]; then
      curl -fsS "https://api.supabase.com/v1/projects/${SUPABASE_PROJECT_REF}/network-restrictions" \
        -H "Authorization: Bearer $SUPABASE_ACCESS_TOKEN" \
        | jq > /tmp/net-restrictions.json
    else
      echo '{"status":"not-available"}' > /tmp/net-restrictions.json
    fi
    ```
    If `disallowed_cidrs` does not include `0.0.0.0/0` AND `::/0` while there is at least one Edge Function hitting `db.<ref>...` → **HIGH** (internet-reachable Postgres).

14. **Region + plan check:**
    ```bash
    if [ -n "$SUPABASE_ACCESS_TOKEN" ]; then
      curl -fsS "https://api.supabase.com/v1/projects/${SUPABASE_PROJECT_REF}" \
        -H "Authorization: Bearer $SUPABASE_ACCESS_TOKEN" \
        | jq '{region, status, organization_id}' > /tmp/project-info.json
    fi
    ```
    Cross-reference with the 12 supported regions. EU users on non-EU region → **MEDIUM** (GDPR DPA review).

15. **Client connection-string sslmode audit:**
    ```bash
    rg -n "postgres(ql)?://[^@\s\"']+@(db\.)?[a-z0-9]+\.(supabase|pooler\.supabase)\.co" . \
      --glob '!node_modules' --glob '!target' --glob '!dist' \
      > /tmp/conn-strings.txt 2>/dev/null
    rg -n "sslmode\s*=\s*\w+" . \
      --glob '!node_modules' --glob '!target' --glob '!dist' \
      > /tmp/sslmode.txt 2>/dev/null
    ```
    Per match: classify `sslmode=` as `verify-full` (good), `require` (HIGH — accepts MITM during STARTTLS), `prefer` / missing (CRITICAL — silent downgrade), `disable` (CRITICAL).

16. **Tauri Rust client cert validation (sanity check):**
    ```bash
    rg -n "rustls::ClientConfig|webpki_roots|RootCertStore|danger_accept_invalid" . \
      --glob '!target' --glob '!node_modules' \
      > /tmp/rust-tls.txt 2>/dev/null
    ```
    Any `danger_accept_invalid_certs(true)` or `with_root_certificates(Vec::new())` → **CRITICAL**.

17. **Write merged report** to `./audit-reports/09-supabase-storage-realtime-network.md`. Use three top-level sections in this order: STORAGE, REALTIME, NETWORK / PLATFORM, each following the corresponding agent file's output format. End with a single REMEDIATION block aggregating all findings ordered CRITICAL → HIGH → MEDIUM → LOW with file:line references where applicable.

OUTPUT
- File: `./audit-reports/09-supabase-storage-realtime-network.md`
- Final stdout: `DONE | supabase-storage-realtime-network | <CRITICAL> CRITICAL | <HIGH> HIGH | ./audit-reports/09-supabase-storage-realtime-network.md`

AUTONOMY RULES (HARD)
- NEVER write SQL that mutates state. SELECT only.
- NEVER call any Management API endpoint other than the two read-only GETs in steps 13 + 14.
- NEVER push to git.
- NEVER write outside `./audit-reports/` and `/tmp/`.
- If Docker is not running, mark steps 10–12 as `not-available (Docker daemon not running)` and continue. Do NOT prompt for sudo.
- If a single probe fails (permission denied, network timeout, missing extension), record `not-available` for that finding and continue — do NOT abort.
- Do NOT ask the user any questions. If required env is missing, emit BLOCKED line and exit cleanly.

BEGIN.
