# Supabase Security Tooling — Deep Analysis & Recommendation (May 2026)

Audit-grade survey of every meaningful security tool for the Supabase stack (Postgres + PostgREST + GoTrue + Storage + Edge Functions Deno + Realtime), with a concrete recommended stack for the user's mobile + Tauri-desktop + Supabase audit.

Sources: live fetches of `supabase.com/docs`, `github.com/supabase/*`, GHSA + NVD + RustSec, vendor docs (GitGuardian, TruffleHog, Aikido, Snyk, Schemathesis, RESTler, Squawk, pgrls, plpgsql_check, pgTAP, Burp), and breach reports (DeepStrike, byteiota, Hacktron SupaPwn, Pomerium, General Analysis MCP). Context7 library: `/supabase/supabase` (6049 snippets, source High); also `/llmstxt/supabase_llms_txt` (1457).

---

## 1. Executive verdict — there is no single tool

**No single tool covers the full Supabase attack surface.** The audit needs a **5-layer stack**, half built-in and free, half external. The right answer is **NOT** "buy a commercial scanner" — it is a free, mostly-OSS layered toolchain built around **Splinter** (Supabase's own lint engine), augmented by a handful of community and OSS tools.

**The recommended stack** (detailed in §3, ordered by priority):

| Priority | Tool | Layer | License | Cost |
|---|---|---|---|---|
| 1 | **Splinter** + dashboard Security/Performance Advisors | RLS + schema lint | Apache 2.0 / built-in | Free |
| 2 | **`supabase test db` + pgTAP + basejump-supabase_test_helpers** | RLS test suite | OSS | Free |
| 3 | **GitGuardian `ggshield` + GitHub Push Protection + Supabase auto-revoke** | Secret hygiene | Freemium | Free tier |
| 4 | **Supashield** (community OSS) | Purpose-built Supabase audit (RLS + storage + CI JSON) | MIT | Free |
| 5 | **Squawk + pgrls + plpgsql_check** | Migration lint + RLS lint + PL/pgSQL static analysis | OSS | Free |
| 6 | **Schemathesis** (against PostgREST OpenAPI) + **OWASP ZAP** with auth scripts | API DAST | Apache 2.0 | Free |
| 7 | **`supabase inspect db` + pgaudit + supa_audit** | Runtime audit + telemetry | OSS / built-in | Free |
| 8 | **Supabomb** (offensive, periodic blackbox) | Adversarial scan | OSS | Free |
| 9 | (optional) **Aikido** | Commercial CSPM with Supabase awareness | Freemium | Free tier |
| 10 | (optional) **testssl.sh + jwt_tool + sqlmap + Burp Pro** | Manual deep-dive | Mixed | Burp $$$ |

This stack costs **€0** if you skip Burp Pro and Aikido paid tiers.

---

## 2. Why a single tool doesn't exist

The Supabase attack surface is **eight distinct layers**, each with different threat models and tooling traditions:

| Layer | What it is | Who tests it natively |
|---|---|---|
| Postgres schema/grants | DDL, roles, GRANT/REVOKE, search_path | DB linters (Splinter, schemalint, pgrls) |
| RLS policies | Per-row authorization gates | pgTAP test helpers + Splinter rules 0007/0010/0013/0015/0023/0024 |
| PostgREST API | Auto-generated REST from schema | API DAST (Schemathesis, RESTler, ZAP) |
| GoTrue auth | JWT issuance, MFA, OIDC, password policy | jwt_tool + Burp + integration tests |
| Storage | Bucket + object RLS via Postgres | Storage-specific scanners (Supashield, Supabomb) |
| Edge Functions | Deno runtime, secrets, CORS, JWT-verify | deno lint + Semgrep + Supabomb edge probes |
| Realtime | Phoenix-based pub/sub with private channels | Manual; no dedicated tool |
| Platform | Network, encryption, compliance, dashboard | CSPM (Aikido) + manual config audit |

Commercial scanners (Wiz, Snyk, Bearer, Lacework, Semgrep) treat Supabase as **generic Postgres + SaaS**. None advertise per-layer Supabase coverage in May 2026 except **Aikido** (CSPM-style detection of misconfigured RLS).

The **only purpose-built Supabase scanners** as of May 2026 are:
- **Splinter** (Supabase's own; 28 lint rules; powers dashboard advisors)
- **Supashield** (~100 stars; OSS CLI; RLS + storage + pgTAP export)
- **Supabomb** (offensive; ~19 stars)
- **SupaExplorer** (browser extension + cloud)
- **AuditYourApp**, **Vibe App Scanner** (commercial SaaS)
- **Supabase Exposure Check** (~124 stars; black-box JS-bundle key extractor)
- **Supabase RLS Checker** (Chrome extension)

Each covers a slice. The honest answer: **assemble a layered pipeline.**

---

## 3. The recommended stack — detailed

### Layer 1 — Splinter (lint, free, built-in)

**What it is:** Supabase's open-source Postgres lint engine. Powers the dashboard Security Advisor + Performance Advisor. Each lint is a Postgres view in the `lint` schema.

**Why it's first:** zero install, zero cost, runs against your live DB, catches the most common high-impact misconfigurations.

**The 28 rules (May 2026):**

| # | Name | Level | Category |
|---|---|---|---|
| 0001 | unindexed_foreign_keys | INFO | PERFORMANCE |
| **0002** | **auth_users_exposed** | **ERROR** | **SECURITY** |
| 0003 | auth_rls_initplan | WARN | PERFORMANCE |
| 0004 | no_primary_key | INFO | PERFORMANCE |
| 0005 | unused_index | INFO | PERFORMANCE |
| 0006 | multiple_permissive_policies | WARN | PERFORMANCE |
| **0007** | **policy_exists_rls_disabled** | **ERROR** | **SECURITY** |
| 0008 | rls_enabled_no_policy | INFO | SECURITY |
| 0009 | duplicate_index | WARN | PERFORMANCE |
| **0010** | **security_definer_view** | **ERROR** | **SECURITY** |
| 0011 | function_search_path_mutable | WARN | SECURITY |
| **0013** | **rls_disabled_in_public** | **ERROR** | **SECURITY** |
| 0014 | extension_in_public | WARN | SECURITY |
| **0015** | **rls_references_user_metadata** | **ERROR** | **SECURITY** |
| 0016 | materialized_view_in_api | WARN | SECURITY |
| 0017 | foreign_table_in_api | WARN | SECURITY |
| 0018 | unsupported_reg_types | WARN | SECURITY |
| **0019** | **insecure_queue_exposed_in_api** | **ERROR** | **SECURITY** |
| 0020 | table_bloat | INFO | PERFORMANCE |
| **0021** | **fkey_to_auth_unique** | **ERROR** | **SECURITY** |
| 0022 | extension_versions_outdated | WARN | SECURITY |
| **0023** | **sensitive_columns_exposed** | **ERROR** | **SECURITY** |
| 0024 | rls_policy_always_true | WARN | SECURITY |
| 0025 | public_bucket_allows_listing | WARN | SECURITY |
| 0026 | pg_graphql_anon_table_exposed | WARN | SECURITY |
| 0027 | pg_graphql_authenticated_table_exposed | WARN | SECURITY |
| 0028 | anon_security_definer_function_executable | WARN | SECURITY |
| 0029 | authenticated_security_definer_function_executable | WARN | SECURITY |

**The 7 ERRORs (audit must-fix):**
- 0002 `auth_users_exposed` — `auth.users` leaks via a view
- 0007 `policy_exists_rls_disabled` — silently broken auth (policies exist but not enforced)
- 0010 `security_definer_view` — view runs as creator, bypasses caller's RLS
- 0013 `rls_disabled_in_public` — table exposed via PostgREST without RLS
- 0015 `rls_references_user_metadata` — RLS reads `user_metadata` (user-editable!)
- 0019 `insecure_queue_exposed_in_api` — pgmq queue exposed
- 0021 `fkey_to_auth_unique` — FK to auth without uniqueness; allows enumeration

**Run in CI:**
```bash
psql "$DB_URL" -f splinter.sql
# Or per-rule:
psql "$DB_URL" -c 'select * from lint."0013_rls_disabled_in_public"'
```
Fail the build on any `level='ERROR'` row. Schedule daily on production via cron.

**Source & docs:**
- https://github.com/supabase/splinter
- https://supabase.github.io/splinter/
- https://supabase.com/docs/guides/database/database-advisors

### Layer 2 — `supabase test db` + pgTAP + basejump-supabase_test_helpers (RLS unit tests)

**What it is:** unit-test framework for RLS policies. `supabase test db` runs `pg_prove` over `supabase/tests/*.sql`. Each test rolls back its transaction. Mocking `auth.uid()` is done via Postgres role + JWT claims.

**Install pattern:**
```sql
-- Once, in your local + remote DB
select dbdev.install('basejump-supabase_test_helpers');
create extension "basejump-supabase_test_helpers";
```

**Test example (`supabase/tests/posts_rls.test.sql`):**
```sql
begin;
select plan(4);

-- Setup: 2 users
select tests.create_supabase_user('alice');
select tests.create_supabase_user('bob');
insert into posts (owner_id, body) values
  (tests.get_supabase_uid('alice'), 'alice secret'),
  (tests.get_supabase_uid('bob'),   'bob secret');

-- Test 1: RLS is enabled on posts
select check_test(tests.rls_enabled('public', 'posts'), true,
  'RLS is enabled on posts');

-- Test 2: alice sees only her own row
select tests.authenticate_as('alice');
select results_eq(
  $$select body from posts$$,
  $$values ('alice secret')$$,
  'alice cannot read bob''s posts');

-- Test 3: bob cannot update alice's post
select tests.authenticate_as('bob');
select throws_ok(
  $$update posts set body = 'pwned' where owner_id = (select tests.get_supabase_uid('alice'))$$,
  null,
  'bob cannot update alice''s posts via RLS');

-- Test 4: anon cannot read at all
select tests.clear_authentication();
select results_eq(
  $$select count(*)::int from posts$$,
  $$values (0)$$,
  'anon role sees no posts');

select * from finish();
rollback;
```

**Run:**
```bash
supabase test db --linked   # against the remote-linked DB
supabase test db --local    # against local container
```

**Why it's second:** Splinter catches structural issues; pgTAP catches semantic ones (the policy compiles but lets the wrong user through). **Both are necessary.**

**Sources:**
- https://supabase.com/docs/reference/cli/supabase-test-db
- https://supabase.com/docs/guides/database/extensions/pgtap
- https://github.com/usebasejump/supabase-test-helpers

### Layer 3 — Secret hygiene (GitGuardian + GitHub Push Protection + Supabase auto-revoke)

**The threat model (post-mortem-grounded):** the most common cause of Supabase breaches in 2024-2026 is **service_role key leaked to client** or **committed to public repo**. Examples: `nightcode112/storj-agent`, the "11% of vibe-coded apps leak Supabase keys" HN report (2026), the Lovable mass-leak (CVE-2025-48757).

**GitGuardian** has **two dedicated Supabase detectors:**
- `supabase_jwt_secret` — anon JWT (lower risk)
- `supabase_service_role_jwt` — service_role (CRITICAL, bypasses RLS)

```bash
brew install gitguardian/tap/ggshield
ggshield auth login
ggshield secret scan repo .
ggshield install --mode local-pre-commit
```

**GitHub Secret Scanning Partnership:** Supabase has been a partner since March 2022. The new `sb_publishable_...` / `sb_secret_...` key formats (introduced 2025) are **auto-revoked on detection** in public repos. Push Protection is rolling out in 2026.

**Action items:**
- Migrate from `anon`/`service_role` legacy JWTs → new `sb_publishable_...`/`sb_secret_...` format
- Enable asymmetric JWT signing (RS256/ES256) — clients verify with public JWKS
- Run `ggshield secret scan repo .` on every PR
- Run `ggshield secret scan path dist/` on the built mobile/Tauri bundles
- Audit Vite config for `envPrefix: ['TAURI_', 'VITE_']` — historic CVE-2023-46115 leaked Tauri keys this way; same risk for `SUPABASE_SERVICE_ROLE_KEY`

**Sources:**
- https://docs.gitguardian.com/secrets-detection/secrets-detection-engine/detectors/specifics/supabase_service_role_jwt
- https://supabase.com/blog/jwt-signing-keys
- https://github.blog/changelog/2022-03-28-supabase-is-now-a-github-secret-scanning-partner/

### Layer 4 — Supashield (purpose-built Supabase audit)

**What it is:** community OSS CLI (~100 stars, MIT, last release Feb 2026 v0.3.0). The most complete *Supabase-aware* audit tool that isn't Supabase's own Splinter.

**Capabilities:**
- RLS audit on all tables
- Storage policy audit
- Lint coverage
- Snapshot + diff (track drift over time)
- pgTAP test export (generates RLS unit tests for you)
- JSON output for CI gating

**Install + run:**
```bash
npm install -g @supashield/cli
supashield audit --url "$SUPABASE_URL" --service-role "$SUPABASE_SERVICE_ROLE_KEY"
supashield test-storage --bucket public --bucket avatars
supashield diff --baseline ./baseline.json
```

**Why it's fourth:** Splinter + pgTAP cover most ground; Supashield adds storage-specific checks and a CI-friendly JSON output that Splinter doesn't natively produce.

**Source:** https://github.com/Rodrigotari1/supashield

### Layer 5 — Squawk + pgrls + plpgsql_check (migration & policy static analysis)

**Squawk** — Postgres migration linter for `supabase/migrations/*.sql`. Catches:
- Lock-blocking DDL (`ALTER TABLE x ADD COLUMN y NOT NULL` on big table)
- Missing `IF EXISTS` / `IF NOT EXISTS`
- `CREATE INDEX` without `CONCURRENTLY`
- Dangerous types (`prefer-text-field` over `varchar`)
- GRANT/REVOKE in migrations (audit trail)

```yaml
# .github/workflows/migrations.yml
- uses: sbdchd/squawk-action@v1
  with:
    paths: supabase/migrations/*.sql
    fail_on_violations: true
```

**pgrls** (PyPI, OSS) — Postgres RLS lint with 20 rules + auto-fix. Categories: SEC001-SEC012 (security), PERF001-PERF002, HYG001-HYG002, VIEW001-VIEW004. The `pgrls diff` mode classifies policy changes as SAFE / BREAKING / REQUIRES_REVIEW / DANGEROUS — great for migration review.

```bash
pip install pgrls
pgrls lint --url "$DB_URL"
pgrls diff --before old-schema.sql --after new-schema.sql
pgrls fix --rule SEC003     # auto-fix function search_path
```

**plpgsql_check** — Postgres extension that statically analyzes PL/pgSQL function bodies. Catches:
- Dynamic SQL built via concatenation (SQL injection!)
- Type mismatches in embedded SQL
- Dead code
- Broken references after schema migration

Available as Supabase managed extension. Wired into `supabase db lint`.

```bash
supabase db lint --level error --fail-on warning
```

**Sources:**
- https://github.com/sbdchd/squawk
- https://pypi.org/project/pgrls/
- https://github.com/okbob/plpgsql_check
- https://supabase.com/docs/guides/database/extensions/plpgsql_check

### Layer 6 — API DAST (Schemathesis + OWASP ZAP)

**The opportunity:** PostgREST emits an OpenAPI 2.0 spec at the root path (`https://<projectref>.supabase.co/rest/v1/`). Property-based fuzzers consume this directly.

**Schemathesis** (best fit):
```bash
pip install schemathesis
SCHEMA="https://<ref>.supabase.co/rest/v1/"
TOKEN=$(supabase auth login ...)  # or your test JWT

# Anonymous role
schemathesis run "$SCHEMA" --base-url "$SCHEMA" --checks all

# Authenticated role
schemathesis run "$SCHEMA" --base-url "$SCHEMA" --checks all \
  --header "Authorization: Bearer $TOKEN" \
  --header "apikey: $ANON_KEY"
```

**Critical caveat:** Schemathesis is **RLS-blind by default** — it tests for "schema violations" and "auth bypass" but does not know that user A should not see user B's row. To detect BOLA (most important class for Supabase), inject a custom check that compares same-resource access across two distinct JWTs.

**OWASP ZAP** — for active scan with auth scripts:
- Use ZAP's OpenAPI add-on against PostgREST `/`
- Authentication script: `AddBearerTokenHeader.js` from community scripts repo
- Session-management script: re-runs `POST /auth/v1/token?grant_type=password` on 401
- Disable CSRF rules (REST API), emphasize SQLi + parameter manipulation + IDOR

**RESTler** (Microsoft, stateful): better than Schemathesis at multi-step workflows (create→read→mutate→delete). Useful for testing PostgREST RPC sequences.

**Burp Suite + JWT Editor + Auth Analyzer** — manual but the de-facto for serious BOLA testing. No Supabase-specific extension exists in the BApp Store; configure a Macro that calls `/auth/v1/token` and propagates JWT.

**Sources:**
- https://github.com/schemathesis/schemathesis
- https://www.securecodebox.io/blog/2023/09/01/automate-zap-with-authentication/
- https://github.com/microsoft/restler-fuzzer

### Layer 7 — Runtime audit (`supabase inspect db` + pgaudit + supa_audit)

**`supabase inspect db`** — read-only Postgres queries surfaced as CLI subcommands:
- `role-connections` — alert on `service_role` connection spikes
- `blocking` — locks held + waiters
- `long-running-queries` (>5 min)
- `outliers` / `calls` — frequent query patterns (DoS detection, RLS hot-paths)
- `unused-indexes` — bloat
- `seq-scans` — RLS performance issues

**pgaudit** — Postgres audit logging extension:
```sql
-- minimum recommended config
alter system set pgaudit.log = 'role,ddl';
alter system set pgaudit.log_relation = on;
select pg_reload_conf();
```

**Supabase caveat:** `pgaudit.log_parameter` is intentionally disabled because it would log `pgsodium`-encrypted column values in plaintext. Use session/object/role scoping instead.

**supa_audit** — Supabase's lightweight per-table trigger that writes change history to `audit.record_version`. Better than pgaudit for queryable audit (vs log files); trigger overhead noticeable above ~1k writes/sec.

```sql
create extension if not exists supa_audit;
select audit.enable_tracking('public.posts'::regclass);
```

**Sources:**
- https://supabase.com/docs/guides/database/inspect
- https://supabase.com/docs/guides/database/extensions/pgaudit
- https://github.com/supabase/supa_audit

### Layer 8 — Supabomb (offensive blackbox)

**What it is:** offensive recon + RLS bypass attempts. Does what an actual attacker would do.

**Capabilities:**
- Discovery: fingerprints Supabase via `X-Client-Info: supabase-js-web`, enumerates tables via REST
- RLS bypass attempts: tries common patterns (`?select=*&limit=1` against likely-named tables)
- JWT/edge function checks: validates whether Edge Functions enforce `verify_jwt`
- Storage perms probing
- Katana web crawler integration

**Use periodically (not in CI)** — quarterly external audit posture.

**Source:** https://github.com/ModernPentest/supabomb

### Layer 9 (optional) — Aikido (commercial CSPM)

The only major commercial vendor with explicit Supabase awareness in May 2026. Free tier covers 1 cloud account; paid tiers add CI integrations and runtime monitoring. Useful for organizations already using CSPM.

Source: https://www.aikido.dev/

### Layer 10 (optional) — manual deep-dive tools

- **testssl.sh** against `db.<projectref>.supabase.co:5432` and `:6543` (Supavisor pooler) — TLS posture, ciphersuite, cert validity
- **jwt_tool** — alg=none, RS→HS confusion, `kid` injection. Less relevant since Supabase moved to asymmetric JWKS, but still useful for self-hosted GoTrue.
- **sqlmap** with `--dbms=PostgreSQL` against PostgREST RPC endpoints (verify they're resistant)
- **Burp Suite Pro** — manual deep-dive on auth flows, BOLA chains
- **Supabase RLS Checker** Chrome extension — passive in-browser detection while you click around the app

---

## 4. Critical CVEs / advisories — fix NOW

### CVE-2026-31813 (GHSA-v36f-qvww-8w8m) — March 2026
- **Component:** `supabase/auth` (GoTrue)
- **Impact:** Apple/Azure OIDC ID token bypass — issuer not validated. Allows session minting for arbitrary users if you have Apple or Azure social login enabled.
- **Affected:** auth `< 2.185.0`
- **Fix:** upgrade auth ≥ **2.185.0**. Hosted Supabase already patched; self-hosters must upgrade.
- https://github.com/supabase/auth/security/advisories/GHSA-v36f-qvww-8w8m

### CVE-2025-48370 (GHSA-8r88-6cj9-9fh5) — 2025
- **Component:** `@supabase/auth-js`
- **Impact:** path traversal via non-UUID inputs in `getUserById`, `deleteUser`, `updateUserById`, `listFactors`, `deleteFactor`
- **Fix:** upgrade `@supabase/auth-js` ≥ **2.69.1**
- https://github.com/supabase/auth-js/security/advisories/GHSA-8r88-6cj9-9fh5

### GHSA-3529-5m8x-rpv3 — November 2024
- **Component:** `supabase/auth`
- **Impact:** Email link poisoning via `X-Forwarded-Host` / `X-Forwarded-Proto` — account takeover via crafted reset/verify URLs
- **Affected:** auth 2.67.1–2.163.0
- **Fix:** ≥ 2.163.1, set `GOTRUE_MAILER_EXTERNAL_HOSTS` allowlist, strip the X-Forwarded-* headers at any proxy in front

### CVE-2025-48757 — Lovable mass-RLS-leak
- **Cause:** AI-codegen (Lovable) shipped projects without RLS; ~170 apps + 13k users exposed
- **Lesson:** every project must run Splinter rule 0013 in CI; **do not trust AI-generated migrations** without RLS audit

### MCP "lethal trifecta" — July 2025
- **Cause:** dev's coding-agent MCP server runs with `service_role` (BYPASSRLS). Attacker files support ticket containing prompt-injection that the agent obeys, dumping `integration_tokens` back into the visible ticket UI.
- **Mitigation:** MCP servers must run **read-only**, never expose `service_role` to an LLM, treat all DB rows as untrusted instruction inputs.
- https://supabase.com/blog/defense-in-depth-mcp

### Postgres upstream CVEs to track
- **CVE-2024-10978** (SET ROLE bypass) — fixed 17.1/16.5/15.9/14.14
- **CVE-2025-1094** (libpq quoting → SQLi) — fixed 17.3/16.7/15.11
- **CVE-2025-8713** (optimizer stats expose RLS-hidden rows)
- **CVE-2025-8714/8715** (pg_dump RCE on restore)

Verify Supabase managed PG version via `select version();` and compare to https://www.postgresql.org/support/security/

### Disputed / non-actionable
- **CVE-2024-24213** (postgres-meta `/pg_meta/default/query` "SQLi") — vendor-disputed, intended-use behavior behind dashboard auth. Not actionable.
- **CVE-2025-57754** / **CVE-2025-57164** — third-party (FlowiseAI, eslint-ban-moment) pulling Supabase, not Supabase itself.

---

## 5. Mapping to MASVS controls (the user's audit spine)

The user's audit uses MASVS (see `docs/owasp-mas-analysis.md`). For the Supabase backend portion, MAS is **explicitly out of scope** — but ASVS-style mappings still apply, and several MASVS controls have backend implications:

| MASVS Control | Supabase concern | Tool layer |
|---|---|---|
| **AUTH-1** (server-side auth) | GoTrue JWT validation, OIDC pinning (CVE-2026-31813), MFA enforcement (`aal=aal2` in RLS) | Layer 6 (Schemathesis + manual JWT testing); upgrade auth |
| **NETWORK-1** | TLS posture on `:5432`, `:6543`, `*.supabase.co` | Layer 10 (testssl.sh) |
| **NETWORK-2** | Cert pinning to specific Supabase project endpoint | Client-side; verify Tauri's rustls config |
| **STORAGE-1/2** | Service-role key never on client; secrets via Supabase Vault | Layer 3 (GitGuardian) |
| **CRYPTO-1/2** | JWT signing keys (RS256/ES256), Vault for at-rest | Migrate to asymmetric (Supabase 2025 update) |
| **CODE-3** | `cargo audit` + `npm audit` includes Supabase client libs | CI; track GHSA feed |
| **CODE-4** | RLS = the auth boundary — every input must validate | Layer 1+2 (Splinter + pgTAP) |
| **PRIVACY-1** | Storage bucket access policies; data minimization | Layer 4 (Supashield); Splinter 0023, 0025 |

---

## 6. Cross-reference with the curated 67-skill set

| Curated skill | Applies to Supabase audit phase |
|---|---|
| `testing-api-for-broken-object-level-authorization` | Layer 6 — BOLA against PostgREST (RLS bypass tests) |
| `testing-api-for-mass-assignment-vulnerability` | PostgREST `Prefer: resolution=merge-duplicates` abuse |
| `testing-jwt-token-security` | Layer 10 — jwt_tool against GoTrue tokens |
| `testing-for-json-web-token-vulnerabilities` | JWT alg confusion (less relevant post-asymmetric) |
| `testing-oauth2-implementation-flaws` | OIDC bypass (CVE-2026-31813) |
| `performing-oauth-scope-minimization-review` | Audit GoTrue social provider scopes |
| `exploiting-sql-injection-vulnerabilities` | Layer 10 — sqlmap against PostgREST RPC |
| `exploiting-sql-injection-with-sqlmap` | Same as above |
| `performing-second-order-sql-injection` | Stored payloads through RLS |
| `performing-serverless-function-security-review` | Edge Functions (Deno) review |
| `testing-cors-misconfiguration` | Edge Function CORS (`@supabase/supabase-js/cors`) |
| `testing-websocket-api-security` | Realtime channels |
| `performing-api-fuzzing-with-restler` | Layer 6 — RESTler |
| `performing-api-rate-limiting-bypass` | Edge Functions don't have native rate limit — must DIY |
| `performing-api-inventory-and-discovery` | PostgREST `/` OpenAPI auto-discovery |
| `performing-cryptographic-audit-of-application` | JWKS rotation, Vault key handling |
| `performing-ssl-tls-security-assessment` | Layer 10 — testssl.sh |
| `implementing-secret-scanning-with-gitleaks` | Layer 3 — GitGuardian / TruffleHog / Gitleaks |
| `implementing-secrets-scanning-in-ci-cd` | Same |

**Gap:** no curated skill specifically covers Supabase RLS authoring/audit. The MASVS-PLATFORM controls don't cover backend either. **This document fills that gap.**

---

## 7. Concrete implementation plan

### Day 1 — Quick wins (60 minutes)
```bash
# 1. Run Splinter via dashboard
open "https://supabase.com/dashboard/project/<ref>/advisors/security"
# Fix every ERROR-level finding before proceeding

# 2. Install ggshield, scan repo + dist
brew install gitguardian/tap/ggshield
ggshield secret scan repo .
ggshield secret scan path dist/   # mobile + Tauri bundles

# 3. Verify auth version (rules out CVE-2026-31813)
psql "$DB_URL" -c "select version from auth.schema_migrations order by version desc limit 1"

# 4. Verify @supabase/auth-js >= 2.69.1
npm ls @supabase/auth-js
```

### Day 2-3 — Static analysis pipeline
```bash
# 1. Install tools
pip install pgrls schemathesis
npm install -g @supashield/cli squawk-cli
cargo install pg-permissions  # optional permission auditor

# 2. CI workflow .github/workflows/security.yml
#   - Splinter views → fail on ERROR
#   - supabase db lint --fail-on warning
#   - squawk supabase/migrations/*.sql
#   - pgrls lint --url $DB_URL
#   - ggshield secret scan ci
#   - supashield audit --output json
```

### Day 4-5 — RLS test suite
```bash
# 1. Install pgTAP + helpers (once per DB)
psql "$DB_URL" <<EOF
create extension if not exists pgtap;
select dbdev.install('basejump-supabase_test_helpers');
create extension "basejump-supabase_test_helpers";
EOF

# 2. Generate test scaffolds
supashield generate-tests > supabase/tests/000-generated-rls.test.sql

# 3. Add hand-written tests for every business-critical table:
#    - posts, comments, profiles, payments, etc.
#    - test: owner can read own / cannot read other
#    - test: anon cannot read
#    - test: service_role bypasses (sanity)

# 4. Run
supabase test db --linked
```

### Week 1 — DAST against PostgREST
```bash
# 1. Generate two test JWTs (anon + authenticated test user)
ANON_KEY=...
TEST_TOKEN=$(curl -s "https://<ref>.supabase.co/auth/v1/token?grant_type=password" \
  -H "apikey: $ANON_KEY" \
  -d '{"email":"audit@example.com","password":"..."}' | jq -r .access_token)

# 2. Run Schemathesis
schemathesis run "https://<ref>.supabase.co/rest/v1/" \
  --header "apikey: $ANON_KEY" \
  --header "Authorization: Bearer $TEST_TOKEN" \
  --checks all --max-examples 100

# 3. Custom BOLA check (Schemathesis is RLS-blind)
#    Write a Python harness that:
#    - Authenticates as user A, fetches /posts → records IDs
#    - Authenticates as user B, GETs /posts?id=eq.<A's ID>
#    - Fails if any A-only ID returns 200 with body
```

### Week 2 — Edge Functions + Realtime + Storage
```bash
# 1. Edge Functions
deno lint supabase/functions/
deno test supabase/functions/
# Manual review: every `createClient` should use the request JWT, not service_role
grep -r "SERVICE_ROLE" supabase/functions/
# Audit CORS: corsHeaders only allowed origins, not '*'

# 2. Realtime
# Verify all channels are private and RLS-gated on realtime.messages
psql "$DB_URL" -c "select * from pg_policies where schemaname='realtime'"

# 3. Storage
supashield test-storage --bucket public --bucket avatars
psql "$DB_URL" -c "select id, name, public, allowed_mime_types, file_size_limit from storage.buckets"
psql "$DB_URL" -c "select * from pg_policies where schemaname='storage'"
```

### Quarterly — Offensive blackbox
```bash
# 1. Supabomb (run from outside)
supabomb scan --url "https://<ref>.supabase.co" --anon-key "$ANON_KEY"

# 2. Manual TLS audit
testssl.sh "db.<ref>.supabase.co:5432"
testssl.sh "db.<ref>.supabase.co:6543"   # Supavisor pooler
testssl.sh "<ref>.supabase.co"

# 3. JWT manipulation (less critical post-asymmetric)
jwt_tool $TEST_TOKEN -T  # tamper mode
```

### Continuous monitoring
- Subscribe to https://github.com/supabase/auth/security/advisories (RSS)
- Subscribe to https://supabase.com/blog?q=security
- Cron daily: `supabase inspect db role-connections`, `blocking`, `long-running-queries`
- Watch GitHub Push Protection alerts (auto-revoke on `sb_secret_...`)

---

## 8. Hardening checklist (action-grade)

**Auth:**
- [ ] Migrate to new key format (`sb_publishable_*`, `sb_secret_*`)
- [ ] Enable asymmetric JWT signing (RS256/ES256)
- [ ] Enforce MFA (`aal=aal2`) on RLS policies for sensitive tables
- [ ] Enable HIBP password check (Pro+ tier)
- [ ] Captcha on signup (hCaptcha or Turnstile)
- [ ] Set `GOTRUE_MAILER_EXTERNAL_HOSTS` allowlist
- [ ] Auth ≥ 2.185.0 (CVE-2026-31813)
- [ ] `@supabase/auth-js` ≥ 2.69.1 (CVE-2025-48370)

**Database:**
- [ ] All public tables have RLS enabled (Splinter 0013)
- [ ] No policies exist on RLS-disabled tables (0007)
- [ ] No SECURITY DEFINER views (0010) without explicit justification
- [ ] No RLS reading `user_metadata` (0015 — user-editable!)
- [ ] All functions have explicit `search_path` (0011)
- [ ] No materialized/foreign tables exposed via PostgREST (0016, 0017)
- [ ] FKs to `auth.users` have unique constraints (0021)
- [ ] No PII columns exposed (0023)
- [ ] No `USING(true)` policies (0024)
- [ ] pgaudit enabled for `role,ddl`
- [ ] Vault for at-rest secrets

**API:**
- [ ] Disable Data API if app doesn't need PostgREST (use only Edge Functions)
- [ ] Disable GraphQL if not used (off-by-default in 2026)
- [ ] OpenAPI exposure limited (`openapi-mode=disabled` on PostgREST)
- [ ] No service_role exposed in client bundles (verify with `ggshield secret scan path dist/`)

**Storage:**
- [ ] No `public` buckets unless intentional
- [ ] Splinter 0025 (public_bucket_allows_listing) clean
- [ ] Signed URL TTL ≤ 7 days
- [ ] All buckets have RLS policies on `storage.objects`

**Edge Functions:**
- [ ] `verify_jwt = true` in `config.toml` for every public function
- [ ] No `Deno.env.toObject()` leaked in error responses
- [ ] CORS headers list specific origins, not `*`
- [ ] Service-role key NEVER passed from request body
- [ ] Rate limiting via Upstash/Redis token bucket

**Realtime:**
- [ ] All production channels are **private** (default since 2025)
- [ ] RLS on `realtime.messages` for broadcast/presence

**Network/Platform:**
- [ ] Network Restrictions allowlist enabled (Pro+)
- [ ] AWS PrivateLink (Team+/Enterprise) if available
- [ ] SSL Enforcement on
- [ ] Daily backup verified
- [ ] PITR enabled (Pro+)

**MCP-specific (if using MCP servers):**
- [ ] MCP server runs **read-only**
- [ ] Service-role NEVER exposed to LLM
- [ ] DB rows treated as untrusted (prompt-injection safe wrapping)

**CI/CD:**
- [ ] Splinter ERROR rules fail the build
- [ ] `supabase db lint` in CI
- [ ] `supabase test db` in CI (RLS unit tests)
- [ ] `ggshield secret scan ci` on every commit
- [ ] Squawk on `supabase/migrations/*.sql`
- [ ] pgrls lint in CI
- [ ] Supashield audit JSON output gated

---

## 9. Bug bounty program

- HackerOne: https://hackerone.com/supabase
- VDP through 2025; **paid bounties launching 2026**
- Scope: Supabase platform infra, PostgREST, Auth flows, service-role isolation, Realtime, Storage, Edge Functions, network segmentation
- Out of scope: DoS, request flooding, cross-tenant attacks, clickjacking on non-sensitive pages, missing security headers, user enumeration
- Customer project domains in scope **only for the researcher's own account**
- Median: 8h first response, 10h triage, 2 days resolution
- Notable: $25k paid for SupaPwn (Hacktron, Oct 2025) despite VDP framing

`security.txt`: https://supabase.com/.well-known/security.txt
Email (scanner pre-approval): security@supabase.io

---

## 10. Compliance / platform posture (May 2026)

- **SOC 2 Type 2** — annual; report on Team+
- **HIPAA** — eligible on Team+ with add-on + signed BAA
- **ISO 27001** — certified
- **GDPR** — DPA + Transfer Impact Assessment available
- **PCI DSS** — NOT certified end-to-end; Stripe is sub-processor
- **Cloud:** AWS only (12 regions)
- **Encryption at rest:** AES-256, FIPS 140-2 HSM
- **TLS:** 1.2 with modern ciphersuites
- **Sub-processors:** Stripe, Cloudflare

Trust Center: https://trust.supabase.io/controls

---

## 11. Critical gaps (what NO tool covers)

1. **No PostgREST-aware DAST** — Schemathesis is RLS-blind; no public tool reasons about `select=`, embedded resources, `or=` filters from a RLS-bypass perspective.
2. **No SAST rule pack for Supabase Edge Functions** — common anti-patterns (service_role from JWT, unsafe `rpc()`, `Deno.env` leak) are uncovered by Snyk/Semgrep/Bearer.
3. **No "S3 Bucket Finder" equivalent for Supabase Storage** — no public scanner treats `storage.buckets` as a first-class internet attack surface.
4. **No continuous threat-intel for Supabase project URLs** comparable to AWS canary tokens.
5. **No specialised GoTrue testing tool** — generic JWT tools work, but Supabase-Auth flows (refresh-token rotation, asymmetric key migration, anonymous sign-ins, MFA, password-grant deprecation) need bespoke playbooks.
6. **No commercial enterprise scanner** advertises Supabase coverage by name except Aikido (CSPM).

For these gaps: hand-written Schemathesis harnesses, custom Semgrep rules, manual storage policy review, manual JWT flow testing.

---

## 12. URLs (canonical)

### Native
- https://supabase.com/docs/guides/security
- https://supabase.com/docs/guides/database/database-advisors
- https://supabase.com/docs/guides/database/postgres/row-level-security
- https://supabase.com/docs/guides/auth/auth-mfa
- https://supabase.com/docs/guides/storage/security/access-control
- https://supabase.com/docs/guides/functions/auth
- https://supabase.com/docs/reference/cli/supabase-test-db
- https://supabase.com/docs/reference/cli/supabase-db-lint
- https://supabase.com/docs/guides/database/inspect
- https://supabase.com/docs/guides/database/extensions/pgaudit
- https://supabase.com/docs/guides/security/platform-audit-logs
- https://supabase.com/blog/supabase-security-2025-retro
- https://supabase.com/blog/jwt-signing-keys
- https://supabase.com/blog/defense-in-depth-mcp
- https://supabase.com/security
- https://supabase.com/.well-known/security.txt
- https://hackerone.com/supabase
- https://trust.supabase.io/controls

### Tools
- https://github.com/supabase/splinter
- https://supabase.github.io/splinter/
- https://github.com/Rodrigotari1/supashield
- https://github.com/ModernPentest/supabomb
- https://github.com/ToritoIO/SupaExplorer
- https://github.com/usebasejump/supabase-test-helpers
- https://github.com/supabase/supa_audit
- https://github.com/sbdchd/squawk
- https://github.com/okbob/plpgsql_check
- https://pypi.org/project/pgrls/
- https://github.com/schemathesis/schemathesis
- https://github.com/microsoft/restler-fuzzer
- https://github.com/akto-api-security/akto
- https://github.com/openclarity/apiclarity
- https://www.audityour.app/
- https://vibeappscanner.com/supabase-security
- https://www.aikido.dev/
- https://docs.gitguardian.com/secrets-detection/secrets-detection-engine/detectors/specifics/supabase_service_role_jwt
- https://github.com/trufflesecurity/trufflehog
- https://github.com/Squarespace/pgbedrock
- https://github.com/testssl/testssl.sh
- https://github.com/ticarpi/jwt_tool

### Advisories (must-track)
- https://github.com/supabase/auth/security/advisories
- https://github.com/supabase/auth/security/advisories/GHSA-v36f-qvww-8w8m (CVE-2026-31813)
- https://github.com/supabase/auth/security/advisories/GHSA-3529-5m8x-rpv3
- https://github.com/supabase/auth-js/security/advisories/GHSA-8r88-6cj9-9fh5 (CVE-2025-48370)
- https://www.postgresql.org/support/security/

### Research / breach reports
- https://deepstrike.io/blog/hacking-thousands-of-misconfigured-supabase-instances-at-scale
- https://mattpalmer.io/posts/2025/05/CVE-2025-48757/
- https://generalanalysis.com/blog/supabase-mcp-blog
- https://simonwillison.net/2025/Jul/6/supabase-mcp-lethal-trifecta/
- https://www.hacktron.ai/blog/supapwn
- https://www.pomerium.com/blog/when-ai-has-root-lessons-from-the-supabase-mcp-data-leak

### Context7
- Library ID: `/supabase/supabase` (6049 snippets, source High, score 81.95)
- Alternates: `/llmstxt/supabase_llms_txt` (1457), `/supabase/auth` (170), `/supabase/cli` (136)
- Use `mcp__context7__query-docs` for specific questions ("Supabase RLS policy patterns", "GoTrue MFA enrollment flow", "Edge Function JWT verification")
