# Audit Skills — Mobile · Tauri · Supabase

Curated set of **67 cybersecurity skills** for auditing a stack composed of:

- **Mobile app** (iOS + Android)
- **Desktop app** built with **Tauri** (Rust core + system WebView)
- **Backend** on **Supabase** (Postgres + GoTrue auth + Storage + Edge Functions)

Each skill is a structured `SKILL.md` with YAML frontmatter and a Markdown body
(`When to Use / Prerequisites / Workflow / Key Concepts / Tools & Systems / Common Scenarios / Output Format`),
designed to be loaded into an AI agent (Claude Code, Cursor, etc.) on demand.

This is a **personal fork**, curated from the upstream
[mukul975/Anthropic-Cybersecurity-Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills) library.
All ~700 skills not relevant to this stack have been removed.

---

## Audit playbook — by phase

The 67 skills are organised below in the order a real audit would run them.

### 1. Threat modelling (start here)

| Skill | Purpose |
|---|---|
| `performing-threat-modeling-with-owasp-threat-dragon` | STRIDE on the full architecture: mobile → API → Postgres → Edge Functions |

### 2. Static analysis & supply chain

| Skill | Purpose |
|---|---|
| `implementing-semgrep-for-custom-sast-rules` | Custom SAST rules for Tauri (Rust + JS) and mobile (Kotlin/Swift) |
| `implementing-github-advanced-security-for-code-scanning` | CodeQL on the repo |
| `integrating-sast-into-github-actions-pipeline` | Wire SAST into CI |
| `performing-sca-dependency-scanning-with-snyk` | npm + cargo + native deps |
| `implementing-secret-scanning-with-gitleaks` | Hardcoded keys / Supabase service-role tokens |
| `implementing-secrets-scanning-in-ci-cd` | Pre-commit + CI gates |
| `implementing-devsecops-security-scanning` | End-to-end scanning pipeline |

### 3. Mobile app audit

| Skill | Purpose |
|---|---|
| `conducting-mobile-app-penetration-test` | Top-level pentest playbook |
| `performing-android-app-static-analysis-with-mobsf` | APK static analysis |
| `performing-dynamic-analysis-of-android-app` | Runtime analysis (Frida + drozer) |
| `reverse-engineering-android-malware-with-jadx` | Decompile your own APK to verify hardening |
| `testing-android-intents-for-vulnerabilities` | Exposed components, intent injection |
| `performing-ios-app-security-assessment` | iOS pentest playbook |
| `analyzing-ios-app-security-with-objection` | Runtime introspection |
| `reverse-engineering-ios-app-with-frida` | iOS dynamic instrumentation |
| `exploiting-deeplink-vulnerabilities` | Custom URL scheme + universal links |
| `exploiting-insecure-data-storage-in-mobile` | Keychain / Keystore / SharedPreferences review |
| `intercepting-mobile-traffic-with-burpsuite` | MITM with cert installed |
| `performing-mobile-app-certificate-pinning-bypass` | Verify pinning actually works |
| `testing-mobile-api-authentication` | Mobile-specific auth flaws |

### 4. Desktop / Tauri audit

| Skill | Purpose |
|---|---|
| `performing-thick-client-application-penetration-test` | Closest analog to Tauri (until Tauri-specific skill exists) |
| `performing-binary-exploitation-analysis` | Stack/heap analysis on the compiled binary |
| `reverse-engineering-rust-malware` | Rust binary triage techniques apply to your own binary |

> **Gap:** no skill in this set covers Tauri `tauri.conf.json` allowlist review,
> IPC command auditing, custom protocol handlers, or updater signing.
> Use the [official Tauri security guide](https://tauri.app/security/) alongside.

### 5. Backend / API audit (Supabase REST + GoTrue)

| Skill | Purpose |
|---|---|
| `conducting-api-security-testing` | Top-level API pentest |
| `performing-api-inventory-and-discovery` | Map every exposed endpoint |
| `testing-api-security-with-owasp-top-10` | OWASP API Top 10 coverage |
| `testing-api-authentication-weaknesses` | GoTrue auth flaws |
| `testing-api-for-broken-object-level-authorization` | **Critical for Supabase RLS** — BOLA tests RLS bypass |
| `testing-api-for-mass-assignment-vulnerability` | PostgREST mass-assignment |
| `testing-jwt-token-security` | Supabase JWT (anon + service_role) |
| `testing-for-json-web-token-vulnerabilities` | JWT alg confusion, key confusion |
| `testing-oauth2-implementation-flaws` | If using OAuth providers via GoTrue |
| `performing-oauth-scope-minimization-review` | Minimise OAuth scopes |
| `testing-cors-misconfiguration` | Supabase CORS for your domains |
| `performing-api-rate-limiting-bypass` | Rate-limit testing |
| `performing-api-fuzzing-with-restler` | Stateful API fuzzing |
| `performing-api-security-testing-with-postman` | Postman collections + tests |
| `testing-websocket-api-security` | Supabase Realtime |
| `performing-serverless-function-security-review` | Edge Functions (Deno) review |

### 6. Database / Postgres / RLS

| Skill | Purpose |
|---|---|
| `exploiting-sql-injection-vulnerabilities` | Generic SQLi patterns |
| `exploiting-sql-injection-with-sqlmap` | sqlmap against PostgREST endpoints |
| `performing-second-order-sql-injection` | Stored payloads through RLS |

### 7. Web / WebView (Tauri webview content + any web admin)

| Skill | Purpose |
|---|---|
| `performing-web-application-penetration-test` | Top-level web pentest |
| `performing-web-application-vulnerability-triage` | Triage findings |
| `testing-for-xss-vulnerabilities` | XSS in webview content |
| `testing-for-xss-vulnerabilities-with-burpsuite` | Burp-driven XSS |
| `performing-content-security-policy-bypass` | Verify CSP holds |
| `performing-clickjacking-attack-test` | Frame-busting / X-Frame-Options |
| `performing-csrf-attack-simulation` | CSRF on cookie-bearing endpoints |
| `performing-ssrf-vulnerability-exploitation` | SSRF in Edge Functions |
| `performing-blind-ssrf-exploitation` | Blind SSRF detection |
| `performing-directory-traversal-testing` | Path traversal (Storage paths) |
| `performing-http-parameter-pollution-attack` | HPP |
| `performing-security-headers-audit` | HSTS / CSP / X-Frame-Options / Referrer-Policy |
| `testing-for-broken-access-control` | Authorization holes |
| `testing-for-business-logic-vulnerabilities` | App-logic abuse |
| `testing-for-host-header-injection` | Host-header tricks |
| `testing-for-open-redirect-vulnerabilities` | Open redirects |
| `testing-for-sensitive-data-exposure` | PII / token leakage |
| `testing-for-xxe-injection-vulnerabilities` | XXE if XML parsed anywhere |
| `testing-for-xml-injection-vulnerabilities` | XML injection |

### 8. Cryptography

| Skill | Purpose |
|---|---|
| `performing-cryptographic-audit-of-application` | Key handling, algorithms, randomness |
| `performing-ssl-tls-security-assessment` | TLS configuration of all endpoints |

### 9. Vulnerability management

| Skill | Purpose |
|---|---|
| `prioritizing-vulnerabilities-with-cvss-scoring` | CVSS scoring of findings |
| `performing-cve-prioritization-with-kev-catalog` | CISA KEV exploit-in-the-wild filter |

---

## How to use this with Claude Code

```bash
# Clone into your project root (or alongside it)
git clone https://github.com/<your>/audit-skills-mobile-tauri-supabase.git

# Inside Claude Code, point it at this directory and ask:
#   "Run the threat-modeling skill on the architecture in /docs/architecture.md"
#   "Use the BOLA-testing skill against the endpoints in postman.json"
```

The agent reads each skill's frontmatter (~30 tokens) to find relevant ones,
then loads the full body (500–2,000 tokens) only for the matched skills.

---

## What this fork is **NOT**

- Not a substitute for [OWASP MASTG/MASVS](https://mas.owasp.org/) — read that for mobile
- Not a substitute for the [Tauri Security guide](https://tauri.app/security/) — Tauri-specific concerns are not covered here
- Not a substitute for a qualified human pentester
- Not affiliated with Anthropic PBC (the upstream repo's branding was misleading; that has been removed here)

---

## Repository layout

```
.
├── skills/                              # 67 SKILL.md (one folder each)
├── tools/validate-skill.py              # Frontmatter validator
├── .github/workflows/
│   ├── validate-skills.yml              # CI: runs validator
│   └── update-index.yml                 # CI: regenerates index.json on push
├── .claude-plugin/
│   ├── plugin.json
│   └── marketplace.json
├── index.json                           # Auto-generated skill index
└── README.md
```

## Validation

```bash
python3 tools/validate-skill.py --all
```

Required frontmatter fields: `name`, `description` (≥50 chars), `domain` (= `cybersecurity`),
`subdomain` (one of 14 allowed), `tags` (≥2). The CI workflow runs the same validator —
no drift between local and CI checks.

## License

Apache-2.0 (inherited from upstream). Skill content remains under its original authors' attribution.
