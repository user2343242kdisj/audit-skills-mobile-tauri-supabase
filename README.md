# Audit Skills — Mobile · Tauri · Supabase

Curated set of **68 cybersecurity skills** for auditing a stack composed of:

- **Mobile app** (iOS + Android)
- **Desktop app** built with **Tauri** (Rust core + system WebView)
- **Backend** on **Supabase** (Postgres + GoTrue auth + Storage + Edge Functions)

Plus **deep-dive audit references** in [`docs/`](docs/), **production-ready audit tools** in [`tools/`](tools/), and **drop-in templates** for CI and threat modeling in [`templates/`](templates/).

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
| `auditing-tauri-capabilities` | **Tauri-specific:** capability files, ACL invariants, high-risk identifier checklist, updater config, runtime addCapability search |
| `performing-thick-client-application-penetration-test` | Generic thick-client pentest workflow |
| `performing-binary-exploitation-analysis` | Stack/heap analysis on the compiled binary |
| `reverse-engineering-rust-malware` | Rust binary triage techniques apply to your own binary |

For deep technical reference, see [`docs/tauri-2-security-analysis.md`](docs/tauri-2-security-analysis.md) — 30-section audit guide with all CVEs, ACL schema, IPC mechanics, and a 9-block checklist.

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

## Audit tooling shipped in this repo

Production-ready scripts and templates that close gaps no public tool covers as of May 2026.

| Path | Purpose |
|---|---|
| [`tools/bola-harness.py`](tools/bola-harness.py) | BOLA / RLS-bypass scanner for Supabase PostgREST. Discovers tables via OpenAPI, probes cross-user access (READ / UPDATE / DELETE) with two test JWTs, fails CI on HIGH+ findings. Schemathesis is RLS-blind — this fills that gap. |
| [`tools/semgrep-edge-functions.yml`](tools/semgrep-edge-functions.yml) | 13 Semgrep rules for Supabase Edge Functions (Deno + TypeScript). Detects `service_role` from request, hardcoded JWTs, `Deno.env` leaks, CORS wildcards, missing JWT verify, RPC concat-injection, JWT decode without verify, deprecated packages. |
| [`tools/sbom-generate.sh`](tools/sbom-generate.sh) | CycloneDX SBOM generation for npm + cargo + Android + iOS, then Grype scan, fail on HIGH+. |
| [`tools/validate-skill.py`](tools/validate-skill.py) | Frontmatter validator for `SKILL.md` files; aligned with CI. |
| [`templates/security-workflow.yml`](templates/security-workflow.yml) | Drop-in `.github/workflows/security.yml` orchestrating 9 layers: ggshield, Squawk, Splinter, supabase test db, pgrls, Supashield, Schemathesis, BOLA harness, Semgrep, MobSF, cargo-audit, cargo-deny, testssl, SBOM, Grype. |
| [`templates/threat-model-pytm.py`](templates/threat-model-pytm.py) | pytm starter for a mobile + Tauri + Supabase architecture; auto-runs STRIDE + lists 16 custom audit-derived threats. |
| [`templates/claude-agents/`](templates/claude-agents/) | **21-subagent hierarchy** for Claude Code (`.claude/agents/`): 1 orchestrator + 20 narrow domain experts (7 Supabase + 5 Tauri + 4 Mobile + 4 cross-cutting). Drop into any repo. See [`templates/claude-agents/README.md`](templates/claude-agents/README.md). |
| [`templates/agent-prompts/`](templates/agent-prompts/) | **16 self-contained terminal prompts** for max-parallelism audits. Install into your app repo with one command (`curl … install.sh \| bash`), which clones this repo as `./audit/` (gitignored) and installs the `exec-agent` wrapper. Then run `exec-agent ./audit/templates/agent-prompts/numbered/agent-N.md` per terminal — each writes to `./audit-reports/<NN>-<name>.md`; the orchestrator (16) synthesises them into `00-FINAL.md`. Secrets resolved at runtime via `op read` (1Password) — no `.audit-env`. See [`templates/agent-prompts/README.md`](templates/agent-prompts/README.md). |

## Deep-dive audit references in this repo

| File | Lines | Coverage |
|---|---|---|
| [`docs/owasp-mas-analysis.md`](docs/owasp-mas-analysis.md) | 355 | OWASP MAS (MASVS v2.1 + MASTG + MASWE) for the mobile portion |
| [`docs/tauri-2-security-analysis.md`](docs/tauri-2-security-analysis.md) | 1260 | Tauri 2 security model, all 8 GHSAs, IPC mechanics, capability schema |
| [`docs/supabase-security-tools.md`](docs/supabase-security-tools.md) | 774 | Supabase security tooling stack (5 layers), CVE-2026-31813, MCP lethal trifecta, full Splinter rule list |

## How to use this with Claude Code

For the **automated agent-prompts audit workflow**, install into your app repo with the one-shot script:

```bash
cd ~/your-app-repo                  # e.g. ~/desktop/travus
curl -fsSL https://raw.githubusercontent.com/user2343242kdisj/audit-skills-mobile-tauri-supabase/main/install.sh | bash
# Clones this repo into ./audit/ (gitignored), installs exec-agent on PATH,
# creates ./audit-reports/, and gitignores both audit/ and audit-reports/.
```

Then run any of the 16 numbered agents per terminal. See [`templates/agent-prompts/numbered/README.md`](templates/agent-prompts/numbered/README.md).

For **ad-hoc skill use** (loading individual `SKILL.md` files into Claude Code/Cursor), you can also just clone anywhere and point your agent at the directory:

```bash
git clone https://github.com/user2343242kdisj/audit-skills-mobile-tauri-supabase.git
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
├── skills/                              # 68 SKILL.md (one folder each)
├── docs/                                # Deep audit references
│   ├── owasp-mas-analysis.md
│   ├── tauri-2-security-analysis.md
│   └── supabase-security-tools.md
├── tools/
│   ├── validate-skill.py                # Frontmatter validator
│   ├── bola-harness.py                  # PostgREST BOLA / RLS-bypass scanner
│   ├── semgrep-edge-functions.yml       # Semgrep rules for Deno Edge Fns
│   └── sbom-generate.sh                 # CycloneDX SBOM + Grype
├── templates/
│   ├── security-workflow.yml            # Drop-in CI orchestrator
│   ├── threat-model-pytm.py             # pytm starter
│   └── claude-agents/                   # 21 Claude Code subagents
│       ├── audit-orchestrator.md
│       ├── supabase-{rls,storage,edge-functions,auth,realtime,postgres,network}-auditor.md
│       ├── tauri-{capabilities,ipc,csp-webview,updater,binary-hardening}-auditor.md
│       ├── mobile-{static-analysis,dynamic-analysis,deeplinks,storage-crypto}-auditor.md
│       ├── {secrets-scanner,sast-dast,sbom-vuln}-coordinator.md
│       ├── threat-modeler.md
│       └── README.md
├── .github/workflows/
│   ├── validate-skills.yml              # CI: runs validator
│   └── update-index.yml                 # CI: regenerates index.json
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
