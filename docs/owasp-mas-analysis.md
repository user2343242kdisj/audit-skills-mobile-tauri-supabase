# OWASP MAS — Deep Analysis (May 2026)

Audit-grade reference for using the OWASP Mobile Application Security project as the methodology spine of a security audit on:

- Mobile app (iOS + Android)
- Desktop app built with Tauri (Rust core + system WebView)
- Backend on Supabase (Postgres + GoTrue + Storage + Edge Functions Deno)

Sources: live fetch of `mas.owasp.org`, GitHub repos `OWASP/masvs`, `OWASP/mastg`, `OWASP/maswe`, App Defense Alliance, NowSecure, Approov, Hiesen, AppSecSanta. Context7 library: `/owasp/mastg` (4379 code snippets, source High).

---

## 1. Executive verdict

OWASP MAS is the **only canonical, executable, atomic** framework for mobile-app audits in 2026. **For the mobile portion — direct fit, essential.** For **Tauri — partial fit (~85% of MASVS controls transfer)**, especially MASVS-PLATFORM, AUTH, CRYPTO, NETWORK. For **Supabase — explicitly out of scope** (use OWASP ASVS v5 + Supabase RLS / security checklist).

Project status: **flagship, active, but in unfinished transition** (MASTG v2 in 3-year refactor on `master`; MASWE in Beta with ~50% placeholders).

---

## 2. Architecture — three-layer pyramid

```
MASVS (what)  →  MASWE (what breaks)  →  MASTG (how to test)
v2.1.0           ~117 weaknesses         v2 rolling
24 controls      Beta                    ~231 atomic tests + 105 demos
```

| Layer | Repo | Status | Size |
|---|---|---|---|
| MASVS | OWASP/masvs | v2.1.0 (2024-01-18), maintenance | 8 categories, 24 controls |
| MASWE | OWASP/maswe | Beta, 105 open issues | 117 weaknesses, ~50% placeholders |
| MASTG | OWASP/mastg | rolling master (last push 2026-05-05) | 231 atomic tests · 105 demos · 140 tools · 117 knowledge · 40 best-practices · 34 Semgrep rules |

Leadership: Carlos Holguera (NowSecure) + Sven Schleier (Crayon Austria). Advocates: NowSecure, Guardsquare. Licence: CC BY-SA 4.0. Conference: MAScon co-located with OWASP Global AppSec EU, Vienna, 25–26 Jun 2026.

---

## 3. MASVS v2.1.0 — 8 categories, 24 controls (verbatim)

### MASVS-STORAGE
- **STORAGE-1** — *"The app securely stores sensitive data."*
- **STORAGE-2** — *"The app prevents leakage of sensitive data."*

### MASVS-CRYPTO
- **CRYPTO-1** — *"The app employs current strong cryptography and uses it according to industry best practices."*
- **CRYPTO-2** — *"The app performs key management according to industry best practices."*

### MASVS-AUTH
- **AUTH-1** — *"The app uses secure authentication and authorization protocols and follows the relevant best practices."*
- **AUTH-2** — *"The app performs local authentication securely according to the platform best practices."*
- **AUTH-3** — *"The app secures sensitive operations with additional authentication."*

### MASVS-NETWORK
- **NETWORK-1** — *"The app secures all network traffic according to the current best practices."*
- **NETWORK-2** — *"The app performs identity pinning for all remote endpoints under the developer's control."*

### MASVS-PLATFORM (key for Tauri)
- **PLATFORM-1** — *"The app uses IPC mechanisms securely."*
- **PLATFORM-2** — *"The app uses WebViews securely."*
- **PLATFORM-3** — *"The app uses the user interface securely."*

### MASVS-CODE
- **CODE-1** — *"The app requires an up-to-date platform version."*
- **CODE-2** — *"The app has a mechanism for enforcing app updates."*
- **CODE-3** — *"The app only uses software components without known vulnerabilities."*
- **CODE-4** — *"The app validates and sanitizes all untrusted inputs."*

### MASVS-RESILIENCE
- **RESILIENCE-1** — *"The app validates the integrity of the platform."*
- **RESILIENCE-2** — *"The app implements anti-tampering mechanisms."*
- **RESILIENCE-3** — *"The app implements anti-static analysis mechanisms."*
- **RESILIENCE-4** — *"The app implements anti-dynamic analysis techniques."*

### MASVS-PRIVACY (added v2.1.0)
- **PRIVACY-1** — *"The app minimizes access to sensitive data and resources."*
- **PRIVACY-2** — *"The app prevents identification of the user."*
- **PRIVACY-3** — *"The app is transparent about data collection and usage."*
- **PRIVACY-4** — *"The app offers user control over their data."*

**v1 → v2 audit-relevant change:** legacy `MSTG-*` IDs (e.g., `MSTG-STORAGE-13`) were collapsed into ~24 abstract controls. Reading pre-2023 reports requires translation via the `masvs-v1` field in the test-file YAML frontmatter.

---

## 4. Profiles — when each control applies

Profiles **live in MASTG**, not in MASVS. 4 profiles, 2 groups:

| Profile | Threat model (verbatim) | Apply to |
|---|---|---|
| **MAS-L1** | OS trusted; user not adversary; other installed apps are adversary | Universal baseline, low-risk data |
| **MAS-L2** | OS NOT trusted; user not adversary; other apps + 3rd party are adversary | Apps with sensitive data (finance/health/enterprise) |
| **MAS-R** | OS NOT trusted; **user IS adversary** (cheater/RE); other apps + 3rd party are adversary | Augments L1/L2, never standalone — apps protecting business assets |
| **MAS-P** | Privacy-focused | Orthogonal — any app with personal data |

Each atomic test in MASTG declares `profiles: [L1, L2]` in its YAML frontmatter. Endorsed combinations: L1+P, L1+P+R, L2+P, L2+P+R.

**Recommended for this stack:** typical mobile → **L2 + P**. If app stores critical secrets or is a target for cheating/RE → add **R**.

---

## 5. MASTG v2 — atomic test mechanics

Each test is a Markdown file with YAML frontmatter + 4 fixed sections (**Overview / Steps / Observation / Evaluation**). 8 top-level component types in the repo:

| Component | ID | Folder | Current count |
|---|---|---|---|
| Tests v2 (canonical) | `MASTG-TEST-NNNN` | `tests-beta/` | 88 Android + 51 iOS = **139** |
| Tests v1 (legacy) | `MASTG-TEST-NNNN` (deprecated) | `tests/` | 92 |
| Demos | `MASTG-DEMO-NNNN` | `demos/{android,ios}/MASVS-*/` | **105** |
| Techniques | `MASTG-TECH-NNNN` | `techniques/` | reusable methods |
| Tools | `MASTG-TOOL-NNNN` | `tools/{android,ios,generic,network}/` | **~140** |
| Best Practices | `MASTG-BEST-NNNN` | `best-practices/` | **40** |
| Knowledge | `MASTG-KNOW-NNNN` | `knowledge/` | **117** |
| Apps | `MASTG-APP-NNNN` | `apps/` | reference test apps |
| Rules | filename | `rules/` | **34 Semgrep rules** |

### Verbatim example — `MASTG-TEST-0244` (Missing Certificate Pinning)
```yaml
title: Missing Certificate Pinning in Network Traffic
platform: network
id: MASTG-TEST-0244
type: [network]
weakness: MASWE-0047
profiles: [L2]
knowledge: [MASTG-KNOW-0015]
```
> **Steps:** 1. Set up an interception proxy (`@MASTG-TECH-0011`). 2. Install on connected device, intercept. 3. Extract intercepted domains.
>
> **Evaluation:** Fails if any relevant domain was intercepted.

### Demo anatomy (executable proof-of-detection)
```
demos/android/MASVS-CRYPTO/MASTG-DEMO-0008/
├── MASTG-DEMO-0008.md         # frontmatter: test: MASTG-TEST-0205
├── MastgTest.kt               # source with the weakness
├── MastgTest_reversed.java    # decompiler output
├── run.sh                     # reproducible command
└── output.txt                 # captured tool output
```
Typical `run.sh`: `NO_COLOR=true semgrep -c ../../../../rules/mastg-android-non-random-use.yml ./MastgTest_reversed.java > output.txt`

---

## 6. MASWE — weakness catalogue (CWE bridge)

**117 entries (MASWE-0001 to MASWE-0118 with gaps), Beta, ~50% placeholders.** ID = `MASWE-NNNN`.

Frontmatter with **cross-mapping**:
```yaml
mappings:
  masvs-v1: [MSTG-CRYPTO-2]
  masvs-v2: [MASVS-CRYPTO-2]
  cwe: [331, 337, 338]
  android-risks: [...]
```

### Distribution by category

| Category | IDs | Count |
|---|---|---|
| MASVS-STORAGE | 0001-0007 (gap 0005) | 6 |
| MASVS-CRYPTO | 0009-0027 | 19 |
| MASVS-AUTH | 0005, 0028-0046 | 21 |
| MASVS-NETWORK | 0047-0052 | 6 |
| MASVS-PLATFORM | 0053-0074, 0118 | 23 |
| MASVS-CODE | 0075-0087, 0116 | 14 |
| MASVS-RESILIENCE | 0008, 0067, 0089-0107 | 21 |
| MASVS-PRIVACY | 0108-0115, 0117 | 9 |

### Audit-critical entries

| MASWE | Title | MASVS | CWE | Profile |
|---|---|---|---|---|
| **0001** | Insertion of Sensitive Data into Logs | STORAGE-2, PRIVACY-1 | 209, 359, 497, 532 | L1, L2, P |
| **0009** | Improper Cryptographic Key Generation | CRYPTO-2 | 331, 337, 338 | L1, L2 |
| **0047** | Insecure Identity Pinning | NETWORK-2 | 295 | L2 |
| **0055** | Sensitive Data Leaked via Screenshots/Recordings | PLATFORM-3, STORAGE-2 | 200, 359 | L2 |
| **0067** | Debuggable Flag Not Disabled | RESILIENCE-4 | 489 | R |

---

## 7. Mapping to the user's stack

### 7.1 Mobile (iOS + Android) — direct fit

100% coverage. All 8 MASVS categories apply literally. Recommended profile: **L2 + P** (typical mobile with auth + personal data via Supabase).

### 7.2 Tauri Desktop — partial fit

| MASVS Control | Tauri equivalent | Applicability |
|---|---|---|
| STORAGE-1/2 | `tauri::api::path::app_data_dir`, avoid plaintext credentials | Direct |
| CRYPTO-1/2 | `ring`/`rustls`/`age`, OS keychain via `keyring` crate | Direct |
| AUTH-1 | OAuth/PKCE against Supabase GoTrue | Direct |
| AUTH-2 | OS biometric (Touch ID, Windows Hello via `windows-rs`) | Direct |
| AUTH-3 | step-up auth for sensitive operations | Direct |
| NETWORK-1 | rustls TLS config, `connect_https` in `tauri.conf.json` | Direct |
| NETWORK-2 | cert pinning via `rustls::client::ServerCertVerifier` | Direct |
| **PLATFORM-1** | **Tauri command system, `invoke` handlers, capabilities v2** — direct analogue to Android Intents/iOS XPC | **Critical** |
| **PLATFORM-2** | **Tauri IS a WebView** — `tauri.conf.json > app > security > csp`, `dangerousDisableAssetCspModification`, IPC allowlist | **Critical** |
| PLATFORM-3 | UI sensitivity, OS-level screenshot prevention | Partial (MASTG assumes mobile screenshot APIs) |
| CODE-1/2/3/4 | `cargo audit`, npm audit on the WebView side, validation in Tauri commands | Direct |
| RESILIENCE-1/2/3/4 | Code signing (notarization macOS, Authenticode Windows), Tauri signed updater | Partial — **anti-rooting irrelevant**, code signing carries the weight |
| PRIVACY-1/2/3/4 | Same as mobile | Direct |

**Verdict:** ~85% transferable. MASTG `tests-beta/android/MASVS-PLATFORM/` for WebView (e.g., MASTG-TEST-0286 for `addJavascriptInterface`) directly applies to Tauri's WebView. RESILIENCE needs full desktop adaptation.

### 7.3 Supabase — out of scope

MASVS scope statement: *"It is important to note that the MASVS only covers the security of the mobile app (client-side). It does not contain specific controls for the remote endpoints (e.g. web services) [...] they should be verified against appropriate standards, such as the OWASP ASVS."*

**Implication:** the Supabase backend audit uses **OWASP ASVS v5** (web/API) + Supabase RLS audit + Supabase official security checklist. MAS does not cover.

---

## 8. Cross-reference with the curated 67-skill set

### Overlap (skills that **operationalise** MASVS controls)

| MASVS Control | Curated skill |
|---|---|
| STORAGE-1/2 | `exploiting-insecure-data-storage-in-mobile` |
| CRYPTO-1/2 | `performing-cryptographic-audit-of-application` |
| AUTH-1 | `testing-mobile-api-authentication`, `testing-jwt-token-security`, `testing-oauth2-implementation-flaws` |
| AUTH-2 | (partial gap — biometric specifics) |
| NETWORK-1 | `performing-ssl-tls-security-assessment`, `intercepting-mobile-traffic-with-burpsuite` |
| NETWORK-2 | `performing-mobile-app-certificate-pinning-bypass` |
| PLATFORM-1 | `testing-android-intents-for-vulnerabilities`, `exploiting-deeplink-vulnerabilities` |
| PLATFORM-2 | `testing-for-xss-vulnerabilities`, `performing-content-security-policy-bypass` |
| CODE-3 | `performing-sca-dependency-scanning-with-snyk`, `implementing-github-advanced-security-for-code-scanning` |
| CODE-4 | (web side covered; mobile side via MobSF static analysis) |
| RESILIENCE-1/4 | `analyzing-ios-app-security-with-objection`, `reverse-engineering-ios-app-with-frida`, `performing-android-app-static-analysis-with-mobsf`, `performing-dynamic-analysis-of-android-app` |

### Curated-skills gaps vs MAS
- **AUTH-2 biometric** — no skill covers BiometricPrompt/LAContext attack patterns
- **PRIVACY-*** — no skill covers tracking SDK enumeration, ATT compliance, iOS Privacy Manifest, Android Privacy Sandbox
- **CODE-1/2** — no skill covers platform-version enforcement / forced update mechanisms
- **MASWE catalogue** — curated skills use generic OWASP terminology, not MASWE IDs

### MAS gaps that the curated skills cover
- **API/backend testing** (MAS refuses; user has 16 skills)
- **SAST/DAST/SCA pipeline integration** (8 skills)
- **Threat modelling** (1 skill with OWASP Threat Dragon)
- **CVSS/KEV vulnerability prioritisation** (2 skills)

→ **MAS + curated skills are complementary, not redundant.**

---

## 9. Critical gaps in MAS itself (May 2026)

| Gap | Audit impact |
|---|---|
| **No AI/LLM coverage** (on-device, prompt injection in mobile) | If app has AI features, MAS doesn't help. Use OWASP GenAI Top 10. |
| **No PQC** (X25519MLKEM768 hybrid TLS, quantum-readiness) | No tests for post-quantum crypto migration |
| **No iOS 19 / Android 16 features** (Lockdown Mode, MTE, RCS E2EE, synced passkeys) | Audit doesn't cover latest platform features |
| **MASWE Beta, 50% placeholders** | Not all weaknesses have actionable guidance |
| **MASTG v2 incomplete after 3 years** | Must cross-reference legacy `tests/` with canonical `tests-beta/` |
| **MASA = Android L1 only** | No iOS certification, no L2 official |
| **MAS Crosscheck does not exist** (404) | No machine-readable mapping MASVS↔ASVS↔NIST↔SOC2 |
| **Supply chain / 3rd-party SDKs** | Placeholder coverage (MASWE-0094, 0095) |
| **Push tokens, biometric specifics, app groups, Privacy Sandbox** | Thin or absent |

---

## 10. Concrete audit playbook for this stack

### Phase 0 — Threat modelling (PRE-MAS)
Skill `performing-threat-modeling-with-owasp-threat-dragon` → STRIDE map of mobile + Tauri + Supabase architecture. Output: list of threats that informs profile selection (L1+P vs L2+P+R).

### Phase 1 — Profile selection
- Mobile: **L2 + P**
- Tauri: **L1 + P** (RESILIENCE adapted to desktop)

### Phase 2 — Static analysis (MASTG-driven)
1. **Android APK:** `performing-android-app-static-analysis-with-mobsf` + Semgrep with `mastg-android-*` rules from MASTG repo (`OWASP/mastg/rules/`)
2. **iOS IPA:** `performing-ios-app-security-assessment` + MobSF iOS
3. **Tauri Rust binary:** `cargo audit` + `cargo-deny` + skill `performing-binary-exploitation-analysis`
4. **WebView content (Tauri):** Semgrep + `testing-for-xss-vulnerabilities`
5. **Dependencies:** `performing-sca-dependency-scanning-with-snyk` for npm + cargo

### Phase 3 — Dynamic / runtime (Frida-based)
1. `analyzing-ios-app-security-with-objection` + `reverse-engineering-ios-app-with-frida`
2. `performing-dynamic-analysis-of-android-app` with objection
3. **MASTG-TEST-0244 (cert pinning runtime):** `intercepting-mobile-traffic-with-burpsuite` + `performing-mobile-app-certificate-pinning-bypass`

### Phase 4 — Network (NETWORK-1, NETWORK-2)
- TLS posture: `performing-ssl-tls-security-assessment` (test Supabase endpoints + edge function URLs)
- Cert pinning bypass: see Phase 3
- MITM with Burp: `intercepting-mobile-traffic-with-burpsuite`

### Phase 5 — Backend Supabase (OUTSIDE MAS)
- OWASP ASVS v5 web/API
- BOLA / RLS bypass: `testing-api-for-broken-object-level-authorization`
- JWT / auth: `testing-jwt-token-security` + `testing-oauth2-implementation-flaws`
- SQL injection (Postgres): `exploiting-sql-injection-vulnerabilities` + `exploiting-sql-injection-with-sqlmap`
- Edge Functions Deno: `performing-serverless-function-security-review`

### Phase 6 — Tauri-specific (OUTSIDE MAS)
1. **Audit `tauri.conf.json`:**
   - `app.security.csp` defined and strict (no `unsafe-inline` / `unsafe-eval`)
   - `app.security.dangerousDisableAssetCspModification: false`
   - `app.security.assetProtocol.scope` minimal
   - Capabilities v2 (`src-tauri/capabilities/*.json`) with minimal `permissions`
2. **Audit IPC commands:** every `#[tauri::command]` accepts validated inputs; no path traversal; no shell injection
3. **Updater:** `tauri.conf.json` `updater.pubkey` defined; signature enforced; HTTPS endpoint
4. **Code signing:** macOS notarisation + Windows Authenticode validated in pipeline
5. Canonical docs: https://tauri.app/security/

### Phase 7 — Reporting with MASWE taxonomy
Every finding cites `MASWE-NNNN + CWE-XXX + MASVS-CONTROL + MASTG-TEST-NNNN`. Allows comparison with CWE-based programs (NIST) and bug bounty platforms.

---

## 11. Canonical resources

**Project core:**
- Site: https://mas.owasp.org/
- MASVS: https://mas.owasp.org/MASVS/
- MASTG: https://mas.owasp.org/MASTG/
- MASWE: https://mas.owasp.org/MASWE/
- Profiles: https://mas.owasp.org/MASTG/0x03b-Testing-Profiles/
- Checklists: https://mas.owasp.org/checklists/
- Adoption (Google MASA, CREST, NIST, BSI): https://mas.owasp.org/MASTG/0x02b-MASVS-MASTG-Adoption/

**GitHub repos:**
- MASVS: https://github.com/OWASP/masvs
- MASTG: https://github.com/OWASP/mastg
- MASWE: https://github.com/OWASP/maswe
- Crackmes (training): https://mas.owasp.org/crackmes/

**Sample artefacts:**
- MASVS controls verbatim: https://github.com/OWASP/masvs/tree/master/controls
- MASTG v2 tests: https://github.com/OWASP/mastg/tree/master/tests-beta
- MASTG demos: https://github.com/OWASP/mastg/tree/master/demos
- MASTG Semgrep rules: https://github.com/OWASP/mastg/tree/master/rules
- CycloneDX SBOM of MASVS: https://github.com/OWASP/masvs/blob/master/OWASP_MASVS.cdx.json

**Certification programme:**
- App Defense Alliance MASA: https://appdefensealliance.dev/masa
- MASA assessors: https://appdefensealliance.dev/masa/masa-assessors

**Context7:** library ID `/owasp/mastg` (4379 code snippets, source High). Use `mcp__context7__query-docs` for specific implementation queries (e.g., "iOS keychain test methodology", "Android Frida hook for cert pinning").

---

## 12. Final recommendation

1. **Adopt MAS as the spine** of the mobile audit. Profile **L2 + P**.
2. **Cite MASWE IDs** in all findings → enables cross-reference with CWE/NIST.
3. **Combine:** Phase 0–4 = MAS-driven; Phase 5 = ASVS-driven (Supabase); Phase 6 = Tauri docs-driven; Phase 7 = MASWE taxonomy.
4. **Don't rely on MASA** for iOS certification (does not exist). For Android-only badge, go through ADA MASA via NowSecure / DEKRA / Bishop Fox.
5. **Beware `deprecated` tests** — always follow the `covered_by` field.
6. **Supplement MAS** with OWASP GenAI (if AI features), Tauri security guide (Tauri specifics), Supabase security checklist (RLS / JWT / Edge Functions).
