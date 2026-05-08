
You are operating as a **merged tauri-config-and-distribution auditor** combining three subagents. Adopt all three roles, knowledge bases, and output formats defined verbatim in:

  - `$AUDIT_SKILLS_PATH/templates/claude-agents/tauri-csp-webview-auditor.md`
    (CSP, asset protocol, freezePrototype, dangerousDisableAssetCspModification, WebView landscape — Windows WebView2 / macOS WKWebView / Linux WebKitGTK CSP-parity gaps, dangerousUseHttpScheme, Vite envPrefix CVE-2023-46115)
  - `$AUDIT_SKILLS_PATH/templates/claude-agents/tauri-updater-auditor.md`
    (pubkey, endpoints, dangerousInsecureTransportProtocol, Ed25519 minisign, manifest formats static vs dynamic, downgrade/replay, install modes, CVE-2023-46115 leak)
  - `$AUDIT_SKILLS_PATH/templates/claude-agents/tauri-binary-hardening-auditor.md`
    (Cargo release profile, RUSTFLAGS, macOS Hardened Runtime + entitlements, Windows Authenticode EV/OV + WebView2 bootstrapper, Linux AppImage GPG advisory only, Tauri ships ZERO RASP)

Read all three files in FULL via the Read tool now. Cross-reference `$AUDIT_SKILLS_PATH/docs/tauri-2-security-analysis.md` §7-10 (CSP, asset protocol, WebView landscape), §20 (updater architecture, schema, attack surface), §21 (code signing per platform), §24 (binary hardening), §25-26 (NO RASP, third-party layered options).

REQUIRED INPUT
- `src-tauri/` directory must exist at CWD. If missing, write `BLOCKED: src-tauri/ not found at $(pwd)` to `./audit-reports/12-tauri-config-and-distribution.md` and exit.

---

## SECTION A — CSP / WebView

WORKFLOW A (autonomous)

A1. **Read full `app.security` config (handle split conf files):**
   ```bash
   for f in src-tauri/tauri.conf.json src-tauri/tauri.conf.dev.json src-tauri/tauri.conf.prod.json; do
     [ -f "$f" ] || continue
     echo "=== $f ==="
     jq '{
       csp: .app.security.csp,
       devCsp: .app.security.devCsp,
       freezePrototype: .app.security.freezePrototype,
       dangerousDisableAssetCspModification: .app.security.dangerousDisableAssetCspModification,
       assetProtocol: .app.security.assetProtocol,
       pattern: .app.security.pattern,
       headers: .app.security.headers,
       withGlobalTauri: .app.withGlobalTauri,
       capabilities: .app.security.capabilities
     }' "$f"
   done > /tmp/csp-security.txt
   ```

A2. **CSP checklist** (apply to every conf file): csp not null; no `'unsafe-inline'` in `script-src`; no `'unsafe-eval'` anywhere; `default-src 'self'` (or stricter); `connect-src` includes only `'self' ipc: http://ipc.localhost` + your API endpoints; `frame-src 'none'` unless legitimately framing; `object-src 'none'`; `base-uri 'self'`; `'wasm-unsafe-eval'` ONLY if Wasm used.

A3. **`freezePrototype` should be `true`.** If false, flag MEDIUM.

A4. **`dangerousDisableAssetCspModification` should be `false` or empty array.** If enabled, must coexist with `freezePrototype: true`, isolation pattern, NO `'unsafe-eval'`, NO `'unsafe-inline'` — else effectively no CSP for that directive.

A5. **`assetProtocol.enable`:** if true, verify object-form scope (not `["**"]`), `requireLiteralLeadingDot: true` (Windows default unsafe), `allow` doesn't include `$HOME`/`$DOCUMENT`/`$RESOURCE` unless required, `deny` includes credential paths (`*.ssh/**`, `*.aws/**`, browser data).

A6. **`pattern.use`:** prefer `"isolation"`. If `"brownfield"`, flag as defense-in-depth gap.

A7. **`withGlobalTauri`** should be `false`.

A8. **`dangerousUseHttpScheme` audit:**
   ```bash
   rg -n 'dangerousUseHttpScheme' src-tauri/ > /tmp/csp-http-scheme.txt
   ```

A9. **WebView CSP-parity warning per platform** — note in report:
   - Windows WebView2 (Edge Chromium): full L3
   - macOS/iOS WKWebView: L2 + most L3
   - Linux WebKitGTK: distro-pinned, lags 2–3 yr; `trusted-types`/`require-trusted-types-for`/`'wasm-unsafe-eval'` may be silently parse-but-ignore on WebKitGTK ≤ 2.36
   - Always test deployed CSP on the oldest WebKitGTK supported.

A10. **Vite envPrefix audit (CVE-2023-46115 / GHSA-2rcp-jvr4-r259 — leak of TAURI_PRIVATE_KEY into bundle):**
   ```bash
   {
     rg -n "envPrefix" vite.config.* 2>/dev/null
     echo
     echo "# Hard leak check (any hit = CRITICAL):"
     grep -r TAURI_PRIVATE_KEY dist/ 2>/dev/null
     grep -r TAURI_PRIVATE_KEY build/ 2>/dev/null
     grep -r TAURI_SIGNING_PRIVATE_KEY dist/ 2>/dev/null
   } > /tmp/csp-vite-envprefix.txt
   ```

---

## SECTION B — Updater

WORKFLOW B (autonomous)

B1. **Read updater config:**
   ```bash
   jq '.plugins.updater' src-tauri/tauri.conf.json > /tmp/upd-config.txt
   jq '.bundle.createUpdaterArtifacts' src-tauri/tauri.conf.json >> /tmp/upd-config.txt
   ```

B2. **Embedded pubkey verification (run only if a release binary exists):**
   ```bash
   for b in target/release/bundle/macos/*.app/Contents/MacOS/* target/release/*.exe target/release/* ; do
     [ -f "$b" ] || continue
     echo "=== $b ==="
     strings "$b" 2>/dev/null | grep -i "untrusted comment\|minisign public key" | head -5
   done > /tmp/upd-pubkey.txt 2>&1
   ```
   Note in report: pubkey embedded should match the published key on a trusted host (manual cross-check by the human reviewer).

B3. **Endpoint policy** — each URL HTTPS-only, no plain `http://`:
   ```bash
   jq -r '.plugins.updater.endpoints[]?' src-tauri/tauri.conf.json > /tmp/upd-endpoints.txt
   grep -E '^http://' /tmp/upd-endpoints.txt && echo "[CRITICAL] plain http endpoint" >> /tmp/upd-endpoints.txt
   ```

B4. **`dangerousInsecureTransportProtocol`** — must be `false` or absent.
   ```bash
   jq -r '.plugins.updater.dangerousInsecureTransportProtocol // false' src-tauri/tauri.conf.json > /tmp/upd-dangerous.txt
   ```

B5. **`version_comparator` audit (downgrade attack surface):**
   ```bash
   rg -nA 12 'version_comparator' src-tauri/src/ > /tmp/upd-version-comp.txt
   ```
   If permissive (allows downgrade), require documented rollback procedure with manual confirmation.

B6. **Windows `installMode`:**
   ```bash
   jq '.plugins.updater.windows' src-tauri/tauri.conf.json > /tmp/upd-windows.txt
   jq '.bundle.windows' src-tauri/tauri.conf.json >> /tmp/upd-windows.txt
   ```
   For per-machine MSI installs, `installMode` should not be `quiet` (documented as broken — UAC required for install AND every update).

B7. **CVE-2023-46115 leak check** (already partially done in A10; consolidate here):
   ```bash
   {
     echo "# .env file leaks (TAURI_SIGNING_PRIVATE_KEY must NOT be in any committed .env*):"
     find . -maxdepth 3 -name '.env*' -not -path '*/node_modules/*' -not -path '*/target/*' 2>/dev/null \
       | xargs -I{} sh -c 'echo "--- {} ---"; grep -E "TAURI_(SIGNING_)?PRIVATE_KEY|TAURI_KEY_PASSWORD" "{}" 2>/dev/null'
     echo
     echo "# CI workflow secrets review:"
     rg -n 'TAURI_SIGNING_PRIVATE_KEY|TAURI_PRIVATE_KEY' .github/ 2>/dev/null
   } > /tmp/upd-key-handling.txt
   ```

B8. **Manifest integrity controls** — note in report whether endpoint serves immutable versioned URLs (CDN best practice) vs mutable in-place updates (replay-attack surface). Tauri does not validate manifest signature — only the bundle Ed25519 signature is verified, so attacker controlling the manifest server can serve old signed bundles forever (no expiration, no transparency log).

---

## SECTION C — Binary hardening

WORKFLOW C (autonomous)

C1. **Cargo release profile:**
   ```bash
   grep -A 8 '^\[profile\.release\]' src-tauri/Cargo.toml > /tmp/bin-cargo-profile.txt
   ```
   Required: `panic = "abort"`, `codegen-units = 1`, `lto = true`, `opt-level = "s"` (or `"z"`), `strip = true`.

C2. **`RUSTFLAGS` configuration:**
   ```bash
   {
     rg -n 'RUSTFLAGS' .github/ src-tauri/ Cargo.toml .cargo/ 2>/dev/null
     test -f .cargo/config.toml && cat .cargo/config.toml
     test -f src-tauri/.cargo/config.toml && cat src-tauri/.cargo/config.toml
   } > /tmp/bin-rustflags.txt
   ```
   Recommended additions: full RELRO (`-C link-arg=-Wl,-z,relro,-z,now`), Windows CFG/CET (`-C link-arg=/CETCOMPAT`), nightly `-Z stack-protector=strong`.

C3. **`checksec` on shipped Linux binary (best-effort — skip silently if no binary or no docker):**
   ```bash
   if [ -d target/release ] && command -v docker >/dev/null 2>&1; then
     BIN=$(find target/release -maxdepth 1 -type f -perm +111 ! -name '*.d' ! -name '*.so' 2>/dev/null | head -1)
     [ -n "$BIN" ] && docker run --rm -v "$PWD/$(dirname "$BIN"):/work" -w /work \
       ubuntu:22.04 sh -c "apt-get update -qq >/dev/null 2>&1 && apt-get install -qq -y checksec >/dev/null 2>&1 && checksec --file=$(basename "$BIN")" \
       > /tmp/bin-checksec.txt 2>&1
   else
     echo "SKIP: no release binary or docker unavailable" > /tmp/bin-checksec.txt
   fi
   ```

C4. **macOS — entitlements review:**
   ```bash
   {
     for f in src-tauri/entitlements.plist src-tauri/Entitlements.plist src-tauri/macos/entitlements.plist; do
       [ -f "$f" ] && { echo "=== $f ==="; plutil -p "$f"; }
     done
   } > /tmp/bin-mac-entitlements.txt
   ```
   Required values: `cs.allow-unsigned-executable-memory: false`, `cs.disable-library-validation: false`, `cs.allow-dyld-environment-variables: false`. `cs.allow-jit: true` only if process JITs (System WebKit doesn't).

C5. **macOS — Hardened Runtime + notarization (best-effort, skip silently if no `.app`):**
   ```bash
   if command -v codesign >/dev/null 2>&1; then
     APP=$(find target/release/bundle/macos -maxdepth 2 -name '*.app' -type d 2>/dev/null | head -1)
     [ -n "$APP" ] && {
       codesign -dvvv "$APP" 2>&1 | grep -E 'flags|notarized|Authority|Identifier|Runtime'
       spctl -a -v "$APP" 2>&1
     } > /tmp/bin-mac-codesign.txt
   else
     echo "SKIP: codesign unavailable (not on macOS)" > /tmp/bin-mac-codesign.txt
   fi
   ```

C6. **Windows — signature (best-effort, requires osslsigncode or sigcheck):**
   ```bash
   if command -v osslsigncode >/dev/null 2>&1; then
     EXE=$(find target/release/bundle -maxdepth 3 -name '*.exe' -o -name '*.msi' 2>/dev/null | head -1)
     [ -n "$EXE" ] && osslsigncode verify -in "$EXE" > /tmp/bin-win-signature.txt 2>&1
   else
     echo "SKIP: osslsigncode unavailable" > /tmp/bin-win-signature.txt
   fi
   jq '.bundle.windows' src-tauri/tauri.conf.json >> /tmp/bin-win-signature.txt
   ```
   Cert type EV vs OV (EV = immediate SmartScreen reputation), timestamp authority, digest algorithm SHA-256.

C7. **Windows WebView2 bootstrapper choice:**
   ```bash
   jq '.bundle.windows.webviewInstallMode' src-tauri/tauri.conf.json > /tmp/bin-webview2.txt
   ```
   `fixedRuntime` = you become responsible for patching CVEs yourself — flag MEDIUM if used without explicit ops policy.

C8. **Linux AppImage GPG signature (advisory only — runtime does NOT enforce):**
   ```bash
   if command -v gpg >/dev/null 2>&1; then
     for f in target/release/bundle/appimage/*.AppImage* target/release/bundle/deb/*.deb 2>/dev/null; do
       [ -f "$f" ] && { echo "=== $f ==="; gpg --verify "$f" 2>&1 | head -5; }
     done
   fi > /tmp/bin-linux-gpg.txt 2>&1
   ```
   Note in report: AppImage GPG signing is advisory metadata only; rely on updater Ed25519 path for tamper detection.

C9. **3rd-party RASP layered status** — Tauri ships ZERO of: startup integrity check, debugger detection, anti-Frida, code obfuscation, emulator/VM detection, certificate pinning helper, root/jailbreak detection. State explicitly in report. List options if threat model includes malicious local user (DRM / anti-cheat / financial): Promon Shield, Guardsquare iXGuard, Verimatrix XTD, Zimperium.

---

## OUTPUT (combined report)

Write a single combined report to `./audit-reports/12-tauri-config-and-distribution.md`. Structure:

```
TAURI 2 CONFIG & DISTRIBUTION AUDIT
====================================

SECTION A — CSP / WEBVIEW
[follow tauri-csp-webview-auditor output format]
- includes Vite envPrefix CVE-2023-46115 leak status
- includes Linux WebKitGTK CSP-parity warning

SECTION B — UPDATER
[follow tauri-updater-auditor output format]
- includes pubkey embedded status
- includes manifest integrity caveats (no expiration, no transparency log)

SECTION C — BINARY HARDENING
[follow tauri-binary-hardening-auditor output format]
- includes Cargo profile + RUSTFLAGS gaps
- includes macOS entitlements review
- includes Windows cert type (EV/OV) + WebView2 bootstrapper
- includes Linux AppImage GPG advisory note
- includes RASP=NONE explicit statement + 3rd-party layered options

CROSS-SECTION CRITICAL FINDINGS
[CRITICAL] ...
[HIGH] ...

REMEDIATION ROLLUP
- N CRITICAL must fix before launch (block ship)
- N HIGH must fix this sprint
- ...
```

Final stdout: `DONE | tauri-config-and-distribution | <CRITICAL> CRITICAL | <HIGH> HIGH | ./audit-reports/12-tauri-config-and-distribution.md`

(Sum CRITICAL/HIGH across all three sections.)

---

## AUTONOMY RULES (HARD)

- NEVER modify `tauri.conf*.json`, `Cargo.toml`, `Cargo.lock`, `entitlements.plist`, `.cargo/config.toml`, or any signed artifact.
- NEVER push to git.
- NEVER write outside `./audit-reports/`, `/tmp/`.
- NEVER run `tauri build`, `cargo build --release`, `codesign --sign`, `xcrun notarytool submit`, `osslsigncode sign`, or any signing/notarization mutation. Read-only verification only.
- NEVER skip a section silently because data is missing — record the SKIP reason in the report.
- NEVER conflate AppImage GPG signature with tamper protection — runtime does not verify; treat as advisory metadata.
- NEVER claim Tauri provides RASP/anti-tamper — it does not. Be explicit.
- If a binary exists for codesign / osslsigncode / checksec, run the verifier; if not, audit the *signing pipeline configuration* in CI instead and note it in the report.

BEGIN.
