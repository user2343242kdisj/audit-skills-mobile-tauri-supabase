# Terminal: mobile-platform-auditor (deeplinks + storage/crypto + pinning) (Phase 2 — parallel)

## Pre-flight

```bash
cd ~/desktop/travus
source .audit-env
mkdir -p audit-reports
brew install apktool 2>/dev/null
brew install --cask android-platform-tools 2>/dev/null
brew install xmlstarlet libxml2 ripgrep jq 2>/dev/null
xcode-select --install 2>/dev/null
claude --dangerously-skip-permissions
```

## Required env

- `AUDIT_SKILLS_PATH`

## Paste this entire block into Claude Code

---

You are operating as a **merged mobile-platform auditor** covering THREE related domains:

1. `mobile-deeplinks-auditor` — Android intent filters, App Links + assetlinks.json, iOS URL Schemes, Universal Links + apple-app-site-association, deeplink hijack class
2. `mobile-storage-crypto-auditor` — iOS Keychain accessibility classes, Android Keystore + EncryptedSharedPreferences, biometric binding, StrongBox
3. `mobile-storage-crypto-auditor` (cert-pinning section) — TrustKit / NSC `<pin-set>` / OkHttp CertificatePinner, ≥2 SPKI hashes per pinned domain

Adopt the roles, knowledge bases, and output formats defined verbatim in:

  `$AUDIT_SKILLS_PATH/templates/claude-agents/mobile-deeplinks-auditor.md`
  `$AUDIT_SKILLS_PATH/templates/claude-agents/mobile-storage-crypto-auditor.md`

Cross-reference: `$AUDIT_SKILLS_PATH/docs/owasp-mas-analysis.md` §3 (MASVS-PLATFORM, MASVS-STORAGE, MASVS-CRYPTO, MASVS-NETWORK controls verbatim).

Read all three files in FULL via the Read tool now.

REQUIRED INPUT
- Mobile source under `android/` and/or `ios/`. If neither exists AND no `*.apk`/`*.ipa` found, write `BLOCKED: no mobile source (android/ and ios/ absent)` to `./audit-reports/15-mobile-platform.md` and exit.

WORKFLOW (autonomous)

### A — Deeplinks

1. **Android intent filters from manifest:**
   ```bash
   MANIFEST=""
   if [ -f android/app/src/main/AndroidManifest.xml ]; then
     MANIFEST=android/app/src/main/AndroidManifest.xml
   else
     APK=$(find . -maxdepth 4 -name '*.apk' | head -n1)
     if [ -n "$APK" ]; then
       apktool d -f -o /tmp/dl_apk "$APK" >/tmp/apktool.log 2>&1
       MANIFEST=/tmp/dl_apk/AndroidManifest.xml
     fi
   fi
   if [ -n "$MANIFEST" ]; then
     xmllint --xpath "//intent-filter" "$MANIFEST" 2>/dev/null > /tmp/dl-intents.xml || true
     xmllint --xpath "//intent-filter[@android:autoVerify='true']/data/@android:host" \
       "$MANIFEST" 2>/dev/null > /tmp/dl-applink-hosts.txt || true
     xmllint --xpath "//data[@android:scheme]/@android:scheme" \
       "$MANIFEST" 2>/dev/null > /tmp/dl-schemes.txt || true
   fi
   ```

2. **Verify assetlinks.json for each App Link host:**
   ```bash
   PKG=$(grep -hoE 'applicationId\s+"[^"]+"' android/app/build.gradle* 2>/dev/null \
     | head -n1 | sed -E 's/.*"([^"]+)".*/\1/')
   for HOST in $(cat /tmp/dl-applink-hosts.txt 2>/dev/null | tr ' ' '\n' | grep -oE '[a-z0-9.-]+\.[a-z]+'); do
     URL="https://${HOST}/.well-known/assetlinks.json"
     curl -fsSL "$URL" -o "/tmp/assetlinks-${HOST}.json" 2>/dev/null || \
       echo "MISSING ${URL}" >> /tmp/dl-assetlinks-missing.txt
   done
   # Verify package_name + sha256 in each
   for F in /tmp/assetlinks-*.json; do
     [ -f "$F" ] || continue
     jq -r --arg pkg "$PKG" '
       .[] | select(.target.namespace=="android_app") |
       "host=\(input_filename) pkg_match=\(.target.package_name == $pkg) sha256_count=\(.target.sha256_cert_fingerprints | length)"
     ' "$F" >> /tmp/dl-assetlinks-verify.txt 2>/dev/null || true
   done
   ```

3. **iOS URL Schemes + Universal Link domains:**
   ```bash
   IOS_PLIST=$(find ios/ -maxdepth 5 -name 'Info.plist' 2>/dev/null \
     | grep -v 'Pods\|Tests' | head -n1)
   IOS_APP=$(find . -maxdepth 6 -name '*.app' -type d 2>/dev/null | head -n1)
   [ -n "$IOS_APP" ] && IOS_PLIST="$IOS_APP/Info.plist"
   if [ -n "$IOS_PLIST" ]; then
     plutil -extract CFBundleURLTypes xml1 -o - "$IOS_PLIST" 2>/dev/null > /tmp/dl-ios-urltypes.xml || true
   fi
   # Associated domains entitlement
   if [ -n "$IOS_APP" ]; then
     codesign -d --entitlements - "$IOS_APP" 2>/dev/null \
       | plutil -p - 2>/dev/null > /tmp/dl-ios-entitlements.txt || true
     grep -A 20 'associated-domains' /tmp/dl-ios-entitlements.txt > /tmp/dl-ios-applinks.txt || true
   else
     rg -n 'applinks:' ios/ 2>/dev/null > /tmp/dl-ios-applinks.txt || true
   fi
   ```

4. **Verify apple-app-site-association for each iOS Universal Link host:**
   ```bash
   for HOST in $(grep -oE 'applinks:[a-z0-9.-]+' /tmp/dl-ios-applinks.txt 2>/dev/null | sed 's/applinks://' | sort -u); do
     URL="https://${HOST}/.well-known/apple-app-site-association"
     # Must NOT redirect, must be application/json
     CT=$(curl -sI "$URL" | grep -i '^content-type:' | tr -d '\r')
     RC=$(curl -s -o /dev/null -w "%{http_code}" "$URL")
     RDR=$(curl -s -o /dev/null -w "%{redirect_url}" "$URL")
     echo "host=$HOST rc=$RC redirect=$RDR ct=$CT" >> /tmp/dl-ios-aasa.txt
     curl -fsSL "$URL" -o "/tmp/aasa-${HOST}.json" 2>/dev/null || \
       echo "MISSING $URL" >> /tmp/dl-ios-aasa-missing.txt
   done
   ```

5. **Deeplink hijack class — flag custom schemes triggering sensitive ops:**
   ```bash
   rg -nA 10 -i 'intent\.getData\(\)|onNewIntent|UIApplicationDelegate.*openURL|application:openURL:options:|onOpenURL\(' \
     android/ ios/ src-tauri/ 2>/dev/null > /tmp/dl-handlers.txt || true
   ```

### B — Keychain / Keystore / Storage

6. **iOS Keychain accessibility class scan:**
   ```bash
   rg -nA 3 'kSecAttrAccessible|SecItemAdd|SecItemCopyMatching|SecAccessControlCreateWithFlags' \
     ios/ src-tauri/ 2>/dev/null > /tmp/sc-ios-keychain.txt || true
   # Flag deprecated / weak classes
   rg -n 'kSecAttrAccessibleAlways[^T]|kSecAttrAccessibleWhenUnlocked[^T]' \
     ios/ src-tauri/ 2>/dev/null > /tmp/sc-ios-keychain-weak.txt || true
   ```

7. **Android Keystore + EncryptedSharedPreferences scan:**
   ```bash
   rg -nA 3 'KeyStore\.getInstance|EncryptedSharedPreferences|EncryptedFile|MasterKey|setIsStrongBoxBacked|setUserAuthenticationRequired' \
     android/ src-tauri/ 2>/dev/null > /tmp/sc-android-keystore.txt || true
   # Flag plain SharedPreferences storing sensitive material
   rg -nA 3 'getSharedPreferences|getDefaultSharedPreferences' android/ 2>/dev/null \
     | rg -B 3 'putString.*(token|password|secret|api[_-]?key|jwt|bearer|access|refresh)' \
     > /tmp/sc-android-plainprefs.txt 2>/dev/null || true
   ```

8. **Biometric binding check (both platforms):**
   ```bash
   rg -n 'biometryCurrentSet|setInvalidatedByBiometricEnrollment|AUTH_BIOMETRIC_STRONG|LAContext|BiometricPrompt' \
     ios/ android/ 2>/dev/null > /tmp/sc-biometric.txt || true
   ```

### C — Cert pinning

9. **iOS pinning — TrustKit / URLSessionDelegate:**
   ```bash
   rg -nA 8 'TrustKit|kTSKPinnedDomains|kTSKPublicKeyHashes|URLSessionDelegate.*didReceiveChallenge|SecTrustEvaluate' \
     ios/ src-tauri/ 2>/dev/null > /tmp/cp-ios.txt || true
   ```

10. **Android pinning — Network Security Config + OkHttp:**
    ```bash
    NSC=$(find android/ -name 'network_security_config.xml' 2>/dev/null | head -n1)
    if [ -n "$NSC" ]; then
      cat "$NSC" > /tmp/cp-android-nsc.xml
      xmllint --xpath "//pin-set/pin" "$NSC" 2>/dev/null > /tmp/cp-android-pins.txt || true
      xmllint --xpath "//trust-anchors/certificates[@src='user']" "$NSC" 2>/dev/null \
        > /tmp/cp-android-userca.txt || true
    fi
    rg -nA 5 'CertificatePinner|certificatePinner' android/ src-tauri/ 2>/dev/null > /tmp/cp-android-okhttp.txt || true
    ```

11. **Backup-pin enforcement — verify ≥2 SPKI hashes per pinned domain:**
    ```bash
    # iOS — count hashes per kTSKPinnedDomains entry
    rg -nB 2 -A 20 'kTSKPinnedDomains' ios/ 2>/dev/null \
      | rg -c 'kTSKPublicKeyHashes' > /tmp/cp-ios-hashcount.txt 2>/dev/null || true
    # Android — count <pin> per <domain-config>
    if [ -n "$NSC" ]; then
      python3 - <<'PY' >> /tmp/cp-android-pincount.txt 2>/dev/null
   import xml.etree.ElementTree as ET, glob
   for f in glob.glob('android/**/network_security_config.xml', recursive=True):
     try:
       root = ET.parse(f).getroot()
       for dc in root.iter('domain-config'):
         dom = ','.join(d.text for d in dc.iter('domain') if d.text)
         pins = list(dc.iter('pin'))
         print(f"{f}: {dom} -> {len(pins)} pin(s)")
     except Exception as e:
       print(f"{f}: parse error {e}")
   PY
    fi
    ```

12. **Aggregate** all of the above into a single report at `./audit-reports/15-mobile-platform.md` with three clearly delimited sections, each following its respective agent file's output format:

    ```
    MOBILE PLATFORM AUDIT (deeplinks + storage/crypto + pinning)
    ============================================================

    ## Section 1 — Deeplinks
    ANDROID — <package>
    - Custom URL schemes:        [list]   [hijackable]
    - App Link hosts:            [list]
    - App Links autoVerify=true: <count>/<total>
    - assetlinks.json correct:   <host>: yes/no/missing
      - package_name match:      yes/no
      - sha256 cert match:       yes/no
    - Deeplinks triggering sensitive ops without re-auth: [list]

    IOS — <bundle>
    - Custom URL schemes:        [list]
    - Universal Link domains:    [list]
    - apple-app-site-association
      reachable / content-type / redirect-free
    - associated-domains entitlement: [list, must match AASA]

    ## Section 2 — Storage / Crypto
    KEYCHAIN (iOS)
    - Items with ThisDeviceOnly: <n>/<n>
    - Items with biometric bind: <n>/<n>
    - Items with Always class:   <n>  [CRITICAL — deprecated]

    KEYSTORE (Android)
    - Aliases / StrongBox / setUserAuthenticationRequired
    - Plain SharedPreferences storing tokens: <list>  [CRITICAL]

    ## Section 3 — Cert Pinning
    iOS:    library / pinned domains / SPKI hash count per domain (≥ 2 required)
    Android: NSC pin-set expiration / domain coverage / OkHttp CertificatePinner / user CA trust-anchor

    CRITICAL FINDINGS
    [CRITICAL] ...
    [HIGH]     ...

    REMEDIATION
    - ...
    ```

OUTPUT
- File: `./audit-reports/15-mobile-platform.md`
- Final stdout: `DONE | mobile-platform | <CRITICAL> CRITICAL | <HIGH> HIGH | ./audit-reports/15-mobile-platform.md`

AUTONOMY RULES (HARD)
- NEVER modify `android/`, `ios/`, or `src-tauri/` source.
- NEVER push to git.
- NEVER write outside `./audit-reports/`, `/tmp/`.
- NEVER fetch assetlinks.json / AASA from internal hosts behind VPN unless `$AUDIT_ALLOW_INTERNAL=1`.
- If both `android/` AND `ios/` are absent AND no APK/IPA exists → BLOCKED message + exit (per REQUIRED INPUT).
- If a host is unreachable for AASA / assetlinks fetch, record `UNREACHABLE` for that host and continue.

BEGIN.
