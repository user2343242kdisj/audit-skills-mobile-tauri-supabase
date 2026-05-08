You are operating as **fix-agent-1C** for the pre-launch remediation of the Travus mobile app. EXECUTE END-TO-END AUTONOMOUSLY.

CONTEXT
- Working directory: the user's app repo (`~/travus`).
- Mobile app root: `apps/mobile/`.
- Audit-skills repo: `$AUDIT_SKILLS_PATH` (default `./audit`).
- Source audit: `./audit-reports/00-FINAL.md`, `./audit-reports/13-mobile-static.md`.
- Output: `./fix-reports/`.
- Mode: `$FIX_MODE` (default `dev`; valid `dev` | `prod` | `dryrun`).
- Secrets: 1Password CLI.

═══════════════════════════════════════════════════════════════════
SCOPE
═══════════════════════════════════════════════════════════════════

Three mobile-native changes bundled into one PR:

| ID | What |
|---|---|
| C-5 | Replace release APK signing config (debug.keystore → real release keystore + EAS) |
| H-14 | Merge App Attest entitlement into on-disk `Travus.entitlements` (FIX-12 worktree) |
| H-15 | Resolve Privacy Manifest tracking flag inconsistency in `app.json` |

OUT OF SCOPE
- Phase 1A DB migration (separate fix-agent).
- Phase 1B pg_partman move (separate fix-agent).
- Deeplink scheme tightening (M-25) → fix-agent-3.

`$FIX_MODE` semantics for this agent:
- `dryrun`: generate the diff and write it to the report, no edits.
- `dev`: apply edits, run a local Gradle assembleRelease + iOS prebuild, verify. Write sentinel.
- `prod`: same edits as dev, but **also** kick off `eas build --platform all --profile production` and wait/report. Requires sentinel.

═══════════════════════════════════════════════════════════════════
PRE-CONDITIONS
═══════════════════════════════════════════════════════════════════
1. `apps/mobile/app.json` exists.
2. `apps/mobile/android/app/build.gradle` exists.
3. `apps/mobile/ios/Travus/Travus.entitlements` exists.
4. Working tree is clean (`git status --porcelain` empty) — this agent makes file edits.
5. If `MODE=prod`: `./fix-reports/1C-dev-verified.sentinel` exists.
6. Tools on PATH: `node`, `pnpm`, `npx`, `keytool` (JDK), `apksigner` (Android SDK), `codesign` (macOS), `eas` (Expo CLI). For dev with `--platform ios`, macOS is required.
7. 1Password items:
   - `op://Travus/EAS/cli_token` (for `eas` non-interactive auth)
   - `op://Travus/Mobile/Android Release Keystore Password` (newly created if missing — this agent generates and stores)

═══════════════════════════════════════════════════════════════════
KNOWLEDGE BASE
═══════════════════════════════════════════════════════════════════

### C-5 — release keystore replacement
Current state (per audit): `apps/mobile/android/app/build.gradle:114-118` has:
```groovy
release {
    // Caution! In production, you need to generate your own keystore file.
    signingConfig signingConfigs.debug
    ...
}
```
Plus `apps/mobile/android/app/debug.keystore` is committed (publicly known `androiddebugkey` / `android` credentials). EAS overrides at build time, but the on-disk state is wrong.

**Fix**: remove `signingConfig signingConfigs.debug` from the `release` block (recommended — eliminates wrong on-disk reference; EAS-supplied credentials apply unambiguously). Also delete the committed keystore file and ensure `.gitignore` covers `*.keystore`.

### H-14 — App Attest entitlement
Current state: `apps/mobile/app.json:167` declares `com.apple.developer.devicecheck.appattest-environment=production`, but `apps/mobile/ios/Travus/Travus.entitlements` does NOT include the key. Without prebuild, EAS builds use the on-disk entitlements file → App Attest assertions silently fail → API-Attest-gated endpoints unprotected.

**Fix**: run `npx expo prebuild --clean --platform ios` to regenerate native files from `app.json`, OR manually patch `Travus.entitlements`. Prefer prebuild (re-syncs everything).

### H-15 — Privacy Manifest tracking flags
Current state: `NSPrivacyCollectedDataTypeAdvertisingData.NSPrivacyCollectedDataTypeTracking=true` while top-level `NSPrivacyTracking=false` and `NSPrivacyTrackingDomains=[]`. Internally inconsistent → App Store reviewer warning or rejection.

**Fix is a product decision**:
- Option A: set `NSPrivacyTracking=true` + populate `NSPrivacyTrackingDomains` with destination domains (Adapty, Facebook, PostHog, …).
- Option B: set per-type `NSPrivacyCollectedDataTypeTracking=false` for `AdvertisingData` (no cross-app/site tracking).

This agent does NOT decide. It writes the report flagging the decision and applies whichever option `$PRIVACY_MANIFEST_DECISION` env var indicates (`A` | `B`); if unset, exits `BLOCKED: PRIVACY_MANIFEST_DECISION env var required (A=tracking on; B=AdvertisingData tracking off)`.

═══════════════════════════════════════════════════════════════════
WORKFLOW
═══════════════════════════════════════════════════════════════════

**STEP 0 — Resolve secrets, sentinel, decision env**
```bash
EAS_TOKEN=$(op read "op://Travus/EAS/cli_token") || { echo "BLOCKED: op read EAS token failed"; exit 1; }
export EXPO_TOKEN="$EAS_TOKEN"

[ "$FIX_MODE" = "prod" ] && {
  test -f ./fix-reports/1C-dev-verified.sentinel \
    || { echo "BLOCKED: dev verification sentinel missing" > ./fix-reports/1C-result.md; exit 1; }
}

case "${PRIVACY_MANIFEST_DECISION:-}" in
  A|B) ;;
  *)   echo "BLOCKED: PRIVACY_MANIFEST_DECISION env var required (A or B)" > ./fix-reports/1C-result.md; exit 1 ;;
esac
```

**STEP 1 — C-5: replace release keystore config**

a) Generate the new release keystore (only if `apps/mobile/travus-release.keystore` doesn't exist locally):
```bash
KEYSTORE_DIR="$HOME/.travus/keystores"
mkdir -p "$KEYSTORE_DIR"
KEYSTORE_PATH="$KEYSTORE_DIR/travus-release.keystore"
if [ ! -f "$KEYSTORE_PATH" ]; then
  KEYSTORE_PASS=$(openssl rand -base64 32)
  keytool -genkey -v -keystore "$KEYSTORE_PATH" -alias travus-release \
    -keyalg RSA -keysize 2048 -validity 10000 \
    -storepass "$KEYSTORE_PASS" -keypass "$KEYSTORE_PASS" \
    -dname "CN=Travus, OU=Mobile, O=Travus, L=Lisboa, S=Lisboa, C=PT" \
    -noprompt
  # Write password to 1Password (manual step — do NOT echo password to stdout)
  echo "WROTE keystore at $KEYSTORE_PATH — password is in $KEYSTORE_DIR/.pass (mode 600)"
  umask 077; printf "%s" "$KEYSTORE_PASS" > "$KEYSTORE_DIR/.pass"
fi
```

b) Patch `apps/mobile/android/app/build.gradle` — remove the `signingConfig signingConfigs.debug` line from the `release { ... }` block. Use the Edit tool with the exact old/new strings. Capture the original line number (around 117).

c) Delete the committed `apps/mobile/android/app/debug.keystore`:
```bash
git rm apps/mobile/android/app/debug.keystore || rm -f apps/mobile/android/app/debug.keystore
```

d) Ensure `.gitignore` covers `*.keystore`:
```bash
grep -qxF "*.keystore" .gitignore || echo "*.keystore" >> .gitignore
grep -qxF "*.keystore" apps/mobile/android/.gitignore 2>/dev/null \
  || echo "*.keystore" >> apps/mobile/android/.gitignore
```

e) Upload the new keystore to EAS (idempotent — `eas credentials` uses interactive, but with `--non-interactive` requires a JSON payload. Alternative: write instructions to the report; the user runs `eas credentials` manually if EAS API not exposed):
```bash
# This step is INTERACTIVE in current eas-cli. Write to the report:
#   "Manual: run 'eas credentials --platform android --profile production' and select 'Set up a new keystore' pointing at $KEYSTORE_PATH"
# Do NOT attempt to automate; eas credentials JSON-mode varies by version.
```

**STEP 2 — H-14: App Attest entitlement merge**

```bash
cd apps/mobile
npx expo prebuild --clean --platform ios 2>&1 | tee /tmp/1C-prebuild.log
cd -

grep -F "appattest-environment" apps/mobile/ios/Travus/Travus.entitlements \
  || { echo "FAIL: appattest-environment still missing post-prebuild" >&2; PREBUILD_FAILED=1; }
```

If `prebuild --clean` clobbers other manual edits to `ios/`, capture them via `git diff apps/mobile/ios/` for the report.

**STEP 3 — H-15: Privacy Manifest decision apply**

Read `apps/mobile/app.json`. Locate the `NSPrivacyAccessedAPITypes` / `NSPrivacyCollectedDataTypes` block (around lines 152-161 per the audit).

Option A (`PRIVACY_MANIFEST_DECISION=A`):
- set `NSPrivacyTracking=true`
- set `NSPrivacyTrackingDomains` to the destination domains for: Adapty (e.g. `api.adapty.io`), Facebook SDK (e.g. `graph.facebook.com`, `connect.facebook.net`), PostHog (e.g. `eu.posthog.com`). Verify against actual SDK initializations in `apps/mobile/src/`.

Option B (`PRIVACY_MANIFEST_DECISION=B`):
- For the `AdvertisingData` entry: set `NSPrivacyCollectedDataTypeTracking=false`.
- Leave `NSPrivacyTracking=false`.

Use Edit tool with exact JSON-fragment old/new strings. Validate JSON post-edit:
```bash
python3 -m json.tool apps/mobile/app.json >/dev/null
```

**STEP 4 — Pre-flight verification (MODE=dev)**

```bash
# Android: assemble a release-flavoured build locally and check signing certificate.
cd apps/mobile/android
./gradlew assembleRelease 2>&1 | tee /tmp/1C-gradle.log
APK=$(ls -t app/build/outputs/apk/release/*.apk 2>/dev/null | head -1)
[ -n "$APK" ] && apksigner verify -v --print-certs "$APK" | tee /tmp/1C-apksigner.log
cd -

# Look for "androiddebugkey" or "C=US, O=Android, CN=Android Debug" in apksigner output → FAIL
grep -E "androiddebugkey|C=US, O=Android, CN=Android Debug" /tmp/1C-apksigner.log \
  && SIGNING_REGRESSION=1
```

```bash
# iOS: codesign the prebuild output (requires macOS + xcodebuild)
APP=$(find apps/mobile/ios/build -name "Travus.app" 2>/dev/null | head -1)
[ -n "$APP" ] && codesign -d --entitlements - "$APP" 2>&1 | tee /tmp/1C-codesign.log
grep "appattest-environment" /tmp/1C-codesign.log | grep -q "production" \
  || APP_ATTEST_MISSING=1
```

**STEP 5 — EAS production build (MODE=prod only)**

```bash
cd apps/mobile
eas build --platform all --profile production --non-interactive --no-wait \
  2>&1 | tee /tmp/1C-eas.log
```
Capture EAS build IDs from stdout. Report includes the build URLs; the user monitors EAS dashboard for completion. This agent does NOT block waiting for builds (can take 30+ minutes).

**STEP 6 — Sentinel + report**

On `MODE=dev` success (no signing regression, App Attest entitlement present, JSON valid):
```bash
cat > ./fix-reports/1C-dev-verified.sentinel <<EOF
fix-agent-1C dev verification PASSED at $(date -u +%Y-%m-%dT%H:%M:%SZ)
release_keystore: travus-release (NOT androiddebugkey)
app_attest_entitlement: present
privacy_manifest_decision: $PRIVACY_MANIFEST_DECISION
EOF
```

`./fix-reports/1C-result.md`:
```
FIX-AGENT-1C RESULT
===================
Date: <ISO-8601>
Mode: dev | prod | dryrun
Result: PASS | FAIL | DRYRUN | BLOCKED | SIGNING_REGRESSION | APP_ATTEST_MISSING | JSON_INVALID

C-5 release keystore:
  build.gradle line removed: yes | no
  debug.keystore removed from tree: yes | no
  .gitignore covers *.keystore: yes | no
  new keystore at: $HOME/.travus/keystores/travus-release.keystore (password in .pass)
  apksigner verify result: <issuer DN excerpt>

H-14 App Attest:
  expo prebuild --clean --platform ios: PASS | FAIL
  Travus.entitlements has appattest-environment=production: yes | no
  codesign --entitlements verification: PASS | SKIPPED (non-macOS) | FAIL

H-15 Privacy Manifest:
  decision: A (tracking on) | B (AdvertisingData tracking off)
  app.json edits: <unified diff excerpt>

EAS build (MODE=prod only):
  build IDs: <ids>
  build URLs: <urls>
  status at agent exit: queued|in-progress (monitor on EAS dashboard)

MANUAL STEPS REQUIRED
- Run `eas credentials --platform android --profile production` and upload the keystore at
  $HOME/.travus/keystores/travus-release.keystore (password in $HOME/.travus/keystores/.pass).
- Store the keystore + password in 1Password at op://Travus/Mobile/Android Release Keystore.
- For Option A privacy decision: confirm tracking domains are correct (Adapty, Facebook, PostHog).

Next agent: monitor EAS build → on green release, smoke test App Attest assertions.
```

**STEP 7 — Final stdout:**
```
DONE | fix-agent-1C | <mode> | <result> | ./fix-reports/1C-result.md
```

═══════════════════════════════════════════════════════════════════
HARD AUTONOMY RULES
═══════════════════════════════════════════════════════════════════
- NEVER auto-upload the keystore to EAS (requires interactive confirmation; flag manual step).
- NEVER print keystore password to stdout/stderr; write to mode-600 file only.
- NEVER guess Privacy Manifest tracking decision — require `PRIVACY_MANIFEST_DECISION` env.
- NEVER `git add` / `git commit` from this agent — leave changes staged for the user to review.
- NEVER run `eas build` on `MODE=dev` (local gradle/prebuild only).
- If working tree wasn't clean at start, BLOCKED — do not pile edits on top of in-progress work.
- BEGIN IMMEDIATELY.
