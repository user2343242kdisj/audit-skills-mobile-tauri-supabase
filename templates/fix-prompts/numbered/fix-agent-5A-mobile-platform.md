You are operating as **fix-agent-5A-mobile-platform** for the pre-launch remediation of the Travus stack. EXECUTE END-TO-END AUTONOMOUSLY.

CONTEXT
- Working directory: `~/travus`.
- Audit-skills repo: `$AUDIT_SKILLS_PATH` (default `./audit`).
- Source audit: `./audit-reports/00-FINAL.md` (REMAINING GAPS sec).
- Output: `./fix-reports/`, `./audit-reports/15-mobile-platform.md`.

═══════════════════════════════════════════════════════════════════
SCOPE
═══════════════════════════════════════════════════════════════════
Run the **combined** mobile-platform audit (NEVER ran in original audit). Covers:
- Deeplink payload validation (`travusfinance://*` JS-router checks)
- iOS Keychain access-control flags (TOTP/MFA/refresh-token)
- Android Keystore key attestation
- SecureStore THIS_DEVICE_ONLY wrapper verification (FIX-12 staged)
- MMKV encryption posture
- RASP-gated TanStack-Query persister + MMKV expunge runtime evidence
- 4 SSL pin lifetimes (Adapty / PostHog EU / Sentry ingest / Expo OTA — one expires Q4 2026)
- Clipboard auto-clear
- Task-switcher overlay

Reuses the existing audit-skills agent prompts:
- `mobile-deeplinks-auditor.md`
- `mobile-storage-crypto-auditor.md`

═══════════════════════════════════════════════════════════════════
PRE-CONDITIONS
═══════════════════════════════════════════════════════════════════
1. `$AUDIT_SKILLS_PATH/templates/claude-agents/mobile-deeplinks-auditor.md` exists.
2. `$AUDIT_SKILLS_PATH/templates/claude-agents/mobile-storage-crypto-auditor.md` exists.
3. Mobile native projects exist: `apps/mobile/android/`, `apps/mobile/ios/`.

═══════════════════════════════════════════════════════════════════
WORKFLOW
═══════════════════════════════════════════════════════════════════

**STEP 0 — Verify auditor prompts**

```bash
test -f "$AUDIT_SKILLS_PATH/templates/claude-agents/mobile-deeplinks-auditor.md" || {
  echo "BLOCKED: mobile-deeplinks-auditor.md missing" > ./fix-reports/5A-mobile-platform-result.md; exit 1
}
test -f "$AUDIT_SKILLS_PATH/templates/claude-agents/mobile-storage-crypto-auditor.md" || {
  echo "BLOCKED: mobile-storage-crypto-auditor.md missing"; exit 1
}
```

**STEP 1 — Read both auditor prompts inline**

Use the Read tool to fully load:
- `$AUDIT_SKILLS_PATH/templates/claude-agents/mobile-deeplinks-auditor.md`
- `$AUDIT_SKILLS_PATH/templates/claude-agents/mobile-storage-crypto-auditor.md`

Adopt the persona, knowledge base, and workflow defined in each. Run them in sequence (or interleaved for parallelism), writing intermediate results to:
- `/tmp/5A-deeplinks.md`
- `/tmp/5A-storage-crypto.md`

**STEP 2 — Specific runtime checks (post-FIX-12 verification)**

Beyond the auditor prompts:

a) **Confirm FIX-12 SecureStore wrapper landed**:
```bash
git log --all --source --oneline -- 'apps/mobile/src/services/auth/secureStorage*' \
  | head -10
grep -nE "WHEN_DEVICE_UNLOCKED|THIS_DEVICE_ONLY" \
  apps/mobile/src/services/auth/secureStorage*.ts 2>/dev/null
```

b) **Inspect MMKV encryption**:
```bash
grep -nE "MMKV|encryptionKey|setEncryptionKey" apps/mobile/src/**/*.ts 2>/dev/null
```

c) **SSL pin lifetimes** — search SSL pinning config:
```bash
grep -rE "pinning|certificateHash|sha256/" \
  apps/mobile/android/app/src/main/res/xml/network_security_config.xml \
  apps/mobile/ios/ 2>/dev/null
```

For each pin, parse the cert hash and compute expiry date. Flag any pin expiring before launch + 90 days.

d) **Clipboard auto-clear** — search:
```bash
grep -rE "Clipboard\.setString|setClipboardText" apps/mobile/src/ \
  | grep -L "setTimeout|clearClipboard"
# Hits without auto-clear: regression
```

e) **Task-switcher overlay** — iOS specific. Confirm `applicationWillResignActive` blurs the screen:
```bash
grep -nE "applicationWillResignActive|UIBlurEffect" apps/mobile/ios/Travus/AppDelegate.* 2>/dev/null
```

**STEP 3 — Synthesize**

Combine `/tmp/5A-deeplinks.md` + `/tmp/5A-storage-crypto.md` + STEP 2 results into `./audit-reports/15-mobile-platform.md` with the canonical audit report shape:
```
MOBILE PLATFORM AUDIT
=====================
Date: <ISO>

DEEPLINKS
- travusfinance:// scheme: <findings>
- App Link autoVerify on https://app.travus.finance/join: <verified | not>
- JS router origin/state token validation: <present | MISSING>

STORAGE & CRYPTO
- iOS Keychain (TOTP/MFA/refresh): access control = <flags>
- Android Keystore: key attestation = <on | off>
- SecureStore THIS_DEVICE_ONLY wrapper: <FIX-12 landed | pending>
- MMKV encryption: <on | off>; key derivation: <method>

RASP RUNTIME EVIDENCE
- TanStack-Query MMKV persister: <gated | fail-open>
- MMKV expunge on RASP fail: <verified | NOT TESTED — needs runtime>

SSL PIN LIFETIMES
- Adapty: <expiry date> — <weeks remaining>
- PostHog EU: <expiry>
- Sentry ingest: <expiry>
- Expo OTA: <expiry>  ← noted in audit Q4 2026

CLIPBOARD AUTO-CLEAR
- <count> setString calls; <count> with timeout-based clear

TASK-SWITCHER OVERLAY (iOS)
- applicationWillResignActive blur: <yes | no>

CRITICAL / HIGH / MEDIUM / LOW (per finding)
- ...

VERDICT
- 0 CRITICAL | <N> HIGH | <N> MEDIUM | <N> LOW
- Launch gate: PASS | FAIL
```

**STEP 4 — Sentinel + report**

```bash
cat > ./fix-reports/5A-mobile-platform-dev-verified.sentinel <<EOF
fix-agent-5A-mobile-platform PASSED at $(date -u +%Y-%m-%dT%H:%M:%SZ)
critical: <N>
high: <N>
EOF
```

`./fix-reports/5A-mobile-platform-result.md`:
```
FIX-AGENT-5A-MOBILE-PLATFORM RESULT
====================================
Result: PASS | FAIL | BLOCKED
Critical: <N>  High: <N>  Medium: <N>  Low: <N>
Detailed report: ./audit-reports/15-mobile-platform.md
Launch gate: PASS | FAIL
```

**STEP 5 — Final stdout:**
```
DONE | fix-agent-5A-mobile-platform | <result> | C=<N> H=<N> | ./fix-reports/5A-mobile-platform-result.md
```

═══════════════════════════════════════════════════════════════════
HARD AUTONOMY RULES
═══════════════════════════════════════════════════════════════════
- NEVER modify mobile native source — this is read-only DAST/SAST.
- If RASP runtime evidence requires an instrumented device, FLAG and defer to fix-agent-5A-mobile-dynamic.
- BEGIN IMMEDIATELY.
