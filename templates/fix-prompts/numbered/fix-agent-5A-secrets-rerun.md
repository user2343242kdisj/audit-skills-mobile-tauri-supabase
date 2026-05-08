You are operating as **fix-agent-5A-secrets-rerun** for the pre-launch remediation of the Travus stack. EXECUTE END-TO-END AUTONOMOUSLY.

CONTEXT
- Working directory: `~/travus`.
- Source audit: `./audit-reports/02-secrets-scan.md` (REDUCED detector coverage — ggshield/trufflehog skipped).
- Output: `./fix-reports/`, `./audit-reports/02-secrets-scan-rerun.md`.

═══════════════════════════════════════════════════════════════════
SCOPE
═══════════════════════════════════════════════════════════════════
Re-run secret scanning with the verified-only detectors that were SKIPPED in the original audit:

- ggshield (GitGuardian) — was skipped: not installed
- trufflehog `--only-verified` — was skipped: broken brew keg
- New-format Supabase keys (`sb_secret_*`, `sb_publishable_*`) — needed live verification

This agent reinstalls the tools cleanly and re-runs against the working tree + git history. **Run AFTER fix-agent-2G** (secret rotation marathon) to confirm rotated secrets aren't still active in history.

═══════════════════════════════════════════════════════════════════
PRE-CONDITIONS
═══════════════════════════════════════════════════════════════════
1. `op://Travus/GitGuardian/api_key` available.
2. `brew` (macOS) or `apt`/`go install` for trufflehog on Linux.
3. fix-agent-2G has run (recommended; not strictly required).

═══════════════════════════════════════════════════════════════════
WORKFLOW
═══════════════════════════════════════════════════════════════════

**STEP 0 — Resolve secrets**
```bash
GITGUARDIAN_API_KEY=$(op read "op://Travus/GitGuardian/api_key")
export GITGUARDIAN_API_KEY
```
If missing, write `BLOCKED: GitGuardian API key not in 1Password (set up at https://dashboard.gitguardian.com/api/personal-access-tokens)` and exit.

**STEP 1 — Install tools cleanly**
```bash
# trufflehog — fix the broken brew keg per audit
if command -v brew >/dev/null; then
  brew uninstall trufflehog 2>/dev/null || true
  brew install trufflehog
else
  go install github.com/trufflesecurity/trufflehog/v3@latest
fi

# ggshield
pip install --quiet --upgrade ggshield
ggshield --version
```

**STEP 2 — ggshield: working tree + history**
```bash
ggshield secret scan repo . > /tmp/5A-ggshield-tree.log 2>&1 || true
ggshield secret scan path --recursive . --json > /tmp/5A-ggshield-tree.json 2>&1 || true
```

ggshield scans both staged and committed; the `repo` subcommand also walks history.

**STEP 3 — trufflehog: history + working tree, --only-verified**
```bash
trufflehog git file://. --only-verified --json > /tmp/5A-trufflehog-history.json 2>&1 || true
trufflehog filesystem . --only-verified --json > /tmp/5A-trufflehog-tree.json 2>&1 || true
```

`--only-verified` triggers an HTTP probe to the provider for each detected token to confirm it still works. This is the gold standard for "real exposed secret" vs "test/dummy".

**STEP 4 — Cross-check rotation status**

For each verified secret found, cross-reference against `./fix-reports/2G-rotation-log.md` (if present):
- If the secret is in the rotation log AND marked DONE → confirmed-and-rotated (still appears in git history but is no longer active at provider).
- If the secret is verified AND not in the rotation log → ESCALATE — emergency rotation needed.

**STEP 5 — New-format key check**

Search working tree + last 100 commits for `sb_secret_*` and `sb_publishable_*`:
```bash
git log -p --all -S 'sb_secret_' --since='3 months ago' \
  | grep -E 'sb_secret_[a-zA-Z0-9_]+' | head -20

grep -rn 'sb_secret_' . --exclude-dir={node_modules,.git,audit,audit-reports,fix-reports} | head
grep -rn 'sb_publishable_' . --exclude-dir={node_modules,.git,audit,audit-reports,fix-reports} | head
```

`sb_publishable_*` in client-distributed code is **expected** (it replaces the legacy public anon JWT). `sb_secret_*` in any client code or git history is a **leak**.

**STEP 6 — Synthesize**

`./audit-reports/02-secrets-scan-rerun.md`:
```
SECRETS SCAN RE-RUN (post-rotation)
===================================
Date: <ISO>
Tools: ggshield <version>, trufflehog <version>

GGSHIELD
- Working tree hits: <count>; HIGH severity: <count>
- History hits: <count>; HIGH severity: <count>
- Top hits: <list>

TRUFFLEHOG --only-verified
- Working tree verified hits: <count>
- Git history verified hits: <count>
- Detail per hit:
  | Detector | File / Commit | Verified | In rotation log | Status |
  |---|---|---|---|---|
  | <Detector> | <path:line> | yes | yes | rotated — old key dead |
  | <Detector> | <commit> | yes | NO | ESCALATE — emergency rotation |

NEW-FORMAT KEY CHECK
- sb_secret_* in working tree: <count>          (expected: 0)
- sb_secret_* in last 100 commits: <count>      (expected: 0)
- sb_publishable_* in client code: <count>      (expected: present, post-2D)

ESCALATIONS
- <list of unrotated active secrets — needs immediate fix-agent-2G run>

LAUNCH GATE
- PASS (verified active hits = 0) | FAIL (escalations present)
```

**STEP 7 — Sentinel + report**

```bash
cat > ./fix-reports/5A-secrets-rerun-dev-verified.sentinel <<EOF
fix-agent-5A-secrets-rerun PASSED at $(date -u +%Y-%m-%dT%H:%M:%SZ)
trufflehog_verified_hits: <N>
unrotated_active: <N>
EOF
```

`./fix-reports/5A-secrets-rerun-result.md`:
```
FIX-AGENT-5A-SECRETS-RERUN RESULT
=================================
Result: PASS | ESCALATE | BLOCKED
trufflehog --only-verified hits: <N>
unrotated active secrets: <N>     (target: 0)
sb_secret_* in working tree/history: <N>  (target: 0)
Detailed report: ./audit-reports/02-secrets-scan-rerun.md
```

**STEP 8 — Final stdout:**
```
DONE | fix-agent-5A-secrets-rerun | <result> | verified=<N> escalate=<N> | ./fix-reports/5A-secrets-rerun-result.md
```

═══════════════════════════════════════════════════════════════════
HARD AUTONOMY RULES
═══════════════════════════════════════════════════════════════════
- NEVER print full secret values; truncate to first 10 chars + "...REDACTED".
- NEVER auto-rotate found secrets — escalate to fix-agent-2G with explicit rotation list.
- If trufflehog --only-verified finds a hit NOT in the 2G rotation log, this is an emergency — write ESCALATE prominently.
- BEGIN IMMEDIATELY.
