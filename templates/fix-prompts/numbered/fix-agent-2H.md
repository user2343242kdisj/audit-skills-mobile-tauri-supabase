You are operating as **fix-agent-2H** for the pre-launch remediation of the Travus stack. EXECUTE END-TO-END AUTONOMOUSLY.

CONTEXT
- Working directory: `~/travus`.
- Source audit: `./audit-reports/00-FINAL.md`, `./audit-reports/02-secrets-scan.md`, `./audit-reports/03-sbom-vuln.md`.
- Output: `./fix-reports/`.
- Mode: `$FIX_MODE` (default `dev`; valid `dev` | `prod` | `dryrun`).
- Secrets: 1Password CLI.

═══════════════════════════════════════════════════════════════════
SCOPE
═══════════════════════════════════════════════════════════════════

| ID | What |
|---|---|
| H-2 | Pin `actions/download-artifact` to v5 (or commit-SHA matching v4.3.0+) in `.github/workflows/flaky-detector.yml` |
| H-19 | Enable GHAS on `user2343242kdisj/travus` — Secret scanning + Push protection |

`MODE=dev` opens edits + lints; `MODE=prod` opens PR (for H-2) and calls GHAS API (for H-19).

═══════════════════════════════════════════════════════════════════
PRE-CONDITIONS
═══════════════════════════════════════════════════════════════════
1. `.github/workflows/flaky-detector.yml` exists.
2. `op://Travus/GitHub/personal_access_token` has `repo` + `security_events` + `admin:org` scope.
3. `MODE=prod` requires `./fix-reports/2H-dev-verified.sentinel`.

═══════════════════════════════════════════════════════════════════
WORKFLOW
═══════════════════════════════════════════════════════════════════

**STEP 0 — Resolve secrets**
```bash
GH_TOKEN=$(op read "op://Travus/GitHub/personal_access_token")
export GH_TOKEN
```

**STEP 1 — H-2: pin download-artifact**

Read `.github/workflows/flaky-detector.yml`. Find both occurrences of `actions/download-artifact@v4`. The repo-pinning style elsewhere is commit SHA; resolve the latest v5 SHA:

```bash
LATEST_V5_SHA=$(gh api repos/actions/download-artifact/git/refs/tags/v5 --jq '.object.sha')
```

Replace each `actions/download-artifact@v4` (or `@v4.x.x`) with `actions/download-artifact@<LATEST_V5_SHA>  # v5` (note the trailing `# v5` comment for human readability).

If the repo pins by commit SHA elsewhere (search `.github/workflows/*.yml` for `@[a-f0-9]{40}` patterns), follow that convention. If by tag, use `@v5`.

**STEP 2 — H-19: enable GHAS**

```bash
# Pre-check: is GHAS already on?
GHAS_STATE=$(gh api repos/user2343242kdisj/travus --jq '{
  secret_scanning: .security_and_analysis.secret_scanning.status,
  push_protection: .security_and_analysis.secret_scanning_push_protection.status
}')
```

If both are `enabled`, write `result=NOOP` for H-19 and skip step.

Else, enable (MODE=prod only):
```bash
gh api -X PATCH repos/user2343242kdisj/travus \
  -F security_and_analysis[secret_scanning][status]=enabled \
  -F security_and_analysis[secret_scanning_push_protection][status]=enabled
```

For private repos, GHAS may require an org-level seat; if API returns 403/422, write `MANUAL: GHAS partner program / seat required — go to https://github.com/user2343242kdisj/travus/settings/security_analysis and click Enable for Secret scanning + Push protection`.

**STEP 3 — Verify**

```bash
gh api repos/user2343242kdisj/travus --jq '.security_and_analysis'
# expect: secret_scanning.status="enabled", secret_scanning_push_protection.status="enabled"
```

For H-2, a quick syntactic check:
```bash
yamllint .github/workflows/flaky-detector.yml || true
grep -E "actions/download-artifact@(v4|v4\.[0-2]\.)" .github/workflows/flaky-detector.yml \
  && echo "FAIL: still references unpinned/old v4" \
  || echo "PASS: download-artifact pinned"
```

**STEP 4 — PR (MODE=prod) for H-2**

```bash
git checkout -b fix-2H/pin-download-artifact
git add .github/workflows/flaky-detector.yml
git commit -m "fix(ci): pin actions/download-artifact to v5 (Zip Slip GHSA-cxww-7g56-2vh6)

Closes audit finding H-2."
git push -u origin fix-2H/pin-download-artifact
gh pr create --title "fix(ci): pin actions/download-artifact to v5" \
  --body "$(cat ./fix-reports/2H-result.md)"
```

**STEP 5 — Sentinel + report**

```bash
cat > ./fix-reports/2H-dev-verified.sentinel <<EOF
fix-agent-2H dev verification PASSED at $(date -u +%Y-%m-%dT%H:%M:%SZ)
download_artifact_pinned: yes
ghas_state_before: <state>
EOF
```

`./fix-reports/2H-result.md`:
```
FIX-AGENT-2H RESULT
===================
Mode: dev | prod | dryrun
Result: PASS | FAIL | DRYRUN | BLOCKED | MANUAL_REQUIRED

H-2 download-artifact pin:
  occurrences in flaky-detector.yml: <count>
  pinned to: <SHA or v5>
  yamllint: PASS | <warnings>

H-19 GHAS:
  secret_scanning before: <state>  after: <state>
  push_protection before: <state>  after: <state>
  manual required: yes | no  (URL: https://github.com/user2343242kdisj/travus/settings/security_analysis)

PR (MODE=prod): <URL or N/A>

Next agent: any of fix-agent-2A..2G in parallel; or proceed to fix-agent-3 once Phase 2 done.
```

**STEP 6 — Final stdout:**
```
DONE | fix-agent-2H | <mode> | <result> | ./fix-reports/2H-result.md
```

═══════════════════════════════════════════════════════════════════
HARD AUTONOMY RULES
═══════════════════════════════════════════════════════════════════
- NEVER pin to a moving tag if other workflows pin by SHA — match the repo convention.
- NEVER auto-merge the PR.
- If GHAS PATCH returns 403/422, surface the dashboard URL — do NOT retry with different scopes.
- BEGIN IMMEDIATELY.
