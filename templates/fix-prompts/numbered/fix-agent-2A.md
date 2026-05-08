You are operating as **fix-agent-2A** for the pre-launch remediation of the Travus stack. EXECUTE END-TO-END AUTONOMOUSLY.

CONTEXT
- Working directory: the user's app repo (`~/travus`).
- Source audit: `./audit-reports/00-FINAL.md`, `./audit-reports/03-sbom-vuln.md`.
- Output: `./fix-reports/`.
- Mode: `$FIX_MODE` (default `dev`; valid `dev` | `prod` | `dryrun`).
- Tools: `pnpm`, `node`, `git`.

═══════════════════════════════════════════════════════════════════
SCOPE
═══════════════════════════════════════════════════════════════════
Materialize existing pnpm overrides (FIX-16 staged but not yet installed) + apply targeted bumps for vulnerabilities not yet covered. Closes:

| ID | What |
|---|---|
| H-1 | lodash CVE-2026-4800 (override declared, lockfile not regenerated) |
| M-1 | next-intl@4.9.1 prototype pollution (direct in apps/web) |
| M-2 | postcss XSS (override declared) |
| M-3 | sanitize-html@2.17.2 in apps/admin (no override; needs bump) |
| M-4 | yaml@1.10.2 / 2.8.2 stack overflow (no override) |
| M-5 | brace-expansion memory exhaustion (no override) |
| M-6 | fast-xml-parser (override declared) |
| M-7 | markdown-it (override declared; verify mobile renderer) |
| L-1 | icu-minify (resolved by next-intl bump) |

OUT OF SCOPE
- M-8 file-type@16.5.4 — major-version cascade through @jimp; track upstream → fix-agent-4 (LOW backlog).

═══════════════════════════════════════════════════════════════════
PRE-CONDITIONS
═══════════════════════════════════════════════════════════════════
1. `package.json` (workspace root) exists.
2. Working tree clean at start.
3. `MODE=prod` requires `./fix-reports/2A-dev-verified.sentinel`.

═══════════════════════════════════════════════════════════════════
WORKFLOW
═══════════════════════════════════════════════════════════════════

**STEP 0 — Sentinel check (MODE=prod)**
```bash
[ "$FIX_MODE" = "prod" ] && {
  test -f ./fix-reports/2A-dev-verified.sentinel \
    || { echo "BLOCKED: dev verification sentinel missing" > ./fix-reports/2A-result.md; exit 1; }
}
```
For 2A, MODE=dev means "apply edits + run pnpm install + audit"; MODE=prod means "open a PR with the changes, do not auto-merge".

**STEP 1 — Edit package.json files**

a) Root `package.json` — add to `pnpm.overrides` (preserve existing keys):
```json
{
  "yaml@<1.10.3": ">=1.10.3",
  "yaml@<2.8.3": ">=2.8.3",
  "brace-expansion@<1.1.13": ">=1.1.13",
  "brace-expansion@<2.0.3": ">=2.0.3",
  "brace-expansion@<5.0.5": ">=5.0.5"
}
```
Use Edit tool with surgical surroundings (read the existing pnpm.overrides block, append).

b) `apps/admin/package.json` — bump `sanitize-html`:
```diff
-  "sanitize-html": "^2.17.2"
+  "sanitize-html": "^2.17.3"
```

c) `apps/web/package.json` — confirm `next-intl: ^4.9.2` (the audit notes the override was declared; if `^4.9.1` is the spec, bump):
```diff
-  "next-intl": "^4.9.1"
+  "next-intl": "^4.9.2"
```

**STEP 2 — Materialize lockfile**
```bash
pnpm install 2>&1 | tee /tmp/2A-install.log
```

If install fails (peer-dep conflict from M-7 markdown-it bump), capture stderr, write `result=PEER_DEP_CONFLICT` with the offending package, exit non-zero.

**STEP 3 — Audit**
```bash
pnpm audit --prod --audit-level high --json > /tmp/2A-audit.json 2>&1 || true
HIGH_COUNT=$(jq '.metadata.vulnerabilities.high // 0' /tmp/2A-audit.json)
CRITICAL_COUNT=$(jq '.metadata.vulnerabilities.critical // 0' /tmp/2A-audit.json)
```

Expected: `HIGH_COUNT=0` and `CRITICAL_COUNT=0`. If non-zero, list the still-vulnerable packages in the report.

**STEP 4 — Mobile markdown renderer smoke test (M-7 verification)**

The audit flagged `react-native-markdown-display@7.0.2` peer-deps `markdown-it@^10`; the override bumps to `>=12.3.2`. This may render-break.

```bash
cd apps/mobile
pnpm tsc --noEmit 2>&1 | tee /tmp/2A-mobile-tsc.log
# If TS check passes, the type contract is intact. Renderer regression can only be caught at runtime.
cd -
```

Flag in the report: "Mobile renderer requires manual smoke test in dev build (open a markdown-rendered screen and check for blank/broken layout)."

**STEP 5 — MODE=prod: open PR**

If `MODE=prod`, create a branch, commit, push, open PR via `gh`:
```bash
git checkout -b fix-2A/dependency-sweep
git add package.json apps/admin/package.json apps/web/package.json pnpm-lock.yaml
git commit -m "fix(deps): clear H-1 + M-1..M-7 + L-1 via pnpm sweep + targeted bumps

Closes audit findings: H-1 lodash, M-1 next-intl, M-2 postcss, M-3 sanitize-html,
M-4 yaml, M-5 brace-expansion, M-6 fast-xml-parser, M-7 markdown-it, L-1 icu-minify.

Verification: pnpm audit --prod --audit-level high → 0 high, 0 critical."
git push -u origin fix-2A/dependency-sweep
gh pr create --title "fix(deps): pnpm sweep clears H-1 + 5 MEDIUMs + 1 LOW" \
  --body "$(cat ./fix-reports/2A-result.md)"
```

**STEP 6 — Sentinel + report**

Dev success:
```bash
cat > ./fix-reports/2A-dev-verified.sentinel <<EOF
fix-agent-2A dev verification PASSED at $(date -u +%Y-%m-%dT%H:%M:%SZ)
high_vulns_after: $HIGH_COUNT
critical_vulns_after: $CRITICAL_COUNT
EOF
```

`./fix-reports/2A-result.md`:
```
FIX-AGENT-2A RESULT
===================
Date: <ISO-8601>
Mode: dev | prod | dryrun
Result: PASS | FAIL | BLOCKED | PEER_DEP_CONFLICT | VULNS_REMAIN

Files edited:
- package.json (pnpm.overrides updated: +yaml ×2, +brace-expansion ×3)
- apps/admin/package.json (sanitize-html ^2.17.3)
- apps/web/package.json (next-intl ^4.9.2)
- pnpm-lock.yaml (regenerated)

pnpm audit --prod --audit-level high (after):
  critical: <N>  (expected 0)
  high: <N>      (expected 0)

Mobile TS check: PASS | FAIL
Mobile renderer manual smoke test: REQUIRED (markdown-it bumped from ^10 to >=12.3.2)

PR (MODE=prod only): <URL or N/A>

Next agent: any of fix-agent-2B..2H in parallel.
```

**STEP 7 — Final stdout:**
```
DONE | fix-agent-2A | <mode> | <result> | ./fix-reports/2A-result.md
```

═══════════════════════════════════════════════════════════════════
HARD AUTONOMY RULES
═══════════════════════════════════════════════════════════════════
- NEVER touch M-8 (file-type) — it's a major version cascade; out of scope.
- NEVER auto-merge the PR. Stop after `gh pr create`.
- NEVER edit other workspaces' package.json beyond the listed targets.
- If pnpm install requires `--force` or `--shamefully-hoist`, BLOCKED — flag for manual review.
- BEGIN IMMEDIATELY.
