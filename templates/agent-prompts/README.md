# Agent Prompts — Parallel-Terminal Audit

Self-contained prompts to paste into individual Claude Code terminals so each subagent runs **fully autonomously, in parallel**, and writes its findings to `./audit-reports/`.

**Two ways to run:**
- **MASTER (1 terminal, easiest)** — paste [`MASTER.md`](MASTER.md) into a single Claude Code session. Phase 1 runs inline; 14 Phase-2 agents dispatched in parallel via the Agent tool; Phase 3 synthesis. End-to-end, fully autonomous.
- **16 individual terminals (max isolation)** — paste each numbered prompt into its own terminal as documented below.

**16 prompts** — designed to run in 16 individual terminals for max parallelism:

```
00-orchestrator.md                          ← Phase 3 (last): synthesises the 15 reports
01-threat-modeler.md                        ← Phase 1 (first): drives MAS profile selection
02-secrets-scanner.md                       ┐
03-sbom-vuln.md                             │
04-sast-dast.md                             │
05-supabase-rls.md                          │
06-supabase-auth.md                         │
07-supabase-edge-functions.md               │ Phase 2 (parallel —
08-supabase-postgres.md                     │ run 14 in parallel)
09-supabase-storage-realtime-network.md     │
10-tauri-capabilities.md                    │
11-tauri-ipc.md                             │
12-tauri-config-and-distribution.md         │  (CSP + WebView + updater + binary hardening)
13-mobile-static.md                         │
14-mobile-dynamic.md                        │
15-mobile-platform.md                       ┘  (deeplinks + Keychain/Keystore + cert pinning)
```

## One-time setup (in YOUR APP REPO at `~/desktop/travus`)

The audit runs from `~/desktop/travus` (your Tauri app repo). `audit-skills` is installed **inside the repo** as `./audit/` (gitignored). Reports go to `./audit-reports/` (also gitignored). Every prompt assumes the working directory contains:
- `src-tauri/` — Tauri Rust core + capabilities + tauri.conf.json
- `supabase/` (or accessible via `SUPABASE_DB_URL`) — Edge Functions + migrations + tests
- `android/` and/or `ios/` if mobile is built in this repo (otherwise mobile agents skip)
- `package.json` — root npm dependencies
- `audit/` — cloned audit-skills (gitignored)
- `audit-reports/` — created on first run, gitignored

### Zero-touch (recommended)

```bash
cd ~/desktop/travus
curl -fsSL https://raw.githubusercontent.com/user2343242kdisj/audit-skills-mobile-tauri-supabase/main/install.sh | bash
```

`install.sh` clones the repo into `./audit/`, installs the `exec-agent` wrapper, creates `./audit-reports/`, and adds both `audit/` and `audit-reports/` to `.gitignore`. Secrets live in 1Password and are resolved at runtime via `op read` — no `.audit-env` file is created.

### Manual

```bash
cd ~/desktop/travus

# 1. Clone audit-skills INSIDE your app repo as ./audit/
[ -d ./audit ] || git clone https://github.com/user2343242kdisj/audit-skills-mobile-tauri-supabase.git ./audit

# 2. Audit reports directory + gitignore both audit/ and audit-reports/
mkdir -p audit-reports
grep -qxF "audit-reports/" .gitignore 2>/dev/null || echo "audit-reports/" >> .gitignore
grep -qxF "audit/"         .gitignore 2>/dev/null || echo "audit/"         >> .gitignore

# 3. Verify 1Password CLI is authenticated (agents resolve secrets via `op read`)
op vault list >/dev/null
```

The shared path is `./audit/templates/agent-prompts/...`. If you prefer an env var for scripts:

```bash
export AUDIT_SKILLS_PATH="./audit"
```

## Run pattern

### Phase 1 — Threat model (sequential, runs FIRST)

```bash
# Terminal 1
cd ~/desktop/travus
claude --dangerously-skip-permissions  # auto-approve tool calls
# Then paste the contents of ./audit/templates/agent-prompts/01-threat-modeler.md
```

Wait for `DONE | threat-modeler | …` line. Output: `audit-reports/01-threat-model.md`.

### Phase 2 — Domain auditors (parallel)

Open 14 separate terminals (or use `tmux`/`zellij` for split-pane). In each:

```bash
cd ~/desktop/travus
claude --dangerously-skip-permissions
# Then paste the contents of ./audit/templates/agent-prompts/<NN>-<name>.md
```

Each writes its report to `audit-reports/<NN>-<name>.md`.

You can also batch them with `claude -p` (non-interactive):

```bash
# In a launch script, looping over Phase 2 prompts (skip 00 and 01):
cd ~/desktop/travus
op vault list >/dev/null   # unlock 1Password once
for prompt in ./audit/templates/agent-prompts/0[2-9]-*.md \
              ./audit/templates/agent-prompts/1[0-5]-*.md; do
  name=$(basename "$prompt" .md)
  log="audit-reports/$name.log"
  (claude --dangerously-skip-permissions -p "$(cat "$prompt")" > "$log" 2>&1) &
done
wait
echo "All 14 Phase 2 agents complete."
```

### Phase 3 — Orchestrator synthesis (sequential, runs LAST)

```bash
cd ~/desktop/travus
claude --dangerously-skip-permissions
# Then paste the contents of ./audit/templates/agent-prompts/00-orchestrator.md
```

Output: `audit-reports/00-FINAL.md`.

## Autonomy guarantees

Every prompt embeds the same autonomy rules:

1. **No questions to user mid-flight.** Missing input → write `BLOCKED: <reason>` and exit cleanly.
2. **No destructive operations.** Audit only. No DROP, DELETE, force push, `rm -rf` outside `/tmp`.
3. **Writes restricted to `./audit-reports/`.** Never modifies app code.
4. **Reads from approved paths only:** the app repo (including `./audit/`), `/tmp/`.
5. **Never pushes to git** — the user reviews the report directory and acts on it.
6. **Final stdout line is parse-friendly:** `DONE | <agent-name> | <CRITICAL> CRITICAL | <HIGH> HIGH | <report-path>`.

## What each agent produces

| File | Contents |
|---|---|
| `audit-reports/00-FINAL.md` | Aggregated executive report; quotes from subagent reports with attribution |
| `audit-reports/01-threat-model.md` | DFD, STRIDE list, attack tree, MAS profile recommendation |
| `audit-reports/02-secrets-scan.md` | ggshield + TruffleHog + Gitleaks consolidated findings |
| `audit-reports/03-sbom-vuln.md` | CycloneDX SBOMs + Grype/Trivy/cargo-audit findings |
| `audit-reports/04-sast-dast.md` | Semgrep + Schemathesis + BOLA harness + ZAP results |
| `audit-reports/05-supabase-rls.md` | Splinter (28 rules) + pgTAP coverage + policy review |
| `audit-reports/06-supabase-auth.md` | GoTrue version, MFA, JWT migration, CVE-2026-31813 / 2025-48370 / GHSA-3529 checks |
| `audit-reports/07-supabase-edge-functions.md` | Deno lint + 13 custom Semgrep rules |
| `audit-reports/08-supabase-postgres.md` | Roles, grants, search_path, extensions, FDWs, 7 upstream PG CVEs |
| `audit-reports/09-supabase-storage-realtime-network.md` | Bucket + signed URL audit · realtime.messages policies + private channel check · TLS testssl.sh + Network Restrictions |
| `audit-reports/10-tauri-capabilities.md` | ACL invariants, high-risk identifiers, runtime add_capability, dep pin (CVE-2026-42184 / 2025-31477 / 2024-35222) |
| `audit-reports/11-tauri-ipc.md` | Commands (6-class vuln checklist), custom schemes, isolation pattern, channels, events |
| `audit-reports/12-tauri-config-and-distribution.md` | CSP/WebView (sec A) + updater Ed25519 (sec B) + binary hardening + signing (sec C) |
| `audit-reports/13-mobile-static.md` | MobSF + jadx + apktool + manifest red-flags + plutil/codesign/otool |
| `audit-reports/14-mobile-dynamic.md` | Frida pinning bypass + Burp + Objection memory dump + Drozer scanners |
| `audit-reports/15-mobile-platform.md` | Deeplinks/intents (sec A) + Keychain/Keystore (sec B) + cert pinning (sec C) |

## Skipping irrelevant agents

If your stack doesn't have a layer (e.g. no mobile app, just Tauri + Supabase), skip the mobile prompts. The orchestrator detects missing reports and notes them as N/A rather than failing.

## Re-running after fix

After remediation, re-run only the affected agents:

```bash
cd ~/desktop/travus
# Example: re-run after fixing CVE-2026-31813
claude --dangerously-skip-permissions -p "$(cat ./audit/templates/agent-prompts/06-supabase-auth.md)"
# Then re-run orchestrator to refresh the synthesis
claude --dangerously-skip-permissions -p "$(cat ./audit/templates/agent-prompts/00-orchestrator.md)"
```

## CI integration

For continuous auditing in CI, see [`templates/security-workflow.yml`](../security-workflow.yml). The CI workflow uses the same tools but as deterministic GitHub Actions steps rather than agent-driven prompts. Both have a place:

- **Agent prompts** → human-in-the-loop deep audit; pre-launch
- **CI workflow** → mechanical regression gating; every PR
