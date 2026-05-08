# Numbered Agents — `exec agent-N.md` UX

Numbered, paste-direct prompts. Each terminal runs one command:

```
exec agent-N.md
```

## Layout

`audit-skills` is installed **inside your Tauri app repo** as `./audit/` (gitignored). Reports are written to `./audit-reports/` (also gitignored). Both live next to your existing `src-tauri/`, `supabase/`, etc.

```
~/desktop/travus/                    ← your Tauri app repo
├── src-tauri/
├── supabase/
├── android/, ios/
├── audit-reports/                   ← gitignored, agents write here
├── audit/                           ← cloned audit-skills (also gitignored)
│   ├── templates/agent-prompts/numbered/{agent-0.md … agent-16.md, exec}
│   ├── tools/
│   └── docs/
└── .gitignore                       ← contains audit-reports/ + audit/
```

## Zero-touch setup (recommended)

```bash
cd ~/desktop/travus
curl -fsSL https://raw.githubusercontent.com/user2343242kdisj/audit-skills-mobile-tauri-supabase/main/install.sh | bash
claude --dangerously-skip-permissions
# Paste the contents of:
#   ./audit/templates/agent-prompts/numbered/agent-0.md
```

`install.sh` clones the repo into `./audit/`, installs the `exec-agent` wrapper on your PATH, creates `./audit-reports/`, and adds both `audit/` and `audit-reports/` to `.gitignore`.

`agent-0` (the **setup-agent**) then verifies `op` CLI authentication, lists expected 1Password item paths, detects your stack, and writes a setup report. **No `.audit-env` is created** — secrets live in 1Password and are resolved at runtime via `op read`.

## Manual setup (if you prefer)

```bash
cd ~/desktop/travus

# 1. Clone audit-skills INSIDE your app repo as ./audit/
[ -d ./audit ] || git clone https://github.com/user2343242kdisj/audit-skills-mobile-tauri-supabase.git ./audit

# 2. Make the exec script available on your PATH (pick one):
sudo cp ./audit/templates/agent-prompts/numbered/exec /usr/local/bin/exec-agent
# OR per-user:
mkdir -p ~/.local/bin && cp ./audit/templates/agent-prompts/numbered/exec ~/.local/bin/exec-agent
export PATH="$HOME/.local/bin:$PATH"   # add to ~/.zshrc

# 3. Create reports dir + gitignore both audit/ and audit-reports/
mkdir -p audit-reports
grep -qxF "audit-reports/" .gitignore 2>/dev/null || echo "audit-reports/" >> .gitignore
grep -qxF "audit/"         .gitignore 2>/dev/null || echo "audit/"         >> .gitignore

# 4. Verify 1Password CLI is authenticated (op session unlocks on first read each Claude session)
op vault list 2>&1 | head -5
```

### Required 1Password items

The agents resolve these paths via `op read` at runtime. Create the items in your `Private` vault (or update the paths in each agent prompt):

| Path | Used by |
|---|---|
| `op://Private/Supabase Travus/db_url` | agents 5, 6, 8, 9 |
| `op://Private/Supabase Travus/project_ref` | agents 4, 6, 9 |
| `op://Private/Supabase Travus/anon_key` | agents 4, 6 |
| `op://Private/Supabase Travus/service_role_key` | (sensitive — used only when MCP is unavailable) |
| `op://Private/Supabase Travus/management_api_token` | agents 6, 9 |
| `op://Private/Test Users Travus/user_a_jwt` | agent 4 (BOLA harness) |
| `op://Private/Test Users Travus/user_b_jwt` | agent 4 (BOLA harness) |
| `op://Private/GitGuardian/api_key` | agent 2 |
| `op://Private/MobSF/api_key` | agent 13 (optional) |
| `op://Private/Tauri Travus/updater_pubkey` | agent 12 (optional) |
| `op://Private/Apple Developer/asc_api_key` | agent 12 (optional) |

> **Note:** the script is named `exec-agent` (not `exec`) when installed on PATH because `exec` is a built-in shell keyword. Inside this directory the script file is named `exec` for convenience — but you call it as `exec-agent` from any terminal.

## Per-terminal workflow

Open 16 terminals (or `tmux` panes). In each:

```bash
cd ~/desktop/travus
exec-agent ./audit/templates/agent-prompts/numbered/agent-1.md   # terminal 1 → threat model
```

```bash
cd ~/desktop/travus
exec-agent ./audit/templates/agent-prompts/numbered/agent-2.md   # terminal 2 → secrets scan
```

… and so on for `agent-3.md` through `agent-16.md`. (If `exec-agent` resolves bare names against `./audit/templates/agent-prompts/numbered/`, you can use the short form `exec-agent agent-1.md`.)

## Agent → topic map

| File | Topic | Phase |
|---|---|---|
| `agent-0.md` | **setup-agent** | 0 (run FIRST, ONCE — installs toolchain) |
| `agent-1.md` | threat-modeler | 1 (run FIRST, sequential) |
| `agent-2.md` | secrets-scanner | 2 (parallel) |
| `agent-3.md` | sbom-vuln | 2 |
| `agent-4.md` | sast-dast | 2 |
| `agent-5.md` | supabase-rls | 2 |
| `agent-6.md` | supabase-auth | 2 |
| `agent-7.md` | supabase-edge-functions | 2 |
| `agent-8.md` | supabase-postgres | 2 |
| `agent-9.md` | supabase-storage-realtime-network | 2 |
| `agent-10.md` | tauri-capabilities | 2 |
| `agent-11.md` | tauri-ipc | 2 |
| `agent-12.md` | tauri-config-and-distribution | 2 |
| `agent-13.md` | mobile-static | 2 |
| `agent-14.md` | mobile-dynamic | 2 |
| `agent-15.md` | mobile-platform | 2 |
| `agent-16.md` | orchestrator (synthesis) | 3 (run LAST, sequential) |

## Recommended order

```
Terminal 1:      exec-agent ./audit/templates/agent-prompts/numbered/agent-1.md    # ← wait for DONE before launching 2-15
Terminals 2-15:  exec-agent ./audit/templates/agent-prompts/numbered/agent-N.md    # ← all in parallel; wait for all 14 DONE
Terminal 16:     exec-agent ./audit/templates/agent-prompts/numbered/agent-16.md   # ← synthesis; produces audit-reports/00-FINAL.md
```

## Batch launch for Phase 2 (alternative to opening 14 terminals)

```bash
cd ~/desktop/travus
# Trigger 1Password unlock once (any op read in foreground first)
op vault list >/dev/null
PROMPTS=./audit/templates/agent-prompts/numbered
for n in 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
  log="audit-reports/agent-$n.log"
  ( exec-agent "$PROMPTS/agent-$n.md" > "$log" 2>&1 ) &
done
wait
echo "Phase 2 complete. Logs in audit-reports/agent-*.log"
exec-agent "$PROMPTS/agent-16.md"
```

## Each agent's autonomy guarantees

- Never asks the user (writes `BLOCKED: <reason>` if env missing)
- Never destructive (no DROP/DELETE/force push)
- Writes only to `./audit-reports/`, `./sbom/`, `/tmp/`
- Never pushes to git
- Final stdout: `DONE | <name> | N CRITICAL | N HIGH | <report path>`

## Re-running after a fix

```bash
cd ~/desktop/travus
PROMPTS=./audit/templates/agent-prompts/numbered
exec-agent "$PROMPTS/agent-6.md"     # e.g. re-audit auth after CVE-2026-31813 fix
exec-agent "$PROMPTS/agent-16.md"    # refresh the synthesis
```

## Source files

The numbered files are mechanically generated from the topic-named originals in `./audit/templates/agent-prompts/raw/`. To regenerate (run from inside the `audit/` clone):

```bash
cd ~/desktop/travus/audit
declare -a MAP=(
  "1:01-threat-modeler" "2:02-secrets-scanner" "3:03-sbom-vuln" "4:04-sast-dast"
  "5:05-supabase-rls" "6:06-supabase-auth" "7:07-supabase-edge-functions"
  "8:08-supabase-postgres" "9:09-supabase-storage-realtime-network"
  "10:10-tauri-capabilities" "11:11-tauri-ipc" "12:12-tauri-config-and-distribution"
  "13:13-mobile-static" "14:14-mobile-dynamic" "15:15-mobile-platform"
  "16:00-orchestrator"
)
for entry in "${MAP[@]}"; do
  N="${entry%%:*}"; TOPIC="${entry#*:}"
  cat templates/agent-prompts/raw/"$TOPIC".txt > templates/agent-prompts/numbered/"agent-$N.md"
done
```
