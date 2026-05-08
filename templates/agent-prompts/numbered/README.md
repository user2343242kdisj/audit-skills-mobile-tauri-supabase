# Numbered Agents — `exec agent-N.md` UX

Numbered, paste-direct prompts. Each terminal runs one command:

```
exec agent-N.md
```

## Zero-touch setup (recommended)

```bash
cd ~/desktop/travus
git clone https://github.com/user2343242kdisj/audit-skills-mobile-tauri-supabase.git ../audit-skills 2>/dev/null
claude --dangerously-skip-permissions
# Paste the contents of:
#   ../audit-skills/templates/agent-prompts/numbered/agent-0.md
```

`agent-0` (the **setup-agent**) does everything below for you: installs the wrapper, hardens `.gitignore`, scaffolds `.audit-env`, detects your stack, writes a setup report. After it finishes, you fill in the CHANGEME values in `.audit-env` and run `exec-agent agent-1.md`.

## Manual setup (if you prefer)

```bash
# 1. Make the exec script available on your PATH (pick one):
sudo cp ../audit-skills/templates/agent-prompts/numbered/exec /usr/local/bin/exec-agent
# OR per-user:
mkdir -p ~/.local/bin && cp ../audit-skills/templates/agent-prompts/numbered/exec ~/.local/bin/exec-agent
export PATH="$HOME/.local/bin:$PATH"   # add to ~/.zshrc

# 2. Configure env in your app repo (one time)
cd ~/desktop/travus
[ -d ../audit-skills ] || git clone https://github.com/user2343242kdisj/audit-skills-mobile-tauri-supabase.git ../audit-skills
mkdir -p audit-reports
echo "audit-reports/" >> .gitignore
echo ".audit-env" >> .gitignore
chmod 600 .audit-env  # after you fill it
```

> **Note:** the script is named `exec-agent` (not `exec`) when installed on PATH because `exec` is a built-in shell keyword. Inside this directory the script file is named `exec` for convenience — but you call it as `exec-agent` from any terminal.

## Per-terminal workflow

Open 16 terminals (or `tmux` panes). In each:

```bash
cd ~/desktop/travus
source .audit-env
exec-agent agent-1.md          # terminal 1 → threat model
```

```bash
cd ~/desktop/travus
source .audit-env
exec-agent agent-2.md          # terminal 2 → secrets scan
```

… and so on for `agent-3.md` through `agent-16.md`.

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
Terminal 1:  exec-agent agent-1.md          # ← wait for DONE before launching 2-15
Terminals 2-15:  exec-agent agent-N.md      # ← all in parallel; wait for all 14 DONE
Terminal 16: exec-agent agent-16.md         # ← synthesis; produces audit-reports/00-FINAL.md
```

## Batch launch for Phase 2 (alternative to opening 14 terminals)

```bash
cd ~/desktop/travus
source .audit-env
for n in 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
  log="audit-reports/agent-$n.log"
  ( exec-agent "agent-$n.md" > "$log" 2>&1 ) &
done
wait
echo "Phase 2 complete. Logs in audit-reports/agent-*.log"
exec-agent agent-16.md
```

## Each agent's autonomy guarantees

- Never asks the user (writes `BLOCKED: <reason>` if env missing)
- Never destructive (no DROP/DELETE/force push)
- Writes only to `./audit-reports/`, `./sbom/`, `/tmp/`
- Never pushes to git
- Final stdout: `DONE | <name> | N CRITICAL | N HIGH | <report path>`

## Re-running after a fix

```bash
exec-agent agent-6.md       # e.g. re-audit auth after CVE-2026-31813 fix
exec-agent agent-16.md      # refresh the synthesis
```

## Source files

The numbered files are mechanically generated from the topic-named originals in `../raw/`. To regenerate:

```bash
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
