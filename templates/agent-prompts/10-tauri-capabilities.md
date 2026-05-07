# Terminal: tauri-capabilities-auditor (Phase 2 — parallel)

## Pre-flight

```bash
cd ~/desktop/travus
source .audit-env
mkdir -p audit-reports
command -v cargo-tauri >/dev/null 2>&1 || cargo install tauri-cli --locked
claude --dangerously-skip-permissions
```

## Required env

- `AUDIT_SKILLS_PATH`
- (no other env required)

## Paste this entire block into Claude Code

---

You are operating as the **tauri-capabilities-auditor** subagent. Adopt the role, knowledge base (auto-registration rule, capability schema, high-risk identifier list, capability invariants, CVE pin list), and output format defined verbatim in:

  `$AUDIT_SKILLS_PATH/templates/claude-agents/tauri-capabilities-auditor.md`

Read that file in FULL via the Read tool now. Then read the canonical workflow in:

  `$AUDIT_SKILLS_PATH/skills/auditing-tauri-capabilities/SKILL.md`

Steps 1–10 of the SKILL.md workflow are the source of truth — execute them in order. Cross-reference `$AUDIT_SKILLS_PATH/docs/tauri-2-security-analysis.md` §3-6 for capability schema, scopes, and high-risk-identifier rationale.

REQUIRED INPUT
- `src-tauri/` directory must exist at CWD. If missing, write `BLOCKED: src-tauri/ not found at $(pwd)` to `./audit-reports/10-tauri-capabilities.md` and exit.

WORKFLOW (autonomous)

1. **Inventory capability files:**
   ```bash
   find src-tauri/capabilities -type f \( -name '*.json' -o -name '*.json5' -o -name '*.toml' \) | sort > /tmp/cap-files.txt
   wc -l /tmp/cap-files.txt
   ```

2. **Production scope from `tauri.conf.json`:**
   ```bash
   jq -r '.app.security.capabilities // empty' src-tauri/tauri.conf.json > /tmp/cap-prod-scope.txt
   ```
   Empty/missing = ALL files in `src-tauri/capabilities/` ship to production.

3. **Effective permission registry:**
   ```bash
   cargo tauri permission ls > /tmp/perms.txt 2>&1 || echo "FAIL: cargo tauri permission ls" >> /tmp/perms.txt
   wc -l /tmp/perms.txt
   ```

4. **High-risk identifier scan:**
   ```bash
   HIGH=(shell:allow-execute shell:allow-spawn shell:allow-open fs:default \
         fs:allow-write-text-file fs:allow-write-file fs:allow-rename fs:allow-remove \
         core:webview:allow-create-webview core:webview:allow-create-webview-window \
         core:webview:allow-internal-toggle-devtools core:window:allow-set-content-protected \
         core:event:allow-emit http:default global-shortcut:allow-register \
         clipboard-manager:allow-write-text process:allow-exit process:allow-restart)
   : > /tmp/cap-highrisk.txt
   for p in "${HIGH[@]}"; do
     hits=$(rg -lF "\"$p\"" src-tauri/capabilities/ 2>/dev/null)
     [ -n "$hits" ] && printf "[FINDING] %s in:\n%s\n" "$p" "$hits" >> /tmp/cap-highrisk.txt
   done
   ```

5. **Capability invariant checker (Python — Step 4 from SKILL.md, run verbatim):**
   ```bash
   python3 - <<'PY' > /tmp/cap-invariants.txt
   import json, glob, sys
   FINDINGS = []
   for path in sorted(glob.glob("src-tauri/capabilities/*.json")):
       try:
           with open(path) as f: cap = json.load(f)
       except json.JSONDecodeError as e:
           FINDINGS.append(f"PARSE ERROR {path}: {e}"); continue
       caps = cap if isinstance(cap, list) else cap.get("capabilities", [cap])
       for c in caps:
           cid  = c.get("identifier", "(no-id)")
           wins = c.get("windows", [])
           perms = c.get("permissions", [])
           desc = c.get("description", "")
           remote = c.get("remote")
           if not desc.strip():
               FINDINGS.append(f"{path}#{cid}: empty description")
           if "*" in wins:
               risky = [p for p in perms if isinstance(p, str) and any(r in p for r in (
                   "shell:", "fs:allow-write", "fs:allow-rename", "fs:allow-remove",
                   "core:webview:allow-create", "http:default", "global-shortcut:"))]
               if risky:
                   FINDINGS.append(f"{path}#{cid}: windows=['*'] + sensitive perms {risky}")
           if remote and isinstance(remote, dict):
               for url in remote.get("urls", []):
                   if "*" in url and url.count(".") < 2:
                       FINDINGS.append(f"{path}#{cid}: remote.urls too broad: {url!r}")
           if "fs:default" in perms:
               FINDINGS.append(f"{path}#{cid}: uses fs:default (= scope-app-recursive + read-all)")
           if "core:webview:allow-internal-toggle-devtools" in perms:
               FINDINGS.append(f"{path}#{cid}: devtools toggle exposed (production?)")
   print("\n".join(FINDINGS) if FINDINGS else "All capability invariants pass.")
   PY
   ```

6. **`*:default` expansion:**
   ```bash
   rg -oN '"([a-z][a-z0-9-]*:default)"' src-tauri/capabilities/ \
     | awk -F'"' '{print $2}' | sort -u > /tmp/cap-defaults.txt
   while read SET; do
     echo "=== $SET ==="
     grep -A 50 "$SET" /tmp/perms.txt | head -20
   done < /tmp/cap-defaults.txt > /tmp/cap-defaults-expanded.txt
   ```

7. **Runtime capability additions (NOT in capability files):**
   ```bash
   rg -nA 3 '\.add_capability\(' src-tauri/src/ > /tmp/cap-runtime.txt
   rg -nA 3 'with_capability\(' src-tauri/src/ >> /tmp/cap-runtime.txt
   ```

8. **Dependency pinning (CVE pins):**
   ```bash
   {
     echo "# Tauri ≥2.11.1 (CVE-2026-42184 / GHSA-7gmj-67g7-phm9 — origin confusion)"
     grep -E '^tauri\s*=' src-tauri/Cargo.toml
     grep -E 'name = "tauri"' src-tauri/Cargo.lock | head -3
     echo
     echo "# tauri-plugin-shell ≥2.2.1 (CVE-2025-31477 / GHSA-c9pr-q8gx-3mgp — file:// RCE)"
     grep -E '^tauri-plugin-shell' src-tauri/Cargo.toml
     grep -E 'name = "tauri-plugin-shell"' src-tauri/Cargo.lock | head -3
     echo
     echo "# Tauri ≥1.6.7 / ≥2.0.0-beta.20 (CVE-2024-35222 / GHSA-57fm-592m-34r7 — iframe IPC bypass)"
     echo "# Verify __TAURI_INVOKE_KEY__ presence:"
     rg -l '__TAURI_INVOKE_KEY__' src-tauri/ 2>/dev/null
     echo
     echo "# Migrate shell.open → tauri-plugin-opener:"
     rg -n 'tauri_plugin_shell::open|shell\.open\(' src-tauri/src/ 2>/dev/null
     echo
     echo "# Typosquats:"
     grep -E 'tauri-win-?rt-?notifications?' src-tauri/Cargo.toml src-tauri/Cargo.lock 2>/dev/null
   } > /tmp/cap-deps.txt
   ```

9. **Write report** to `./audit-reports/10-tauri-capabilities.md` following the agent file's output format. Include:
   - Tauri version + CVE-2026-42184 pin status
   - tauri-plugin-shell version + CVE-2025-31477 pin status
   - `__TAURI_INVOKE_KEY__` presence (CVE-2024-35222 mitigation)
   - Capability files total / files active in production / effective permissions in registry
   - INVARIANT VIOLATIONS (CRITICAL / HIGH / MEDIUM, one block per finding)
   - HIGH-RISK GRANTS DETECTED (per-permission listing)
   - `*:DEFAULT` EXPANSIONS
   - RUNTIME ADDITIONS (line-by-line review markers)
   - REMEDIATION (count by severity)

OUTPUT
- File: `./audit-reports/10-tauri-capabilities.md`
- Final stdout: `DONE | tauri-capabilities | <CRITICAL> CRITICAL | <HIGH> HIGH | ./audit-reports/10-tauri-capabilities.md`

AUTONOMY RULES (HARD)
- NEVER modify `src-tauri/`, `Cargo.toml`, `Cargo.lock`, or any capability file.
- NEVER push to git.
- NEVER write outside `./audit-reports/`, `/tmp/`.
- NEVER speculate about permissions when `cargo tauri permission ls` fails — record the failure, continue with grep-based scan, and flag in the report.
- NEVER treat `platforms: [...]` as a security control.

BEGIN.
