---
name: auditing-tauri-capabilities
description: >-
  Audits Tauri 2 capability files (src-tauri/capabilities/*) and tauri.conf.json
  for over-grants, dangerous permission identifiers, scope bypasses, isolation
  pattern misconfiguration, dangerousDisableAssetCspModification abuse, broken
  CSP, and updater key handling. Activates for requests involving Tauri desktop
  app security audits, capability lint, IPC review, ACL inspection, or
  pre-launch hardening checks for Rust+WebView desktop apps.
domain: cybersecurity
subdomain: application-security
tags:
  - tauri
  - desktop-security
  - capabilities
  - ipc
  - audit
  - csp
  - rust
version: 1.0.0
author: sreis
license: Apache-2.0
mitre_attack:
  - T1059
  - T1190
  - T1574
nist_csf:
  - PR.IP-12
  - DE.CM-08
  - PR.AC-04
  - PR.DS-06
---

# Auditing Tauri 2 Capabilities

## When to Use

- Auditing a Tauri 2 desktop application before production launch
- Reviewing capability files and `tauri.conf.json` for security misconfigurations
- Investigating an IPC abuse incident and reconstructing the granted attack surface
- Running pre-merge review on a PR that touches `src-tauri/capabilities/*` or `tauri.conf.json`
- Validating that the upgrade from Tauri 1 allowlist to Tauri 2 capabilities did not silently widen permissions

**Do not use** for mobile-app audits (use OWASP MASTG-aligned skills); for the Rust binary itself (use `performing-binary-exploitation-analysis`); for the WebView frontend XSS surface (use `testing-for-xss-vulnerabilities` and `performing-content-security-policy-bypass`).

## Prerequisites

- Tauri 2 source tree with `src-tauri/` accessible
- `tauri-cli >= 2.11.1` (CVE-2026-42184 fixed) — `cargo install tauri-cli --locked`
- Tauri version pinned in `Cargo.toml`: `tauri = "^2.11.1"`
- `tauri-plugin-shell` pinned `>= 2.2.1` (CVE-2025-31477 fixed) if used
- `jq` and `python3` available for JSON parsing
- `ripgrep` (`rg`) for fast searches
- Optional: VS Code with the Tauri extension for inline schema validation

## Workflow

### Step 1: Inventory capability files

```bash
# List every capability file (auto-registered by Tauri)
find src-tauri/capabilities -type f \( -name '*.json' -o -name '*.json5' -o -name '*.toml' \) | sort

# Confirm whether tauri.conf.json restricts the active set
jq -r '.app.security.capabilities // empty' src-tauri/tauri.conf.json
# Empty/missing = ALL files in src-tauri/capabilities/ are active
```

```
RED FLAG: If src-tauri/capabilities/dev-*.json or *-debug.json files
exist and `app.security.capabilities` is empty, dev capabilities ship
in production. Confirm by reading every file.
```

### Step 2: Inline-expand `*:default` references

Every `*:default` reference (e.g. `fs:default`, `core:default`) hides multiple permissions. Expand them programmatically:

```bash
# Use the Tauri CLI to dump the effective permission registry
cargo tauri permission ls > /tmp/perms.txt

# For each *:default in capability files, find what it includes
rg -oN '"([a-z][a-z0-9-]*:default)"' src-tauri/capabilities/ | \
  awk -F'"' '{print $2}' | sort -u | while read SET; do
    echo "=== $SET ==="
    grep -A 50 "$SET" /tmp/perms.txt | head -20
done
```

### Step 3: Apply the high-risk identifier checklist

Grep each capability file for any identifier on this list. Each match is a finding unless explicitly justified in the capability's `description`:

```bash
HIGH_RISK_PERMS=(
  "shell:allow-execute"
  "shell:allow-spawn"
  "shell:allow-open"          # CVE-2025-31477 if plugin < 2.2.1
  "fs:default"                # = read-all + scope-app-recursive
  "fs:allow-write-text-file"
  "fs:allow-write-file"
  "fs:allow-rename"
  "fs:allow-remove"
  "core:webview:allow-create-webview"
  "core:webview:allow-create-webview-window"
  "core:webview:allow-internal-toggle-devtools"
  "core:window:allow-set-content-protected"
  "core:event:allow-emit"
  "http:default"
  "global-shortcut:allow-register"
  "clipboard-manager:allow-write-text"
  "process:allow-exit"
  "process:allow-restart"
)

for perm in "${HIGH_RISK_PERMS[@]}"; do
  results=$(rg -l --type=json --type=toml -F "\"$perm\"" src-tauri/capabilities/ 2>/dev/null)
  if [ -n "$results" ]; then
    echo "FINDING: $perm granted in:"
    echo "$results" | sed 's/^/  /'
  fi
done
```

```
EXPECTED: zero matches in production capabilities, OR every match must have:
- An explicit, non-empty description
- An inline scope object (allow + deny arrays)
- Window/webview labels (not "*")
```

### Step 4: Check capability invariants

```bash
python3 - <<'PY'
import json, glob, sys

CRITICAL_INVARIANTS = []

for path in sorted(glob.glob("src-tauri/capabilities/*.json")):
    with open(path) as f:
        try:
            cap = json.load(f)
        except json.JSONDecodeError as e:
            print(f"PARSE ERROR {path}: {e}")
            continue

    # Multiple capabilities per file: cap may be a list or {capabilities: [...]}.
    caps = cap if isinstance(cap, list) else cap.get("capabilities", [cap])

    for c in caps:
        cid = c.get("identifier", "(no-id)")
        windows = c.get("windows", [])
        webviews = c.get("webviews", [])
        permissions = c.get("permissions", [])
        description = c.get("description", "")
        remote = c.get("remote")

        # Invariant 1: non-empty description
        if not description.strip():
            CRITICAL_INVARIANTS.append(f"{path}#{cid}: empty description")

        # Invariant 2: no wildcard window
        if windows == ["*"] or "*" in windows:
            # Combined with sensitive perms = critical
            risky = [p for p in permissions if (
                isinstance(p, str) and any(r in p for r in (
                    "shell:", "fs:allow-write", "fs:allow-rename",
                    "fs:allow-remove", "core:webview:allow-create",
                    "http:default", "global-shortcut:"
                ))
            )]
            if risky:
                CRITICAL_INVARIANTS.append(
                    f"{path}#{cid}: windows=['*'] + sensitive perms {risky}"
                )

        # Invariant 3: remote.urls must not be permissive
        if remote and isinstance(remote, dict):
            for url in remote.get("urls", []):
                if "*" in url and not url.count(".") >= 2:
                    CRITICAL_INVARIANTS.append(
                        f"{path}#{cid}: remote.urls too broad: {url!r}"
                    )

        # Invariant 4: no fs:default (= read-all)
        if "fs:default" in permissions:
            CRITICAL_INVARIANTS.append(
                f"{path}#{cid}: uses fs:default (= scope-app-recursive + read-all)"
            )

        # Invariant 5: no devtools in production
        if "core:webview:allow-internal-toggle-devtools" in permissions:
            CRITICAL_INVARIANTS.append(
                f"{path}#{cid}: devtools toggle exposed (production?)"
            )

if CRITICAL_INVARIANTS:
    print("\n".join(CRITICAL_INVARIANTS))
    sys.exit(1)
else:
    print("All capability invariants pass.")
PY
```

### Step 5: Audit `tauri.conf.json > app.security`

```bash
jq '{
  csp: .app.security.csp,
  devCsp: .app.security.devCsp,
  freezePrototype: .app.security.freezePrototype,
  dangerousDisableAssetCspModification: .app.security.dangerousDisableAssetCspModification,
  assetProtocol: .app.security.assetProtocol,
  pattern: .app.security.pattern,
  withGlobalTauri: .app.withGlobalTauri,
  capabilities: .app.security.capabilities
}' src-tauri/tauri.conf.json
```

Apply this checklist to the output:

| Field | Required value | Why |
|---|---|---|
| `csp` | non-null, no `'unsafe-inline'`, no `'unsafe-eval'` | CSP off = XSS = full IPC |
| `freezePrototype` | `true` | Blocks prototype-pollution gadgets |
| `dangerousDisableAssetCspModification` | `false` (or empty array) | Disables Tauri's hash/nonce injection |
| `assetProtocol.enable` | `false` unless used | Each enable widens fs surface |
| `assetProtocol.scope.requireLiteralLeadingDot` | `true` | Windows default is unsafe |
| `pattern.use` | `"isolation"` | AES-GCM IPC validation; only skip if impossible |
| `withGlobalTauri` | `false` | Reduces XSS-to-IPC discoverability |

### Step 6: Audit updater configuration

```bash
jq '.plugins.updater' src-tauri/tauri.conf.json
```

Check:

```
- pubkey: present and matches the published key
- endpoints: HTTPS only (no http://, no dangerousInsecureTransportProtocol)
- dangerousInsecureTransportProtocol: false (or absent)
- windows.installMode: "passive" or "basicUi" (not "quiet" for per-machine)
```

```bash
# Verify embedded pubkey matches what you control
strings target/release/<binary> | grep -i "untrusted-comment"
# Compare to your minisign public key on a trusted host
```

### Step 7: Search for runtime capability additions

Tauri 2 supports `Manager::add_capability` at runtime — these are NOT in capability files:

```bash
rg -n '\.add_capability\(' src-tauri/src/
rg -n 'with_capability\(' src-tauri/src/
```

Each match must be reviewed line-by-line. Runtime capabilities frequently bypass the static audit.

### Step 8: Fuzz commands for argument-handling bugs

For each command exposed via `#[tauri::command]`, manually review for:

- Path arguments not canonicalised + allowlisted in Rust
- `String`/`Vec<u8>` without length bounds (DoS via 4 GB JSON)
- `#[serde(flatten)]` with `serde_json::Value` (recursion DoS)
- Errors leaking filesystem paths or stack traces
- Authorization decisions imported from frontend state
- `register_uri_scheme_protocol` handlers reflecting URL into HTML / forwarding to `reqwest`

```bash
rg -n '#\[tauri::command\]' src-tauri/src/ -A 10 | less
rg -n 'register_uri_scheme_protocol' src-tauri/src/
```

### Step 9: Verify dependency pinning

```bash
# Tauri >= 2.11.1 (CVE-2026-42184)
grep -E '^tauri\s*=' src-tauri/Cargo.toml

# tauri-plugin-shell >= 2.2.1 (CVE-2025-31477)
grep -E '^tauri-plugin-shell' src-tauri/Cargo.toml

# Migrate shell.open -> tauri-plugin-opener
grep -E 'tauri_plugin_shell::open' src-tauri/src/

# No typosquats
grep -E 'tauri-win-?rt-?notifications?' src-tauri/Cargo.toml src-tauri/Cargo.lock
```

### Step 10: Check signing & build hardening

```bash
# Cargo release profile present and tight
grep -A 8 '^\[profile\.release\]' src-tauri/Cargo.toml

# RUSTFLAGS hardening (look in CI)
rg -n 'RUSTFLAGS' .github/ src-tauri/

# macOS entitlements minimum surface
test -f src-tauri/entitlements.plist && plutil -p src-tauri/entitlements.plist
```

## Key Concepts

| Term | Definition |
|---|---|
| **Capability** | JSON/TOML file binding permissions to specific window labels, webview labels, platforms, and origin context (local vs remote). |
| **Permission** | Smallest ACL atom; whitelists/blacklists a set of commands and optionally carries a scope. |
| **Scope** | Plugin-specific JSON value (e.g. `{path: "$APPDATA/**"}` for fs) injected into command invocations. |
| **Runtime Authority** | Tauri Core singleton that resolves `(window, webview, origin, command)` per IPC call; deny-by-default. |
| **Isolation Pattern** | AES-GCM-encrypted iframe between WebView and Rust core; mitigates frontend supply-chain XSS. |
| **`__TAURI_INVOKE_KEY__`** | Build-time secret inlined into JS; defends IPC against off-origin frames (post-CVE-2024-35222). |
| **Brownfield Pattern** | Default; replicates browser semantics. Trusted-frontend assumption. |

## Tools & Systems

- **`cargo tauri permission ls`** — enumerates the effective permission registry (after plugin resolution)
- **`cargo tauri permission inspect <id>`** — details on a single permission
- **`jq`** — for parsing `tauri.conf.json` and capability JSON
- **`ripgrep`** — fast searches across capability + Rust source
- **`Splinter`-style approach** — apply the deny-list of high-risk identifiers in CI
- **`schema.tauri.app/config/2`** — JSON schema for `tauri.conf.json`
- **`tauri-utils::config`** docs.rs — authoritative type definitions

## Common Scenarios

### Scenario: Pre-launch capability audit

**Context**: Tauri 2 app shipping to production next week. Codebase grew from a single capability to 12 files; a recent contractor added several more.

**Approach**:
1. Run Steps 1-4 above; produce a numbered finding list
2. For each high-risk grant, request a written justification from the owning developer
3. For accepted grants, ensure inline scope objects + window labels (not `*`)
4. Move ALL dev-only capabilities to a separate file and exclude via `app.security.capabilities` in `tauri.conf.prod.json`
5. Activate isolation pattern if not already on (`pattern.use = "isolation"`)
6. Ship build, then re-run Step 6 against the actual binary's embedded pubkey

**Pitfalls**:
- Forgetting that ALL files in `src-tauri/capabilities/` are auto-registered unless the conf enumerates a subset
- Treating `platforms: ["macOS"]` as a security control (it is not)
- Approving `*:default` references without inline-expanding what they include
- Letting `windows: ["*"]` slide because "we only have one window today"

### Scenario: PR review

**Context**: PR touches `src-tauri/capabilities/main.json` adding a permission.

**Approach**:
1. Diff the capability file before/after
2. Apply Steps 3-4 of the workflow against the new state only
3. Require non-empty description on any new capability or permission entry
4. If new permission is on the high-risk list, require an issue link justifying the grant
5. Block merge if any invariant fails

### Scenario: IPC abuse incident

**Context**: User reports app behaving suspiciously; suspected XSS-to-IPC chain.

**Approach**:
1. Run Step 1 to know the full granted surface at the time of the incident
2. Run Step 7 to find runtime capability additions
3. For each `register_uri_scheme_protocol` handler, audit input handling
4. Cross-reference with `__TAURI_INVOKE_KEY__` log evidence (was the key valid? — confirms in-process call vs forged)
5. Check `Cargo.lock` against advisory feed for plugin versions

## Output Format

```
TAURI 2 CAPABILITY AUDIT REPORT
================================
Project:           <app name>
Tauri version:     2.11.1
Plugins workspace: 2.2.1
Audit date:        2026-05-XX
Auditor:           <handle>

CAPABILITY FILES (12 total)
- src-tauri/capabilities/main.json
- src-tauri/capabilities/settings.json
- ...

PERMISSION REGISTRY (effective)
Total permissions resolved: 47
Core: 18  |  fs: 8  |  shell: 3  |  http: 5  |  custom: 13

HIGH-RISK GRANTS
[CRITICAL] main.json: shell:allow-execute (no scope, no validators)
           Justification: <missing>
[CRITICAL] settings.json: windows=["*"] + fs:allow-write-file
           Justification: <missing>
[HIGH]     main.json: core:webview:allow-internal-toggle-devtools
           Justification: dev-only — should be excluded from production conf

INVARIANT VIOLATIONS
- 3 capabilities have empty description
- 1 capability uses fs:default (= read-all)
- 1 capability has remote.urls with overly broad pattern

CONFIG (tauri.conf.json > app.security)
- csp: <set, contains 'unsafe-inline' on style-src> [WARN]
- freezePrototype: false [FAIL]
- dangerousDisableAssetCspModification: false [PASS]
- pattern.use: brownfield [WARN — consider isolation]
- withGlobalTauri: false [PASS]

UPDATER
- pubkey: matches build secret store [PASS]
- endpoints: HTTPS only [PASS]
- dangerousInsecureTransportProtocol: false [PASS]

RUNTIME CAPABILITY ADDITIONS
- src-tauri/src/dynamic.rs:42 calls add_capability()
  Reviewer: <handle>  Status: needs review

DEPENDENCY PINNING
- tauri 2.11.1 [PASS — CVE-2026-42184 fixed]
- tauri-plugin-shell 2.1.0 [FAIL — < 2.2.1, CVE-2025-31477]
- No typosquats detected

REMEDIATION SUMMARY
- 2 CRITICAL must fix before launch
- 1 HIGH must fix before launch
- 4 MEDIUM should fix this sprint
- 3 LOW suggested

REFERENCES
- docs/tauri-2-security-analysis.md (this repo)
- https://v2.tauri.app/security/capabilities/
- https://github.com/tauri-apps/tauri/security/advisories
```
