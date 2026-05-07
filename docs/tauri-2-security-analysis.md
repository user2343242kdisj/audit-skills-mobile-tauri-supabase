# Tauri 2 Security — Deep Analysis (May 2026)

Audit-grade reference for the Tauri 2 security model, derived from live fetch of `v2.tauri.app/security/`, the `tauri-apps/tauri` and `tauri-apps/plugins-workspace` repos, GHSA / RustSec advisories, and Context7 library `/tauri-apps/tauri-docs` (1027 snippets, source High; alternatives `/websites/v2_tauri_app` 2376 snippets, `/websites/rs_tauri_2_9_5` 6886 snippets).

Versions referenced: Tauri 2.11.1, wry 0.55.1, tao 0.35.0.

---

## 1. Executive verdict

Tauri 2 ships a **mature, opinionated, deny-by-default security model** materially better than Tauri 1's allowlist and competitive with Electron (which has nothing equivalent). The model rests on four primitives — **Permission, Permission Set, Capability, Runtime Authority** — and an **Isolation Pattern** that interposes an AES-GCM-protected iframe between the WebView and the Rust core.

**Strong points**: ACL is granular (per-command × per-window × per-webview × per-origin × per-platform); plugin permissions have first-class scope objects; the IPC envelope is hardened with a build-time `__TAURI_INVOKE_KEY__`; the updater enforces Ed25519 signature verification non-optionally.

**Weak points**: the WebView is **explicitly out of Tauri's threat model** ("the weak link"); origin-resolution code on Windows/Android has been the recurring source of CVEs (CVE-2024-35222, CVE-2026-42184); **no anti-tampering / anti-debug / RASP** primitives — Tauri assumes the OS provides the trust boundary; **the only payload-integrity layer beyond the invoke key is Isolation**, and most apps skip it; signing key compromise is catastrophic with no recovery (no transparency log, no key rotation primitive, no version-binding on signatures).

**For the user's audit** (mobile + Tauri-desktop + Supabase): the Tauri layer concentrates risk in (a) **capability over-grant** in `src-tauri/capabilities/*.json`, (b) **`tauri-plugin-shell` open-scheme regressions**, (c) **fs-scope wildcards**, (d) **CSP holes from `dangerousDisableAssetCspModification`**, (e) **updater key handling**.

---

## 2. Architecture — three views

### 2.1 Process model

```
┌─────────────────────────────────────────────────────────────────┐
│ Single OS process                                               │
│                                                                 │
│  ┌──────────────────┐  postMessage(IPC)  ┌──────────────────┐  │
│  │  WebView         │ ──────────────────►│  Rust Core (tao) │  │
│  │  (WebView2 /     │                    │  - RuntimeAuth   │  │
│  │   WKWebView /    │ ◄──────────────────│  - Plugin host   │  │
│  │   WebKitGTK)     │  Response/Event    │  - State mgmt    │  │
│  └──────────────────┘                    └──────────────────┘  │
│         ▲                                                      │
│         │ optional: AES-GCM Isolation iframe in between        │
└─────────────────────────────────────────────────────────────────┘
```

Two key facts:

- **All in one OS process.** WebView and Rust share PID, address space, file descriptors. Memory-corruption RCE in WebView ≡ RCE in Rust core. Process isolation is at the OS-process boundary, not within Tauri.
- **No bundled WebView.** Tauri delegates to the host OS's WebView via `wry` + `tao`. Renderer security depends on whatever WebKitGTK / WebView2 / WKWebView the OS provides.

### 2.2 ACL — four layers

| Layer | Lives in | Role |
|---|---|---|
| **Permission** | `permissions/*.toml` (plugin or app) | Whitelists/blacklists a *set of commands* and optionally carries a *scope* (allow/deny `Value` arrays). Smallest atom. |
| **Permission Set** | Same TOML files (`[[set]]`) | Bundles permissions under a new identifier for reuse (e.g. `fs:default`). |
| **Capability** | `src-tauri/capabilities/*.{json,json5,toml}` | Binds permissions to specific *window labels*, *webview labels*, *platforms*, and *origin context* (local vs remote). |
| **Runtime Authority** | `crates/tauri/src/ipc/authority.rs` | Singleton in core; resolves `(window, webview, origin, command)` per invoke; deny-by-default. |

### 2.3 Full IPC chain — 8 steps

```
[1] JS:  invoke('plugin:fs|read_text_file', { path: '...' })
[2] @tauri-apps/api/core: serializes to IPC, attaches __TAURI_INVOKE_KEY__
[3] WebView → native bridge (custom URI scheme OR postMessage fallback)
[4] IPC handler verifies invoke key (post-CVE-2024-35222 mitigation)
[5] (optional) Isolation iframe AES-GCM hook can rewrite payload
[6] RuntimeAuthority::resolve_access(command, window_label, webview_label, origin):
       a) check denied_commands  → if match: deny
       b) check allowed_commands → filter by capability rules
       c) inject Scopes into the request
[7] Rust command handler executes (#[tauri::command]); MUST honor the injected scope
[8] Result serialized back to JS via callback table
```

**Key insight:** deny check runs *before* allow check — deny always supersedes allow. Window/webview matching uses Rust `glob::Pattern` on **labels, not titles**. Multiple matching capabilities **merge additively** (union of allows, union of denies — a frequent over-grant footgun).

---

## 3. Capability files — schema and audit pitfalls

Capability files live in `src-tauri/capabilities/*.{json,json5,toml}`. **All files in that directory are auto-registered** unless `app.security.capabilities` in `tauri.conf.json` enumerates an explicit subset.

### 3.1 Verbatim Rust struct (`crates/tauri-utils/src/acl/capability.rs`)

```rust
pub struct Capability {
  pub identifier: String,
  #[serde(default)]
  pub description: String,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub remote: Option<CapabilityRemote>,
  #[serde(default = "default_capability_local")]
  pub local: bool,                         // defaults true
  #[serde(default)]
  pub windows: Vec<String>,
  #[serde(default)]
  pub webviews: Vec<String>,
  pub permissions: Vec<PermissionEntry>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub platforms: Option<Vec<Target>>,
}

pub struct CapabilityRemote { pub urls: Vec<String> }   // URLPattern strings

pub enum PermissionEntry {
  PermissionRef(Identifier),
  ExtendedPermission { identifier: Identifier, scope: Scopes },
}
```

### 3.2 Field reference

| Field | Type | Default | Audit pitfall |
|---|---|---|---|
| `identifier` | string | — required | Duplicates may silently merge in some configurations. Grep for duplicates. |
| `description` | string | `""` | Empty description hides intent. Require non-empty during audit. |
| `windows` | string[] glob | `[]` | `windows: ["*"]` + `shell:allow-execute` is a **critical finding**. |
| `webviews` | string[] glob | `[]` | Forgotten `webviews: ["*"]` makes per-webview scoping meaningless. |
| `permissions` | string\|object[] | — required | Object form lets you tighten scope inline. |
| `local` | bool | `true` | Set to `false` only when capability is purely for remote URLs. |
| `remote` | `{ urls: string[] }` | `null` | A wildcard `https://*` here allows the entire web. |
| `platforms` | string[] | `null` (= all) | **Not a security boundary** — only build/runtime filter. |

### 3.3 Real example (verbatim)

```json
{
  "$schema": "../gen/schemas/desktop-schema.json",
  "identifier": "main-capability",
  "description": "Capability for the main window",
  "windows": ["main"],
  "permissions": [
    "core:path:default",
    "core:event:default",
    "core:window:default",
    "core:app:default",
    "core:resources:default",
    "core:menu:default",
    "core:tray:default",
    "core:window:allow-set-title"
  ]
}
```

### 3.4 Capability audit pitfalls

1. **`windows: ["*"]` + sensitive permission** — biggest red flag. Any future window inherits the grant.
2. **Inline extended permissions vs separate scope file** — both are valid, but `*:default` references hide broad allow rules; auditors must inline-expand.
3. **Missing `webviews` field** — version-dependent semantics; pin Tauri version and verify.
4. **`remote.urls` overly broad** — `https://*` is the entire web; even `https://*.supabase.co` covers all Supabase tenants. Pin to `https://<projectref>.supabase.co`.
5. **Mixed `local + remote`** — same permissions whether bundled or remote; almost always wrong.
6. **`platforms` used as security control** — it's documentation, not enforcement.
7. **User-controlled labels** — if window labels derive from URL params, attacker may create labels matching `admin-*`.

---

## 4. Permissions — schema, identifier rules, resolution

Permission files in:
- Plugin crates: `<plugin>/permissions/*.toml` + `permissions/default.toml`
- App-level custom: `src-tauri/permissions/*.toml`

### 4.1 Verbatim struct

```rust
pub struct Permission {
  pub version: Option<NonZeroU64>,
  pub identifier: String,
  pub description: Option<String>,
  #[serde(default)] pub commands: Commands,    // { allow: Vec<String>, deny: Vec<String> }
  #[serde(default)] pub scope: Scopes,         // { allow: Option<Vec<Value>>, deny: Option<Vec<Value>> }
  pub platforms: Option<Vec<Target>>,
}

pub struct PermissionSet {
  pub identifier: String,
  pub description: String,
  pub permissions: Vec<String>,
}
```

### 4.2 Identifier rules (`crates/tauri-utils/src/acl/identifier.rs`)

- Total max: **115 bytes** (`base` ≤ 64, `prefix` ≤ 50 because `tauri-plugin-` is reserved).
- Plugin prefix `tauri-plugin-` is auto-stripped at compile time → reference as `fs:`.
- Core plugins use reserved `core:` prefix.
- Lowercase ASCII alphanumeric + hyphens only; single `:` separator.
- Errors: `StartsWithTauriPlugin`, `Humongous`, `MultipleSeparators`, `TrailingHyphen`, `PrefixWithoutBase`.

### 4.3 `allow-` vs `deny-` resolution

For every command in `build.rs`'s `COMMANDS` array, Tauri auto-generates two permissions in `permissions/autogenerated/commands/`: `allow-<cmd>` and `deny-<cmd>`. Resolution at `RuntimeAuthority::resolve_access`:

1. Look up command in `denied_commands`. If `(window, webview, origin)` triple matches any deny entry → reject.
2. Iterate `allowed_commands` for matching entries.
3. Multiple matching allow entries → **scope union** (`allow` is union, `deny` also union and wins inside command).

### 4.4 `default.toml` and the `*:default` trap

```toml
"$schema" = "schemas/schema.json"
[default]
description = "Default permissions for the plugin"
permissions = ["allow-ping", "allow-write-custom-file"]
```

Referencing `fs:default` from a capability inherits whatever this set lists. **Every audit must inline-expand `*:default`** — `fs:default` famously includes `read-all`, `scope-app-recursive`, `deny-default`. Never approve a capability that uses `*:default` without manually expanding.

### 4.5 Custom permission

```toml
[[permission]]
identifier = "read-files"
description = "Enables file read commands."
commands.allow = ["read_file", "read", "open", "read_text_file"]

[[scope.allow]]
path = "$HOME/*"

[[scope.deny]]
path = "$HOME/.ssh/**"

[[set]]
identifier = "allow-home-read-extended"
description = "Recursive read in $HOME plus mkdir."
permissions = ["fs:read-files", "fs:scope-home", "fs:allow-mkdir"]
```

---

## 5. Scopes — schema, substitutions, locking down

```rust
pub struct Scopes {
  pub allow: Option<Vec<Value>>,
  pub deny:  Option<Vec<Value>>,
}
```

> "The scope type needs be of any serde serializable type. These types are plugin-specific in general."

> **Critical:** "Command developers need to ensure that there are no scope bypasses possible. The scope validation implementation should be audited to ensure correctness."

### 5.1 Path variable substitutions (fs / asset)

`$APPCONFIG`, `$APPDATA`, `$APPLOCALDATA`, `$APPCACHE`, `$APPLOG`, `$HOME`, `$TEMP`, `$DESKTOP`, `$DOCUMENT`, `$DOWNLOAD`, `$AUDIO`, `$PICTURE`, `$VIDEO`, `$RESOURCE`, `$EXE`, `$FONT`, `$LOG`, `$PUBLIC`, `$RUNTIME`, `$TEMPLATE`, `$CACHE`, `$CONFIG`, `$DATA`, `$LOCALDATA`.

### 5.2 Scoping `fs:read-text-file` to `$APPCONFIG/*.json`

**Inline (within capability):**
```json
{
  "identifier": "config-reader",
  "windows": ["main"],
  "permissions": [
    {
      "identifier": "fs:allow-read-text-file",
      "allow": [{ "path": "$APPCONFIG/*.json" }],
      "deny":  [{ "path": "$APPCONFIG/secrets.json" }]
    }
  ]
}
```

**Standalone permission file** (`src-tauri/permissions/scope-config-json.toml`):
```toml
[[permission]]
identifier = "scope-config-json"

[[permission.scope.allow]]
path = "$APPCONFIG/*.json"

[[permission.scope.deny]]
path = "$APPCONFIG/secrets.json"
```

Referenced from capability: `"permissions": ["fs:allow-read-text-file", "fs:scope-config-json"]`.

### 5.3 Scope traps

- **`require_literal_leading_dot=false`** (Windows default) means `**` matches dotfiles → symlink path `$APPDATA/uploads/.ssh/id_rsa` resolves dangerously. **Set true cross-platform.**
- **Wildcard scope `["**"]`** = "any file the OS lets binary read." Critical finding.
- **Symlink resolution gaps** were the root of CVE-2022-39215 (`readDir` traversed symlinks beyond scope).
- **Glob characters in user-selected paths** — CVE-2022-41874 had `*`, `**`, `[a-z]` bypass scope match.

---

## 6. High-risk permission identifiers — explicit audit list

| Identifier | Why dangerous |
|---|---|
| `core:webview:allow-create-webview` / `allow-create-webview-window` | FE can spawn webview pointing anywhere, then jailbreak via privileged origin. |
| `core:webview:allow-internal-toggle-devtools` | DevTools in production = full IPC for any XSS. |
| `core:window:allow-set-content-protected` | Disables screen-capture defenses. |
| `core:event:allow-emit` (broad) | FE can forge events as if from core. |
| `core:resources:allow-close` | Trivial DoS on resource handles. |
| `fs:default` | Includes `read-all` + `scope-app-recursive`. Almost always too broad. |
| `fs:allow-write-text-file` without scope | Arbitrary write within scope; with `$HOME/**` scope = full user-data compromise. |
| `fs:allow-rename`, `fs:allow-remove` | Destructive; ransomware-grade with broad scope. |
| `shell:allow-execute` without scope validators | **Highest risk — arbitrary RCE.** |
| `shell:allow-spawn` | Same risk class. |
| `shell:allow-open` (pre-2.2.1) | CVE-2025-31477 — RCE via `file://`/`smb://`/`nfs://` on Windows. |
| `http:default` with permissive URL scope | SSRF — bypasses browser CORS via Rust HTTP client. |
| `dialog:allow-open` | Selected paths get auto-added to fs scope — composes dangerously. |
| `updater:default` (custom endpoint) | Endpoint or pubkey misconfiguration → supply-chain compromise. |
| `notification:allow-notify` | Phishing/social-engineering UI. |
| `clipboard-manager:allow-write-text` | Clipboard hijack (e.g., crypto address swap). |
| `global-shortcut:allow-register` | System-wide hotkey capture → keylogger primitive. |
| `process:allow-exit`, `process:allow-restart` | Local DoS, can mask attacks via forced restart. |

**Audit invariant:** any capability containing `shell:`, `fs:allow-write-*`, `core:webview:allow-create-*`, or `http:` permissions without inline scope objects requires deeper review.

---

## 7. CSP — injection mechanics and traps

### 7.1 Schema (`app.security`)

```json
{
  "app": {
    "withGlobalTauri": false,
    "security": {
      "csp": null,
      "devCsp": null,
      "freezePrototype": false,
      "dangerousDisableAssetCspModification": false,
      "assetProtocol": { "enable": false, "scope": [] },
      "pattern": { "use": "brownfield" },
      "capabilities": [],
      "headers": null
    }
  }
}
```

`csp` accepts the `Csp` enum:
- `Policy(String)` — full raw policy
- `DirectiveMap(HashMap<String, CspDirectiveSources>)` — directive → string|array (recommended)

### 7.2 Object form example (verbatim)

```json
"csp": {
  "default-src": "'self' customprotocol: asset:",
  "connect-src": "ipc: http://ipc.localhost",
  "font-src": ["https://fonts.gstatic.com"],
  "img-src": "'self' asset: http://asset.localhost blob: data:",
  "style-src": "'unsafe-inline' 'self' https://fonts.googleapis.com"
}
```

### 7.3 What Tauri auto-injects

- `connect-src` += `ipc:` and `http://ipc.localhost` (Windows/Android) or `ipc://localhost` (macOS/iOS/Linux).
- `img-src` += `asset: http://asset.localhost` if `assetProtocol.enable=true`.
- `script-src` += SHA-256 hashes for inline `<script>` blocks (`csp_hashes`) + nonce for Tauri bootstrap.
- `style-src` += hashes for inline initialization style.
- **Wasm needs you to add `'wasm-unsafe-eval'` manually** — Tauri does not inject.

### 7.4 Verifying emitted CSP

CSP is delivered as **`Content-Security-Policy` HTTP header** on the custom-protocol response (not `<meta>`). Audit via:
- DevTools → Network → first response headers
- WebKit Web Inspector (Linux/macOS)
- `fetch(window.location.href).then(r => r.headers.get('content-security-policy'))`
- Build-time: `target/.../build/.../csp_hashes.json`

### 7.5 `freezePrototype`

When `true`, Tauri injects pre-runtime `Object.freeze` over `Object.prototype`, `Array.prototype`, `Function.prototype`. Blocks prototype-pollution gadgets. Default `false`. Trade-off: breaks libraries that mutate prototypes (older lodash, polyfills).

### 7.6 `dangerousDisableAssetCspModification` — protections lost

Boolean OR `Vec<String>` (specific directives only). Stops Tauri injecting hashes/nonces.

**Lost when enabled:**
- Inline `<script>` / `<style>` no longer covered by hashes → if dev falls back to `'unsafe-inline'`, **any XSS = script execution**.
- Tampered HTML at install time not caught by hash mismatch.
- Combined with `'unsafe-eval'`, prototype-pollution gadgets become weaponizable.

**Audit rule:** any project using this should have `freezePrototype: true`, isolation pattern enabled, **no** `'unsafe-eval'`, **no** `'unsafe-inline'`. If they do less, treat as effectively running without CSP for the affected directive.

### 7.7 `dangerousUseHttpScheme` (per-window attribute, not under `security.*`)

Serves frontend over `http://tauri.localhost` (Windows). Allows mixed-content from plain HTTP backends.

**Why discouraged:**
- WebView2 treats origin as **non-secure**. Service Worker, `crypto.subtle` (some configs), Clipboard API, geolocation, camera/mic, persistent storage, SharedArrayBuffer with COOP/COEP — all unavailable.
- MITM on local network can inject scripts.
- Cookies, localStorage, IndexedDB are scheme-namespaced — toggling orphans data (issue #11252).

---

## 8. Asset Protocol

### 8.1 Schema

```json
"assetProtocol": {
  "enable": true,
  "scope": {
    "allow": ["$APPDATA/db/**", "$RESOURCE/assets/*"],
    "deny": ["$APPDATA/db/users/*.sqlite"],
    "requireLiteralLeadingDot": true
  }
}
```

`scope` is `FsScope` enum:
- `AllowedPaths(Vec<PathBuf>)` — short form, allow only
- `Scope { allow, deny, require_literal_leading_dot }` — full form. **Deny precedence over allow.**

`require_literal_leading_dot` defaults: **`true` on Unix, `false` on Windows.**

### 8.2 `convertFileSrc` risk

Wraps a filesystem path into `asset://localhost/...` URL the WebView can load via `<img>`/`<video>`/`fetch()`. **Performs no client-side scope check** — enforcement runs in the Rust handler. Overly broad scope = arbitrary file exfiltration via `fetch('asset://localhost/<sensitive-path>').then(r => r.text())`.

### 8.3 Locking down

1. Default is `enable: false` — keep unless needed.
2. Use object form with explicit `allow` + `deny`.
3. Anchor to writable user-content roots (`$APPCACHE`, `$APPLOCALDATA`); **never** `$HOME`, `$DOCUMENT`, `$RESOURCE` unless required.
4. Set `requireLiteralLeadingDot: true` cross-platform.
5. Add explicit denies for credential paths (SSH, AWS, browser data).

---

## 9. WebView landscape per platform

| Platform | WebView | Engine | CSP support | Update cadence |
|---|---|---|---|---|
| Windows 7/8/10/11 | **WebView2** (Edge Chromium) | Blink/V8 | Full Level 3 | Microsoft Evergreen runtime |
| macOS 10.10+ | **WKWebView** | WebKit/JSC | L2 + most L3 | OS updates (e.g., WebKit 616.x on Sonoma) |
| iOS | **WKWebView** | WebKit/JSC | Same as macOS | OS updates |
| Linux | **WebKitGTK** | WebKit/JSC | L2 + most L3 | **Distro-pinned** (Ubuntu 22.04 = 2.36, Ubuntu 20.04 = 2.28) |
| Android | **System WebView** | Blink/V8 | Full Level 3 | Play Store updates |

**CSP enforcement parity is NOT guaranteed across platforms.** WebKitGTK on older LTS lags Chromium 2-3 years on directives like `trusted-types`, `require-trusted-types-for`, `'wasm-unsafe-eval'` parsing. **Linux is the weakest CSP target.**

WebView2 maps custom URI schemes to `http://<scheme>.localhost` (also Android); macOS/iOS/Linux use real `<scheme>://localhost`. Root cause of CVE-2026-42184.

---

## 10. Isolation Pattern — architecture and limits

### 10.1 Configuration

```json
{ "app": { "security": { "pattern": {
  "use": "isolation",
  "options": { "dir": "../dist-isolation" }
} } } }
```

`dir` contains an HTML defining `window.__TAURI_ISOLATION_HOOK__`.

### 10.2 Architecture

```
Main webview window
   │  invoke("cmd", args)
   ▼
__TAURI_INTERNALS__.postMessage  ──────────────►  Sandboxed iframe (Isolation app)
                                                       │  __TAURI_ISOLATION_HOOK__(payload)
                                                       │  AES-GCM encrypt with per-launch key
                                                       ▼
                                                  Encrypted blob
   ◄─────────────────────  postMessage  ──────────────┘
   │  forwards encrypted blob to Rust core
   ▼
Tauri Core (Rust) — decrypts, validates capability, dispatches
```

Encryption: `SubtleCrypto` AES-GCM, key generated per-launch, shared between iframe and Rust via bootstrap channel. **Main webview only sees ciphertext** — even fully-compromised main webview cannot forge IPC because it lacks the key.

### 10.3 Hook example

```javascript
window.__TAURI_ISOLATION_HOOK__ = (payload) => {
  if (payload.cmd === 'fs|read_text_file' && /\.\./.test(payload.path)) {
    throw new Error('rejected: path traversal');
  }
  if (payload.cmd === 'fs|read-text-file' && !payload.path.startsWith('/var/myapp/')) {
    throw new Error('blocked');
  }
  return payload;
};
```

### 10.4 Protects against
Frontend supply-chain compromise, accidental XSS in main webview, malicious code via CDN or stale lockfile. Such code can run JS but its IPC calls go through the hook.

### 10.5 Limits

- **Windows**: iframe sandbox doesn't load external `<script src>`; isolation app must be inlined. **ES module imports break on Windows** in this mode.
- Hook itself runs in same V8/JSC context as iframe — compromise of isolation app source = protection gone.
- Hook does **not** see capability metadata; only sees command name + args. Capability auth still happens in Rust.
- AES-GCM adds sub-millisecond per-message overhead; matters for high-throughput streams.
- Cold-start cost: key gen needs entropy (`/dev/urandom`); headless CI may stall without `haveged`.
- **Does NOT protect against:** malicious Rust code, overly permissive capability scopes, WebView 0-days themselves.

**Tauri team's official position: always use isolation unless you cannot.**

---

## 11. IPC — protocol details

### 11.1 Two transports

JS bootstrap (`crates/tauri/scripts/ipc-protocol.js`) exposes `window.__TAURI_INTERNALS__.postMessage`. Tries:
1. **Custom protocol** (`ipc://localhost` or `http://ipc.localhost`) — HTTP POST.
2. **Fallback `window.ipc.postMessage`** — string transport via wry's `with_ipc_handler`. Used on Android (`canUseCustomProtocol = osName !== 'android'`) and when CSP blocks scheme.

### 11.2 Custom protocol envelope

HTTP POST headers:
```
Tauri-Callback: <CallbackFn>      // numeric ID → JS callback table
Tauri-Error:    <CallbackFn>      // numeric ID → JS error callback
Tauri-Invoke-Key: <secret>        // build-time generated, anti-XSS-from-stale-frames
Content-Type: application/json | application/octet-stream
```

Body: command JSON args, or raw bytes. Response: HTTP with `Tauri-Response: ok|error`.

### 11.3 postMessage fallback envelope

```rust
#[derive(Deserialize)]
struct Message {
  cmd: String,
  callback: CallbackFn,
  error: CallbackFn,
  payload: serde_json::Value,
  options: Option<RequestOptions>,
  #[serde(rename = "__TAURI_INVOKE_KEY__")]
  invoke_key: String,
}
```

### 11.4 `__TAURI_INVOKE_KEY__`

- Generated at build time, inlined into `ipc-protocol.js`.
- Declared **outside** `__TAURI_INVOKE__` closure so `toString()` cannot leak it.
- Validated server-side per invoke.
- **Defends against:** off-origin frames, stale init scripts, iframe IPC inheritance (CVE-2024-35222).
- **Does NOT defend against:** XSS in legitimate frame (key is reachable from any JS in the WebView).
- **Not a per-message MAC** — no nonce, no replay protection. The IPC is in-process; per-message integrity is unnecessary unless an attacker has code execution in the same process, in which case integrity is moot.

### 11.5 Callback table

JS holds `Map<number, (data: unknown) => void>` indexed by `transformCallback()`. Rust delivers via:
- HTTP response on custom protocol → `runCallback(callbackId, data)`
- `webview.eval()` of a JS string from `format_callback` (fallback / small payloads)

`MAX_JSON_DIRECT_EXECUTE_THRESHOLD = 8192`, `MAX_RAW_DIRECT_EXECUTE_THRESHOLD = 1024` — switches between eval and channel-fetch round-trip.

---

## 12. `#[tauri::command]` — macro deep dive

### 12.1 Attributes

| Attribute | Behaviour |
|---|---|
| `async` | Runs on Tokio task (required for `async fn`) |
| `rename` | Override JS-facing name |
| `rename_all` | `"snake_case"`, `"camelCase"` (default), etc. |
| `root` | Override macro path (rare) |

### 12.2 Argument injection (`CommandArg` trait)

| Type | Source |
|---|---|
| `tauri::AppHandle<R>` | from `Invoke.message` |
| `tauri::Window<R>` / `tauri::WebviewWindow<R>` / `tauri::Webview<R>` | from `Invoke.message` |
| `tauri::State<'_, T>` | from app-managed state |
| `tauri::ipc::Request<'_>` | raw access (body + headers) |
| `tauri::ipc::Channel<T>` | server-push stream |
| `tauri::ipc::CommandScope<T>` | scope from matched permission |
| `tauri::ipc::GlobalScope<T>` | merged scope from all matching permissions |
| `T: serde::Deserialize` | regular JSON-payload arg |

### 12.3 Return types

- `T: Serialize` → JSON
- `Result<T, E>` where `E: Serialize` → error path (`Tauri-Response: error`)
- `tauri::ipc::Response::new(Vec<u8>)` → raw octet-stream (zero-copy fast path)

### 12.4 Filter step at compile time

`filter_unused_commands` (in `tauri-macros/src/command/handler.rs`) reads ACL at compile time and **strips commands not present in any permission** from the binary. A command "registered" in code but absent from any TOML → not in binary at all.

### 12.5 End-to-end registration chain

A function is callable iff **all four** are true:
1. **Registered**: `tauri::Builder::default().invoke_handler(generate_handler![my_cmd])`
2. **Permission**: TOML in `permissions/` declares `commands.allow = ["my_cmd"]`
3. **Capability**: JSON in `capabilities/` references the permission, lists window labels
4. **Runtime authority**: at invoke, `(origin, window-label, command)` resolves through allowed_commands and scope is injected

Multiple capabilities → permissions **merge additively** (union of allows).

### 12.6 Audit checklist for commands

1. Every path arg canonicalised + verified against allowlist *inside the Rust command*. Don't trust capability scope alone unless plugin supplies `CommandScope`.
2. `String`/`Vec<u8>` length-bound. Serde does not bound by default; 4 GB JSON string OOMs the process.
3. Async commands: no awkward `unsafe { transmute }` workarounds for borrows.
4. Errors `Serialize`-able and **don't leak filesystem paths or stack traces**.
5. Function names unique per plugin; namespace collisions silently shadow.
6. `pub` forbidden in `lib.rs` (macro glue).
7. If returning `Channel`, decide drop semantics.

---

## 13. Argument deserialization — failure modes

- **Tag confusion** on `#[serde(tag = "type")]` and `#[serde(untagged)]` — attacker picks variant.
- **`#[serde(flatten)]` with `serde_json::Value`** — accepts anything, unbounded depth/size.
- **Numeric coercion**: `usize` deserializes from any non-negative JSON number; `9007199254740993` quietly becomes valid `u64`.
- **`Option<T>`** treats missing/null/absent identically — confuses "not provided" with "null".
- **Untrusted boundary**: every value reaching the command is attacker-controlled when WebView has any XSS, embedded iframe, or brownfield 3rd-party scripts.

For raw bodies: `Request::body()` returns `InvokeBody::Raw(Vec<u8>)` or `InvokeBody::Json(serde_json::Value)` — confirm variant before unwrapping.

---

## 14. Channels — security considerations

```rust
#[tauri::command]
fn download(on_event: Channel<DownloadEvent>) {
  on_event.send(DownloadEvent::Started).unwrap();
}
```

Wire form: serializes to `"__CHANNEL__:<id>"` (constant `IPC_PAYLOAD_PREFIX = "__CHANNEL__:"`). Plugin `__TAURI_CHANNEL__|fetch` retrieves queued payloads JS-side. Sends counted atomically (`AtomicUsize`) for in-order delivery.

**Risks:**
- **Lifetime**: `Channel` is `Clone`; storing in `State<Mutex<Vec<Channel<_>>>>` keeps alive past command return. `ChannelInner::Drop` fires only when last clone drops — leaks easy.
- **Cross-window leakage**: a malicious renderer can mint any numeric ID; do **not** treat `JavaScriptChannelId` as authentication.
- **Race**: `Channel::send` returns immediately; isolation encrypts before delivery, so `send` followed by `app.exit()` may drop in-flight payloads.
- **No explicit `close()`** — JS stops receiving when `Channel` instance is GC'd or webview navigates.
- **Channels not subject to capabilities** — once accepted as command arg, every send goes through.

---

## 15. Events — threat model

```rust
app.emit("event-name", &payload)?;
app.emit_to("webview-label", "name", payload)?;
app.emit_filter("event-name", payload, |target| /* predicate */)?;
```

`EventTarget`: `Any`, `App`, `Window { label }`, `Webview { label }`, `WebviewWindow { label }`, `AnyLabel { label }`.

**Threat: an attacker with renderer JS can emit anything.** FE `emit` API publishes to all webviews by default; **no permission required**. XSS in window A can `emit` to window B, listeners cannot tell source.

**Mitigations:**
- Never trust event payload contents (re-validate, like unauthenticated network packet).
- Prefer `emit_to` over `emit` from Rust to limit fan-out.
- On listener side, gate sensitive actions behind capability-protected commands, not raw event handling.

---

## 16. Custom URI scheme handlers

```rust
tauri::Builder::default()
  .register_uri_scheme_protocol("myproto", |ctx, request| {
    // request: http::Request<Vec<u8>>
    // return  : http::Response<Cow<'static, [u8]>>
  })
```

Handler runs in Rust core, **not subject to capabilities**. URL host/path is attacker-controlled.

**Unsafe (path traversal):**
```rust
let path = request.uri().path().trim_start_matches('/');
let bytes = std::fs::read(format!("/var/lib/myapp/{path}")).unwrap();
// JS: fetch("myproto://x/../../etc/passwd") → reads /etc/passwd
```

**Safer:**
```rust
let path = std::path::Path::new(request.uri().path().trim_start_matches('/'));
if path.components().any(|c| matches!(c, std::path::Component::ParentDir)) { return forbidden(); }
let full = base_dir.join(path).canonicalize()?;
if !full.starts_with(&base_dir) { return forbidden(); }
```

**Other footguns:**
- Reflecting URL into HTML responses → XSS in custom-scheme window.
- Forwarding URL into `reqwest::get` → SSRF.
- Serving binary files without `Content-Type` → WebView sniffs and executes as HTML/JS.

---

## 17. Brownfield vs Isolation pattern

### Brownfield (default)

Replicates browser environment so existing webapps work. Implications:

- **CORS subversion**: Tauri sets `Access-Control-Allow-Origin: *` on IPC responses. 3rd-party iframe sharing JS context can fire commands. Use strict CSP `frame-src 'none'`.
- **Cookie & storage leaks**: WebView shares storage with anything you load. Brownfield app loading remote `<script>` exposes app cookies/localStorage to that origin.
- **Threat model**: brownfield assumes frontend is **trusted**. Any 3rd-party JS = native code in trust terms.
- **No isolation hook** — every postMessage goes straight to Rust.

### When to switch to Isolation

- App ships supply-chain-fragile npm deps.
- App accepts user-content / 3rd-party plugins / MFE hosting.
- Defense-in-depth posture against frontend XSS.

---

## 18. Common command vulnerabilities — code examples

### a. Path traversal
```rust
#[tauri::command]
fn read_doc(name: String) -> Result<String, String> {
  std::fs::read_to_string(format!("./docs/{}", name)).map_err(|e| e.to_string())
}
// JS: invoke("read_doc", { name: "../../../etc/passwd" })
```
**Mitigate:** reject `..` components, `canonicalize`, `starts_with` allowed base. Or use `tauri-plugin-fs` with tight scope.

### b. Command injection (shell)
```json
{ "name":"git", "cmd":"git", "args":[true] }   // BAD: any args
```
With `args: true`, attacker can pass `--git-dir=/`. Always validate:
```json
"args": ["log", { "validator": "^[A-Za-z0-9_./-]+$" }]
```
**Avoid `sh -c` sidecars with `validator: ".*"` — literal arbitrary execution.**

### c. SSRF
```rust
#[tauri::command]
async fn proxy(url: String) -> Result<String, ...> {
  Ok(reqwest::get(&url).await?.text().await?)
}
// Attacker: fetch http://169.254.169.254/latest/meta-data/
```
**Mitigate:** `tauri-plugin-http` with explicit URL scope; reject private/link-local IPs **after DNS resolution** (DNS-rebinding bypass).

### d. Unbounded resource consumption
Serde happily deserializes 100 MB JSON string. Combine with recursive structs (`#[serde(flatten)]` + `serde_json::Value`) for stack overflow DoS.
**Mitigate:** `#[serde(bound)]`, length-bounded newtypes, `serde_with::base64::Base64<Strict>` with size limits.

### e. Race conditions
Each invoke spawns Tokio task. `State<Mutex<Counter>>` is fine; `State<RefCell<…>>` panics. TOCTOU on filesystem state — `if path.exists() { create_file(path) }` is racy.

### f. Authorization-decision-in-frontend
```js
if (await invoke('get_user_role') === 'admin') { btn.disabled = false }
// then: invoke('delete_everything')
```
Treating frontend gating as security. **Every command must re-check auth in Rust**, regardless of capability or UI state.

---

## 19. Plugin command surface — highest-risk per plugin

| Plugin | Highest-risk permissions | Why |
|---|---|---|
| `tauri-plugin-shell` | `shell:allow-execute`, `shell:allow-spawn`, `shell:allow-open` (pre-2.2.1) | Direct RCE if validators weak. **Pin ≥ 2.2.1 (CVE-2025-31477)**. Prefer `tauri-plugin-opener` — `shell.open` is deprecated. |
| `tauri-plugin-fs` | `fs:allow-read-file`, `fs:allow-write-file`, `fs:allow-remove`, `fs:scope` with `$HOME/**` | Read/write any file in scope; symlink traversal is dev's responsibility. |
| `tauri-plugin-http` | `http:default` without URL scope | SSRF; cookies attached to attacker-chosen URLs. |
| `tauri-plugin-process` | `process:allow-exit`, `process:allow-restart` | Local DoS; can mask attacks via forced restart. |
| `tauri-plugin-dialog` | `dialog:allow-open`, `dialog:allow-save` | Returns native paths; selected paths auto-added to fs scope at runtime — composes with fs to widen. |
| `tauri-plugin-store` | `store:default` | Plaintext JSON in `$APPDATA`; **never store secrets here**. Use `tauri-plugin-stronghold`. |
| `tauri-plugin-os` | `os:allow-platform/arch/hostname/version` | Information disclosure; useful for targeted exploits. |
| `tauri-plugin-updater` | `updater:default` | Endpoint or pubkey misconfig = full RCE on next launch. |
| `tauri-plugin-opener` | `opener:default` | Same risk class as shell.open; configurable scope, treat as security-sensitive. |

The fs plugin's `default` set wisely **denies** `$APPLOCALDATA/EBWebView/**` (Windows WebView2 cookies + IndexedDB), but does **not** deny `$APPDATA/**/*token*`. Bring your own deny list.

---

## 20. Updater — architecture and attack surface

### 20.1 Flow

```
1. Manifest fetch (HTTP-GET each endpoint until 200 or 204)
2. Version compare (default: semver greater-than; custom version_comparator overrides)
3. Bundle download (streamed; optional proxy/headers/timeout)
4. Signature verify (Ed25519 minisign) — "cannot be disabled"
5. Install (macOS: replace .app; Windows: MSI/NSIS forces app exit; Linux: replace AppImage)
```

### 20.2 Schema (verbatim)

```json
{
  "bundle": { "createUpdaterArtifacts": true },
  "plugins": {
    "updater": {
      "pubkey": "<embedded Ed25519 public key>",
      "endpoints": ["https://example.com/{{target}}/{{arch}}/{{current_version}}"],
      "dangerousInsecureTransportProtocol": false,
      "windows": {
        "installMode": "passive",
        "installerArgs": []
      }
    }
  }
}
```

Defaults: `createUpdaterArtifacts: false`, `dangerousInsecureTransportProtocol: false`, `installMode: "passive"`.

URL placeholders: `{{current_version}}`, `{{target}}` (`linux`/`windows`/`darwin`), `{{arch}}` (`x86_64`/`i686`/`aarch64`/`armv7`).

`installMode`:
- `"passive"` — small progress window, no interaction (default, recommended)
- `"basicUi"` — basic UI, requires user interaction
- `"quiet"` — no feedback; cannot self-elevate, only per-user installs or pre-elevated contexts

### 20.3 Manifest schemas

**Static (CDN):**
```json
{
  "version": "", "notes": "", "pub_date": "",
  "platforms": {
    "linux-x86_64":   { "signature": "", "url": "" },
    "darwin-aarch64": { "signature": "", "url": "" },
    "windows-x86_64": { "signature": "", "url": "" }
  }
}
```

**Dynamic (200 OK):**
```json
{ "version": "", "url": "", "signature": "", "notes": "", "pub_date": "" }
```

### 20.4 Key management

```bash
tauri signer generate -w ~/.tauri/myapp.key
```
Build-time env vars: `TAURI_SIGNING_PRIVATE_KEY` (path or content), `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`.

**`.env` files do NOT work** — must be in build-process environment.

**Private key is the entire trust root.** Loss = permanent inability to ship updates to existing installs.

### 20.5 Attack surface

| Vector | Mitigation in default | Residual risk |
|---|---|---|
| TLS-stripping | HTTPS-only by default | Fully exposed if `dangerousInsecureTransportProtocol: true` ships |
| Pubkey replacement (CI compromise) | Embedded at build, tied to signing key | **No chain of trust** |
| Signature skip | "Cannot be disabled" — no flag | App-level patch required |
| Manifest URL hijack (DNS/CDN) | Signature verifies bundle, not manifest | Attacker can serve any version; signature still gates install |
| **Downgrade attack** | Default semver comparator rejects `<= current` | Permissive `version_comparator` enables rollback to vulnerable version |
| Server impersonation | TLS + signature | **Manifest itself unsigned** — `notes`, `pub_date` mutable |
| Replay of old signed bundle | None at protocol | **Signatures stay valid forever; no expiry, no nonce** |

**Critical:** Tauri's signature scheme has **no expiration, no version-binding, no transparency log**. A legitimate signed bundle for v1.2.0 (with known RCE) remains forever installable. **No equivalent of TUF's role separation, snapshot keys, or threshold signing.**

### 20.6 How an attacker would backdoor

- **Steal private key from CI/CD secrets** (most realistic). Forge valid signed manifests; updater accepts blindly.
- **Replace embedded `pubkey` at build time** (CI compromise). New installs trust attacker keys.
- **Compromise manifest endpoint** if `dangerousInsecureTransportProtocol: true`.
- **Force vulnerable older version** via downgrade.
- **Vite env-leak** — historic CVE-2023-46115 exfiltrated keys via `envPrefix: ['TAURI_']`. Audit `dist/` with `grep -r TAURI_PRIVATE_KEY dist/`.

---

## 21. Code signing — platform specifics

### 21.1 macOS

**Cert types**: `Apple Distribution` (App Store) or `Developer ID Application` (outside, Account Holder only).

**Notarization** (required for Developer ID): `xcrun notarytool` via App Store Connect API key (preferred) or Apple ID + app-specific password.
- `APPLE_API_KEY`, `APPLE_API_KEY_ID`, `APPLE_API_ISSUER` (modern)
- Or: `APPLE_ID`, `APPLE_PASSWORD`, `APPLE_TEAM_ID` (legacy)

Tauri runs `notarytool submit --wait` then `stapler staple`.

**Local signing**: `tauri.conf.json > bundle > macOS > signingIdentity` or `APPLE_SIGNING_IDENTITY` env. Discover with `security find-identity -v -p codesigning`. Apple Silicon ad-hoc: pseudo-identity `"-"`.

**CI**: `.p12` exported as base64 to `APPLE_CERTIFICATE` + `APPLE_CERTIFICATE_PASSWORD`, decoded into temp keychain.

**Entitlements** — Tauri does NOT generate these. Audit checklist:

| Entitlement | Should be |
|---|---|
| `com.apple.security.cs.allow-jit` | Only if host process JITs (System WebKit doesn't need it) |
| `com.apple.security.cs.allow-unsigned-executable-memory` | **false** |
| `com.apple.security.cs.disable-library-validation` | **false** unless loading unsigned plugins |
| `com.apple.security.cs.allow-dyld-environment-variables` | **false** (DYLD env = injection vector) |
| `com.apple.security.app-sandbox` | If true, file/network/IPC entitlements must be enumerated |
| `com.apple.security.network.client` | Minimal |

Hardened Runtime is implicit when notarizing. App Sandbox not required for Developer ID; required for Mac App Store.

### 21.2 Windows

**Cert types**:
- **OV**: cheaper, individuals can obtain; SmartScreen warns until reputation builds.
- **EV**: hardware-token-bound; **immediate SmartScreen reputation**, no warning.

**Signing methods**:
1. **Local cert** (legacy): `bundle > windows > certificateThumbprint` + `digestAlgorithm: "sha256"` + `timestampUrl`.
2. **Azure Key Vault** via `relic` — `AZURE_CLIENT_ID/TENANT_ID/CLIENT_SECRET`.
3. **Azure Trusted Signing** (modern, recommended) via `trusted-signing-cli` — short-lived certs.
4. **Custom `signCommand`** — needed for cross-platform builds (sign Windows from Linux/macOS runner).

**Per-user vs machine-wide**: NSIS defaults to per-user (`installMode: currentUser`); MSI defaults to per-machine. **Per-machine crosses privilege boundary** — UAC required for install + every update; `installMode: "quiet"` documented as broken for per-machine.

For hardened distribution: prefer per-user installs unless machine-wide-resource reason. Per-user avoids Admin write to `Program Files`, reduces DLL-hijacking and update-privilege-escalation surface.

**WebView2 bootstrapper**: `bundle > windows > webviewInstallMode`:
- `"downloadBootstrapper"` (default) — downloads from Microsoft on first run
- `"embedBootstrapper"` — bootstrapper bundled
- `"offlineInstaller"` — full WebView2 runtime bundled
- `"fixedRuntime"` — pinned WebView2 runtime; **you become responsible for patching CVEs**
- `"skip"` — assumes already installed

### 21.3 Linux

Tauri docs cover **AppImage with GPG only**. **Critical warning, verbatim**: *"AppImage does not validate the signature, so you can't rely on it to check whether the file has been tampered with"* — AppImage runtime does not verify signature on launch; users must run `appimagetool --validate` manually.

Env: `SIGN=1`, `SIGN_KEY=<key id>`, `APPIMAGETOOL_SIGN_PASSPHRASE`, `APPIMAGETOOL_FORCE_SIGN=1`.

**.deb / .rpm / Flatpak / Snap**: not covered by Tauri docs. Practical:
- `.deb` — sign `Release` files in apt repo via `gpg --clearsign`; clients trust `/etc/apt/trusted.gpg.d/`.
- `.rpm` — `rpmsign --addsign` with GPG key; users `rpm --import`.
- **Flatpak** — Flathub signs OSTree commit with their GPG; you trust Flathub.
- **Snap** — Canonical-controlled signing; cannot self-distribute trust.

**For LTS hardening posture, AppImage GPG signing is not a real defense** — treat as advisory metadata; rely on updater Ed25519 path for integrity.

---

## 22. Runtime Authority — historical bypass conditions

| CVE | Date | Root cause |
|---|---|---|
| **CVE-2024-35222** | 2024-05 | iframes inherited parent IPC because Tauri injected init scripts into them. Fixed: `__TAURI_INVOKE_KEY__` + don't inject into iframes (except same-origin Windows) |
| **CVE-2026-42184** | 2026-05 | `is_local_url()` only checked first DNS label; `http://app.evil.com/` matched registered `app://` protocol on Windows/Android. Fixed in 2.11.1. Vulnerable code: `current_url.domain().and_then(|d| d.split_once('.')).unwrap_or_default().0` |
| **CVE-2023-31134** | 2023-05 | Open-redirect in app code allowed external sites to load into Tauri window and gain full IPC |

**Pattern: Tauri's authority is robust at the policy layer, but the origin-resolution code on Windows/Android is custom (no spec-compliant URL parsing) and has been the recurring weakness.**

---

## 23. Lifecycle threats — by phase

| Phase | Attacker capability | Tauri's stated trust assumption |
|---|---|---|
| **Upstream tooling** | Compromise crates.io / npm | "Tauri maintains strict authorial control" — third parties may not |
| **Development** | MITM dev server, inject FE code, steal secrets | "Developer machines are reasonably secured"; **dev server has no mutual auth or transport encryption** |
| **Build-time** | Inject backdoor in CI, exfiltrate signing key | *"Rust is by default not fully reliably producing reproducible builds"* |
| **Distribution** | Serve malicious updates if manifest/binary host compromised | "Manifest servers, build servers, binary hosting remain under your control" |
| **Runtime** | RCE in WebView, IPC abuse, capability bypass | *"WebView implementations contain exploitable security gaps"* — explicitly acknowledged |
| **Update** | All §20.5 vectors | Same trust-the-host assumption |
| **Uninstall** | Persistence via leftover files / scheduled tasks | **Not documented** — uninstall is OS-installer-driven; Tauri has no scrub-on-remove primitive |

### Trust assumptions (verbatim)

- *"The security of your Tauri application is the sum of the overall security of Tauri itself, all Rust and npm dependencies, your code, and the devices that run the final application."*
- *"In Tauri's current threat model and boundaries we are not able to add more security constraints to the WebView itself."*
- *"We believe that this part of our stack is the weak link but current generation WebViews are improving in their hardening."*

**Future-work items explicitly listed**: tooling for binary-asset extraction, proxy-interception support (Burp/Zap/Caido), WebView sandboxing research, libAFL fuzzing, multi-platform fuzz harnesses.

---

## 24. Binary hardening

### 24.1 Tauri's recommended `Cargo.toml` profile

```toml
[profile.release]
panic = "abort"
codegen-units = 1
lto = true
opt-level = "s"
strip = true
```

This gets symbol stripping + DCE via LTO. **Tauri does NOT configure further hardening flags.**

### 24.2 Recommended additional `RUSTFLAGS`

| Flag | Purpose | Default | Recommended |
|---|---|---|---|
| PIE | ASLR | Rust default `-C relocation-model=pic` on most targets | Verify with `checksec` |
| Full RELRO | GOT read-only | Not set by default | `-C link-arg=-Wl,-z,relro,-z,now` |
| Stack canaries | Stack overflow detection | `nightly` enables; stable depends on target | `-Z stack-protector=strong` (nightly) |
| NX bit | Non-exec stack | Default | — |
| Windows CFG/CET | Control-flow integrity | Not on by default | `-C link-arg=/CETCOMPAT` |

---

## 25. Anti-tampering / RASP — Tauri offers NONE

**Out-of-box, Tauri does NOT provide:**
- No startup integrity check (no self-CRC, no signature self-verification at launch)
- No debugger detection
- No anti-Frida / anti-instrumentation
- No code obfuscation
- No emulator / VM detection
- No certificate pinning helper for app HTTPS calls
- No root / jailbreak detection (relevant for iOS/Android Tauri targets)

**This is deliberate desktop posture** — Tauri assumes the OS provides the trust boundary (Hardened Runtime + notarization on macOS, Authenticode + SmartScreen on Windows, AppArmor/SELinux on Linux). Equivalent to a stock Electron app; far behind mobile RASP (Promon, Guardsquare, Zimperium).

If the threat model includes malicious local user (DRM, anti-cheat, financial), you must **layer a third-party RASP product on top** — Tauri itself does not address it.

What you can implement on top:
- Verify app code-signature programmatically at startup (call `codesign -v` / Authenticode API yourself).
- Pin updater pubkey in TPM / Secure Enclave; compare at runtime.
- Use `tauri-plugin-stronghold` to encrypt local secrets at rest.

---

## 26. Comprehensive advisory history

### Tauri core (`tauri-apps/tauri`)

| GHSA | CVE | Date | Severity | Affected | Fixed | Summary |
|---|---|---|---|---|---|---|
| GHSA-7gmj-67g7-phm9 | CVE-2026-42184 | 2026-05-06 | Medium (CVSS 6.1) | 2.0.0–2.11.0 | 2.11.1 | **Origin Confusion**: `is_local_url()` mis-classifies subdomains as local on Windows/Android |
| GHSA-57fm-592m-34r7 | CVE-2024-35222 | 2024-05-23 | Medium | ≤1.6.6; 2.0.0-beta.0–2.0.0-beta.19 | 1.6.7; 2.0.0-beta.20 | iframes bypass origin checks; introduced `__TAURI_INVOKE_KEY__` |
| GHSA-2rcp-jvr4-r259 | CVE-2023-46115 | 2023-10-19 | Low (downgraded from High) | tauri-cli 1.0.0–1.5.5; 2.0.0-alpha.0–alpha.15 | 1.5.6; 2.0.0-alpha.16 | **Updater private keys leaked** into Vite bundles via `envPrefix: ['TAURI_']` |
| GHSA-wmff-grcw-jcfm | CVE-2023-34460 | 2023-06-21 | Medium (4.8) | 1.4.0 | 1.4.1 | Regression: dotfile glob check on Linux/macOS fs scope |
| GHSA-4wm2-cwcf-wwvp | CVE-2023-31134 | 2023-05-03 | Medium (4.8) | <1.3, 1.0–1.0.8, 1.1–1.1.3, 1.2–1.2.4 | 1.0.9, 1.1.4, 1.2.5, 1.3 | Open redirect exposes IPC to external sites |
| GHSA-6mv3-wm7j-h4w5 | CVE-2022-46171 | 2022-12-22 | Medium (6.8) | 1.0–1.0.7, 1.1–1.1.2, 1.2–1.2.2, 2.0.0-alpha.0–alpha.1 | 1.0.8, 1.1.3, 1.2.3, 2.0.0-alpha.2 | fs glob too permissive; `*` matched dotfiles |
| GHSA-q9wv-22m9-vhqh | CVE-2022-41874 | 2022-11-08 | Low | 1.0–1.0.6, 1.1–1.1.1 | 1.0.7, 1.1.2 | fs scope partial bypass via dialog/drag-drop with special chars |
| GHSA-28m8-9j7v-x499 | CVE-2022-39215 | 2022-09-15 | Low | <1.0.6 | 1.0.6, 1.1.0 | `readDir` scope bypass via symbolic links |

### Plugins (`tauri-apps/plugins-workspace`)

| GHSA | CVE | Date | Severity | Affected | Fixed | Summary |
|---|---|---|---|---|---|---|
| GHSA-c9pr-q8gx-3mgp | CVE-2025-31477 | 2025-04-02 | High (some sources Critical 9.3) | tauri-plugin-shell ≤2.2.0 | 2.2.1 | `open` endpoint scope failed to block `file://`, `smb://`, `nfs://` — RCE via `file:///c:/windows/system32/calc.exe` |

### RustSec — **not official Tauri** (typosquats)

| RustSec | Crate | Note |
|---|---|---|
| RUSTSEC-2023-0108 | `tauri-win-rt-notification` | Removed from crates.io for malicious code |
| RUSTSEC-2023-0117 | `tauri-winrt-notifications` | Removed from crates.io for malicious code |

Legitimate crate is `tauri-plugin-notification`. **Verify `Cargo.lock` does not pull either.**

---

## 27. Mapping to MASVS controls

The user's audit uses MASVS as the spine for the mobile portion (see `docs/owasp-mas-analysis.md`). Tauri-equivalent mappings:

| MASVS Control | Tauri implementation surface | Audit focus |
|---|---|---|
| **STORAGE-1/2** | `tauri::api::path::app_data_dir`, `tauri-plugin-store` (plaintext!), `tauri-plugin-stronghold` (encrypted) | Never store secrets in `tauri-plugin-store`; use stronghold; check fs scope doesn't expose `$APPDATA/**` to webview |
| **CRYPTO-1/2** | Rust `ring`/`rustls`/`age`, OS keychain via `keyring` crate, `tauri-plugin-stronghold` | Audit crypto choices in Rust deps; verify `ring` versions; rotate updater key handling |
| **AUTH-1** | `tauri-plugin-oauth`, custom Supabase GoTrue integration | OAuth/PKCE; token storage in OS keychain not localStorage |
| **AUTH-2** | OS biometric (Touch ID, Windows Hello via `windows-rs`) | Verify biometric integration callbacks, no backdoors |
| **AUTH-3** | Step-up auth via re-prompt | Sensitive Tauri commands require fresh auth |
| **NETWORK-1** | `rustls` TLS config, optional reqwest customization | TLS posture; no `dangerousInsecureTransportProtocol` |
| **NETWORK-2** | **No built-in cert pinning** — must implement via `rustls::client::ServerCertVerifier` | **DIY**; audit ServerCertVerifier impl |
| **PLATFORM-1** | **Tauri command system, capabilities v2** | Full Section 3-4 audit |
| **PLATFORM-2** | **Tauri IS a WebView** — CSP, asset protocol, Isolation Pattern | Full Section 7-10 audit |
| **PLATFORM-3** | OS-level screenshot prevention | Limited; Tauri docs don't cover natively |
| **CODE-1** | Min OS version requirements in installers | Set deliberately; document |
| **CODE-2** | Updater (`tauri-plugin-updater`) | Full Section 20 audit |
| **CODE-3** | `cargo audit`, `cargo-deny`, npm audit | CI-integrated SCA |
| **CODE-4** | Validation in `#[tauri::command]` handlers | Full Section 12-13 audit |
| **RESILIENCE-1/2/3/4** | **Tauri offers NONE** (Section 25) | Layer 3rd-party RASP if threat model demands |
| **PRIVACY-1/2/3/4** | Manual implementation; no Tauri scaffolding | Same as mobile |

---

## 28. Cross-reference with curated 67-skill set

| Curated skill | Applies to Tauri audit phase |
|---|---|
| `performing-thick-client-application-penetration-test` | Top-level Tauri pentest playbook |
| `performing-binary-exploitation-analysis` | Section 24 (binary hardening verification) |
| `reverse-engineering-rust-malware` | Triage techniques for Rust binary; assess code-signature integrity |
| `performing-cryptographic-audit-of-application` | Section 21 (signing keys), Section 5/8 (scope crypto) |
| `performing-ssl-tls-security-assessment` | Section 9 (WebView TLS), updater HTTPS posture |
| `testing-for-xss-vulnerabilities` | Section 7-10 (CSP, WebView XSS in Tauri webview) |
| `performing-content-security-policy-bypass` | Section 7 (verifying CSP holds) |
| `performing-sca-dependency-scanning-with-snyk` | Section 26 (advisory history) — npm + cargo |
| `implementing-secret-scanning-with-gitleaks` | Section 20.4 (key handling) — detect leaked TAURI_PRIVATE_KEY |
| `performing-threat-modeling-with-owasp-threat-dragon` | Phase 0 of the audit |

**Gaps in the curated set vs Tauri-specific concerns:**
- No skill for capability/permission ACL audit — must rely on this document
- No skill for Tauri-specific IPC fuzzing
- No skill for code-signing verification on macOS / Windows / Linux

---

## 29. Concrete audit checklist for the user's app

### A. tauri.conf.json
- [ ] `app.security.csp` populated, no `'unsafe-inline'` or `'unsafe-eval'` (except for documented framework-specific cases)
- [ ] `app.security.devCsp` populated (or null deliberately) — no production CSP cross-contamination
- [ ] `app.security.freezePrototype: true`
- [ ] `app.security.dangerousDisableAssetCspModification: false`
- [ ] `app.security.assetProtocol.enable: false` UNLESS used (then strict scope)
- [ ] If asset protocol enabled: `requireLiteralLeadingDot: true`, deny credentials paths
- [ ] `app.security.pattern.use: "isolation"` (not `"brownfield"`) UNLESS impossible
- [ ] `app.withGlobalTauri: false`
- [ ] `bundle.windows.webviewInstallMode` chosen deliberately
- [ ] `plugins.updater.dangerousInsecureTransportProtocol: false`
- [ ] `plugins.updater.endpoints` are HTTPS with HSTS-preloaded TLDs

### B. Capabilities (`src-tauri/capabilities/*`)
- [ ] All capabilities have non-empty `description`
- [ ] No capability has `windows: ["*"]` + sensitive permission
- [ ] No capability with `remote.urls` + `core:webview:allow-create-*`
- [ ] No `*:default` reference without manual expansion documented in audit notes
- [ ] `remote.urls` pinned to specific Supabase project subdomain (not `*.supabase.co`)
- [ ] `core:webview:allow-internal-toggle-devtools` absent from production capability files
- [ ] `core:event:allow-emit` restricted (consider whether it's needed at all)
- [ ] All fs permissions have inline `allow` scope; no fs scope contains `$HOME/**` or `**`
- [ ] `shell:allow-execute`/`shell:allow-spawn` absent OR have validators on every arg
- [ ] `shell:allow-open` migrated to `tauri-plugin-opener` (CVE-2025-31477)
- [ ] `http:default` has explicit URL scope (no `https://*`)

### C. Permissions (`src-tauri/permissions/*`)
- [ ] Custom permissions have non-empty `description`
- [ ] Scopes use absolute pattern roots
- [ ] Scope deny lists include credential paths (`*.ssh/**`, `*.aws/**`, browser data)
- [ ] No `[[set]]` referenced from capabilities without expansion check

### D. Commands (`#[tauri::command]`)
- [ ] Every path arg canonicalised + validated against allowlist in Rust (don't trust capability scope alone)
- [ ] `String`/`Vec<u8>` length-bounded
- [ ] No `#[serde(flatten)]` with `serde_json::Value` for untrusted input
- [ ] Errors don't leak filesystem paths or stack traces
- [ ] No authorization decisions in frontend reflected back to commands
- [ ] No `register_uri_scheme_protocol` handler reflects URL into HTML response
- [ ] No `register_uri_scheme_protocol` handler forwards URL to `reqwest::get` without scope check

### E. Updater
- [ ] `pubkey` in shipped binary matches build secret store (`strings <binary> | grep -i untrusted-comment`)
- [ ] No `envPrefix: ['TAURI_']` in `vite.config.ts`; no leaked private keys in `dist/` (`grep -r TAURI_PRIVATE_KEY dist/`)
- [ ] Tauri version pinned **≥ 2.11.1** (CVE-2026-42184)
- [ ] `tauri-plugin-shell` version pinned **≥ 2.2.1** (CVE-2025-31477)
- [ ] Signing key stored in HSM / Azure Trusted Signing / Apple App Store Connect API — **never** long-lived `.p12` in CI secrets
- [ ] `version_comparator` left default (no rollback unless documented + manual confirmation)

### F. Code signing
- macOS:
  - [ ] Hardened Runtime enabled (implicit via notarization)
  - [ ] Entitlements: NO `disable-library-validation`, NO `allow-dyld-environment-variables`, NO `allow-unsigned-executable-memory`
  - [ ] App Sandbox enabled if shipping via Mac App Store
- Windows:
  - [ ] EV cert preferred (immediate SmartScreen reputation)
  - [ ] Per-user installs unless machine-wide is required
  - [ ] `installerArgs` reviewed
- Linux:
  - [ ] AppImage GPG signing treated as advisory only
  - [ ] Distribution channel signing (apt/rpm/Flathub/Snap) configured

### G. Binary hardening
- [ ] `Cargo.toml` has Tauri-recommended release profile
- [ ] Additional `RUSTFLAGS` for full RELRO + CFG/CET
- [ ] `checksec` verification on shipped binary

### H. Dependencies
- [ ] `cargo audit` clean in CI
- [ ] `cargo deny` configured
- [ ] No typosquat crates (`tauri-win-rt-notification`, `tauri-winrt-notifications`)
- [ ] npm audit clean
- [ ] Tauri plugins pinned to fixed versions

### I. Lifecycle
- [ ] Dev server not exposed beyond loopback
- [ ] CI build environment hardened (least-privilege secrets, isolated runners)
- [ ] Manifest/binary host TLS-only with HSTS preload
- [ ] Uninstaller cleans `$APPDATA`, `$APPLOCALDATA`, scheduled tasks

---

## 30. Sources

### Tauri docs
- https://v2.tauri.app/security/
- https://v2.tauri.app/security/capabilities/
- https://v2.tauri.app/security/permissions/
- https://v2.tauri.app/security/scope/
- https://v2.tauri.app/security/csp/
- https://v2.tauri.app/security/lifecycle/
- https://v2.tauri.app/security/runtime-authority/
- https://v2.tauri.app/security/future-work/
- https://v2.tauri.app/security/http-headers/
- https://v2.tauri.app/concept/inter-process-communication/
- https://v2.tauri.app/concept/inter-process-communication/isolation/
- https://v2.tauri.app/concept/inter-process-communication/brownfield/
- https://v2.tauri.app/concept/process-model/
- https://v2.tauri.app/concept/architecture/
- https://v2.tauri.app/develop/calling-rust/
- https://v2.tauri.app/develop/calling-frontend/
- https://v2.tauri.app/reference/config/
- https://v2.tauri.app/reference/acl/capability/
- https://v2.tauri.app/reference/acl/permission/
- https://v2.tauri.app/reference/acl/scope/
- https://v2.tauri.app/reference/acl/core-permissions/
- https://v2.tauri.app/reference/webview-versions/
- https://v2.tauri.app/plugin/updater/
- https://v2.tauri.app/distribute/sign/macos/
- https://v2.tauri.app/distribute/sign/windows/
- https://v2.tauri.app/distribute/sign/linux/
- https://v2.tauri.app/learn/security/using-plugin-permissions/
- https://v2.tauri.app/learn/security/writing-plugin-permissions/
- https://v2.tauri.app/learn/security/capabilities-for-windows-and-platforms/
- https://schema.tauri.app/config/2

### docs.rs
- https://docs.rs/tauri-utils/latest/tauri_utils/config/struct.SecurityConfig.html
- https://docs.rs/tauri-utils/latest/tauri_utils/config/enum.Csp.html
- https://docs.rs/tauri-utils/latest/tauri_utils/config/struct.AssetProtocolConfig.html
- https://docs.rs/tauri-utils/latest/tauri_utils/config/enum.FsScope.html
- https://docs.rs/tauri-runtime/latest/tauri_runtime/webview/struct.WebviewAttributes.html

### Source code
- https://github.com/tauri-apps/tauri/blob/dev/crates/tauri/src/ipc/protocol.rs
- https://github.com/tauri-apps/tauri/blob/dev/crates/tauri/src/ipc/channel.rs
- https://github.com/tauri-apps/tauri/blob/dev/crates/tauri/scripts/ipc-protocol.js
- https://github.com/tauri-apps/tauri/blob/dev/crates/tauri-macros/src/command/handler.rs
- https://github.com/tauri-apps/tauri/blob/dev/crates/tauri-utils/src/acl/capability.rs
- https://github.com/tauri-apps/tauri/blob/dev/crates/tauri-utils/src/acl/identifier.rs

### Advisories
- https://github.com/tauri-apps/tauri/security/advisories
- https://github.com/tauri-apps/tauri/security/advisories/GHSA-7gmj-67g7-phm9
- https://github.com/tauri-apps/tauri/security/advisories/GHSA-57fm-592m-34r7
- https://github.com/tauri-apps/tauri/security/advisories/GHSA-2rcp-jvr4-r259
- https://github.com/tauri-apps/tauri/security/advisories/GHSA-wmff-grcw-jcfm
- https://github.com/tauri-apps/tauri/security/advisories/GHSA-4wm2-cwcf-wwvp
- https://github.com/tauri-apps/tauri/security/advisories/GHSA-6mv3-wm7j-h4w5
- https://github.com/tauri-apps/tauri/security/advisories/GHSA-q9wv-22m9-vhqh
- https://github.com/tauri-apps/tauri/security/advisories/GHSA-28m8-9j7v-x499
- https://github.com/tauri-apps/plugins-workspace/security/advisories/GHSA-c9pr-q8gx-3mgp
- https://rustsec.org/advisories/RUSTSEC-2023-0108.html
- https://rustsec.org/advisories/RUSTSEC-2023-0117.html

### Coordinated disclosure
**security@tauri.app**

### Context7
- Library: `/tauri-apps/tauri-docs` (1027 snippets, source High, score 82.16)
- Alternates: `/websites/v2_tauri_app` (2376), `/websites/rs_tauri_2_9_5` (6886), `/llmstxt/tauri_app_llms-full_txt` (2567)
- Use `mcp__context7__query-docs` for specific technical questions ("Tauri 2 capability YAML schema", "Tauri Channel lifetime semantics", "tauri-plugin-fs scope substitutions")
