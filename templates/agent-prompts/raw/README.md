# Raw Paste-Text Only

Each `.txt` here contains **only the bare prompt** — what you paste into Claude Code.
The full `.md` files in the parent directory contain the prompt PLUS the pre-flight bash + env documentation.

## Quickest copy

```bash
# Single-terminal master orchestrator (does everything):
pbcopy < ../audit-skills/templates/agent-prompts/raw/MASTER.txt

# Or any specific subagent:
pbcopy < ../audit-skills/templates/agent-prompts/raw/05-supabase-rls.txt
```

Then paste in Claude Code (Cmd+V).

## Files

| File | Phase | Description |
|---|---|---|
| `MASTER.txt` | All-in-one | Single-terminal end-to-end orchestrator |
| `00-orchestrator.txt` | 3 (last) | Synthesis only (assumes 01–15 reports already exist) |
| `01-threat-modeler.txt` | 1 (first) | Threat model + MAS profile selection |
| `02-secrets-scanner.txt` | 2 | ggshield + TruffleHog + Gitleaks |
| `03-sbom-vuln.txt` | 2 | CycloneDX + Grype + Trivy + cargo-audit |
| `04-sast-dast.txt` | 2 | Semgrep + Schemathesis + BOLA harness |
| `05-supabase-rls.txt` | 2 | Splinter + pgTAP RLS audit |
| `06-supabase-auth.txt` | 2 | GoTrue + JWT + MFA + CVEs |
| `07-supabase-edge-functions.txt` | 2 | Deno lint + 13 custom Semgrep rules |
| `08-supabase-postgres.txt` | 2 | Roles, grants, search_path, FDWs, PG CVEs |
| `09-supabase-storage-realtime-network.txt` | 2 | Storage + Realtime + TLS posture |
| `10-tauri-capabilities.txt` | 2 | ACL invariants, high-risk identifiers |
| `11-tauri-ipc.txt` | 2 | Commands, custom schemes, isolation |
| `12-tauri-config-and-distribution.txt` | 2 | CSP + updater + binary hardening |
| `13-mobile-static.txt` | 2 | MobSF + jadx + manifest red-flags |
| `14-mobile-dynamic.txt` | 2 | Frida + Burp + Objection + Drozer |
| `15-mobile-platform.txt` | 2 | Deeplinks + Keychain + cert pinning |

## How these were generated

Each is the segment of the corresponding `../<NN>-<name>.md` file that comes after the `## Paste this entire block into Claude Code` heading and after the `---` separator that follows it.

To regenerate after editing the `.md` source files:

```bash
for f in templates/agent-prompts/[0-9M]*.md; do
  name=$(basename "$f" .md)
  awk '/^## Paste this entire block into Claude Code/{p=1; next} p && /^---$/{if(!started){started=1; next}} started' "$f" \
    > "templates/agent-prompts/raw/$name.txt"
done
```
