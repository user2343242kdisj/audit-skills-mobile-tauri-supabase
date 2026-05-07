# Claude Code Subagent Hierarchy

21 specialised subagents that turn this audit toolkit into a hierarchy: **one orchestrator + 20 narrow domain experts.** Each agent has a tight, audit-specific system prompt and references the deep documents in `../../docs/`.

## Hierarchy

```
audit-orchestrator               ← top-level "gestor"
│
├── threat-modeler               ← runs first, drives profile selection
│
├── Supabase (7)
│   ├── supabase-rls-auditor             RLS policies, Splinter, pgTAP
│   ├── supabase-storage-auditor         storage.buckets, signed URLs, MIME limits
│   ├── supabase-edge-functions-auditor  Deno + 13 Semgrep rules
│   ├── supabase-auth-auditor            GoTrue, JWT, MFA, CVE-2026-31813
│   ├── supabase-realtime-auditor        channels, broadcast/presence, postgres-changes
│   ├── supabase-postgres-auditor        roles, grants, search_path, pgaudit
│   └── supabase-network-auditor         TLS, regions, Network Restrictions
│
├── Tauri (5)
│   ├── tauri-capabilities-auditor       capability files, ACL invariants
│   ├── tauri-ipc-auditor                #[tauri::command], custom schemes, isolation
│   ├── tauri-csp-webview-auditor        CSP, asset protocol, freezePrototype
│   ├── tauri-updater-auditor            updater config, Ed25519 keys
│   └── tauri-binary-hardening-auditor   code signing, RUSTFLAGS, RASP=NONE
│
├── Mobile (4)
│   ├── mobile-static-analysis-auditor   APK/IPA, MobSF, jadx, manifest
│   ├── mobile-dynamic-analysis-auditor  Frida, Objection, Burp, Drozer
│   ├── mobile-deeplinks-auditor         App Links, Universal Links, intents
│   └── mobile-storage-crypto-auditor    Keychain, Keystore, cert pinning
│
└── Cross-cutting (4)
    ├── secrets-scanner-coordinator      ggshield + TruffleHog + Gitleaks
    ├── sast-dast-coordinator            Semgrep + Schemathesis + BOLA harness + ZAP
    ├── threat-modeler                   pytm + STRIDE + 16 custom threats
    └── sbom-vuln-coordinator            CycloneDX + Grype + Trivy + cargo-audit
```

## How to deploy

In your app repo:

```bash
# From the app repo root:
git clone https://github.com/<your>/audit-skills-mobile-tauri-supabase /tmp/audit-skills
mkdir -p .claude/agents
cp /tmp/audit-skills/templates/claude-agents/*.md .claude/agents/
```

Or, if you use this repo as a submodule:

```bash
git submodule add https://github.com/<your>/audit-skills-mobile-tauri-supabase audit-skills
ln -s ../audit-skills/templates/claude-agents .claude/agents
```

### Verify Claude Code picks them up

```bash
# Inside Claude Code:
/agents
```

Should list all 21 agents under your project scope.

## Usage patterns

### Full pre-launch audit

```
> Run a full pre-launch security audit on this codebase.
```

→ The `audit-orchestrator` invokes phases:
1. `threat-modeler` (first, drives profile)
2. Static analysis subagents (in parallel)
3. Configuration auditors (in parallel)
4. Dynamic / DAST (sequential, needs test users)
5. IPC + Tauri runtime
6. Synthesis + final report

### Targeted audit

```
> Audit just the RLS policies on the new schema.
```

→ Goes directly to `supabase-rls-auditor`. The orchestrator is for multi-domain requests.

### Re-run after fix

```
> The CVE-2026-31813 fix is deployed. Re-run the auth audit and confirm clean.
```

→ `supabase-auth-auditor` re-runs version checks and reports clean / regression.

## Design principles (max precision)

Every subagent is engineered for **highest precision in a narrow domain**, following these rules:

1. **One scope per agent.** Each agent declares its scope in plain English at the top and lists out-of-scope items with the correct subagent to delegate.
2. **No invented findings.** When data is missing, agents ask for the missing input and stop. They never speculate.
3. **Source-cited.** Every finding cites `path:line`, CVE/GHSA ID, Splinter rule ID, MASWE ID, or URL.
4. **Knowledge baked in.** Each agent's prompt embeds the relevant CVEs, schemas, rules verbatim from `docs/owasp-mas-analysis.md`, `docs/tauri-2-security-analysis.md`, `docs/supabase-security-tools.md`. No external lookup needed for routine work.
5. **Output format fixed.** Each agent has a structured output template; the orchestrator can compose them mechanically.
6. **Tool access scoped.** Most agents have `Read, Bash, Grep, Glob` only. The threat-modeler also has `Write` (produces a model file). The orchestrator has `Write` (produces the final report).
7. **No model override.** Each agent inherits the parent model — for sustained audit work on Opus-class capability, run the parent on Opus; subagents follow.

## Adding a new agent

1. Write the file: `templates/claude-agents/<name>.md`
2. Frontmatter: `name`, `description` (when to invoke), optional `tools` and `model`
3. System prompt body following the structure: scope → out-of-scope → knowledge base → workflow → output format → references
4. Add a row to the orchestrator's routing table (`audit-orchestrator.md`)
5. Add to this README's hierarchy diagram
6. Copy to your `.claude/agents/` to test

## Anti-patterns to avoid

- **Don't** create one mega-agent that "does everything". Defeats the precision-via-narrow-scope design.
- **Don't** duplicate scope across agents. If two agents both audit RLS, findings will collide and contradict.
- **Don't** put generic security advice in subagent prompts. The point is domain-specific actionable guidance.
- **Don't** skip the threat-modeler for full audits. Profile selection (L1/L2/R/P) drives everything else.

## References

All subagents reference the deep documents in this repo:
- `docs/owasp-mas-analysis.md` — MAS / MASVS / MASTG / MASWE deep dive
- `docs/tauri-2-security-analysis.md` — 30-section Tauri 2 audit reference
- `docs/supabase-security-tools.md` — Supabase security-tooling stack
