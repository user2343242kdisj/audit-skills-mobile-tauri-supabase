# Extended agents 17–29 — Extreme Security Build (2026-05-16)

This file complements `README.md` (which is under modification by a parallel
session and intentionally not touched here per the project's
parallel-instances rule). It documents the 13 new auditor agents added on
the `feat/extreme-security-skills-2026-05-16` branch.

All agents are read-only against the target repo, write only to
`./audit-reports/`, and use open-source tooling exclusively.

## Topic table

| #  | Agent prompt                                       | Specialist file                                                  | Output report                                | Phase |
| -- | -------------------------------------------------- | ---------------------------------------------------------------- | -------------------------------------------- | ----- |
| 17 | `numbered/agent-17.md`                             | `claude-agents/llm-redteam-auditor.md`                           | `audit-reports/17-llm-redteam.md`            | 2     |
| 18 | `numbered/agent-18.md`                             | `claude-agents/webhook-signature-auditor.md`                     | `audit-reports/18-webhook-signature.md`      | 2     |
| 19 | `numbered/agent-19.md`                             | `claude-agents/race-toctou-statemachine-auditor.md`              | `audit-reports/19-race-toctou.md`            | 2     |
| 20 | `numbered/agent-20.md`                             | `claude-agents/supply-chain-attestation-auditor.md`              | `audit-reports/20-supply-chain-attestation.md` | 2   |
| 21 | `numbered/agent-21.md`                             | `claude-agents/crypto-review-auditor.md`                         | `audit-reports/21-crypto-review.md`          | 2     |
| 22 | `numbered/agent-22.md`                             | `claude-agents/mobile-rasp-runtime-auditor.md`                   | `audit-reports/22-mobile-rasp-runtime.md`    | 2     |
| 23 | `numbered/agent-23.md`                             | `claude-agents/anti-fraud-fintech-auditor.md`                    | `audit-reports/23-anti-fraud-fintech.md`     | 2     |
| 24 | `numbered/agent-24.md`                             | `claude-agents/privacy-pii-dsar-auditor.md`                      | `audit-reports/24-privacy-pii-dsar.md`       | 2     |
| 25 | `numbered/agent-25.md`                             | `claude-agents/dns-email-cert-auditor.md`                        | `audit-reports/25-dns-email-cert.md`         | 2     |
| 26 | `numbered/agent-26.md`                             | `claude-agents/bot-abuse-ato-auditor.md`                         | `audit-reports/26-bot-abuse-ato.md`          | 2     |
| 27 | `numbered/agent-27.md`                             | `claude-agents/browser-security-web-auditor.md`                  | `audit-reports/27-browser-security-web.md`   | 2     |
| 28 | `numbered/agent-28.md`                             | `claude-agents/compliance-regulatory-auditor.md`                 | `audit-reports/28-compliance-regulatory.md`  | 2     |
| 29 | `numbered/agent-29.md`                             | `claude-agents/ota-update-channel-auditor.md`                    | `audit-reports/29-ota-update-channel.md`     | 2     |

## Per-agent scope summary

- **agent-17 llm-redteam** — OWASP LLM Top 10 2025; Garak 37+ probes; Promptfoo
  redteam; system prompt leakage (LLM07); RAG / embedding (LLM08); excessive
  agency on action tools; unbounded consumption (token DoS).
- **agent-18 webhook-signature** — HMAC raw bytes, constant-time compare,
  ≤5-min replay window, composite idempotency `(key, user_id, function_name)`,
  per-vendor secrets, body-logging discipline across 9 Travus webhook EFs.
- **agent-19 race-toctou** — 12 race-condition pitfalls; SELECT-then-UPDATE
  without row-lock; idempotency replay; state-machine guards; FIFO depletion
  (ADR-019); cron concurrency; trigger re-entry.
- **agent-20 supply-chain-attestation** — SLSA v1.1, Sigstore cosign, npm
  provenance, OpenSSF Scorecard, dep-confusion / typosquat, Shai-Hulud V2
  IOC sweep, CVE pin verification (Clerk 2025-53548, Next 2025-29927, Hono
  2026-22817).
- **agent-21 crypto-review** — JWT alg pinning, HMAC ct-compare, AES-GCM
  nonce, RSA padding, Math.random in security, TLS 1.3 0-RTT, key custody
  hygiene (1P ↔ Vault).
- **agent-22 mobile-rasp-runtime** — MASVS-RESILIENCE 1-4; App Attest;
  Play Integrity; anti-Frida / anti-debug; Hermes bundle leak; cleartext
  traffic; WebView hardening; FLAG_SECURE.
- **agent-23 anti-fraud-fintech** — velocity, geo-velocity, device-rep,
  receipt + Adapty-user reuse across accounts (promo abuse), refund abuse,
  mass-portfolio-create, sanctions, disposable email.
- **agent-24 privacy-pii-dsar** — PII column inventory, retention crons,
  DSAR pipeline, right-to-erasure cascade, residency, Sentry beforeSend,
  PostHog properties allowlist.
- **agent-25 dns-email-cert** — CAA, DNSSEC (CA mandate 2026-03-15), SPF /
  DKIM / DMARC, MTA-STS, DANE TLSA, BIMI, CT-log monitoring via crt.sh, HSTS
  preload, HTTP→HTTPS redirect.
- **agent-26 bot-abuse-ato** — Clerk Bot Protection, Vercel BotID +
  CF-proxy degradation pitfall, CF Bot Management, HIBP credential leak,
  failed-login + failed-MFA telemetry, impossible-travel.
- **agent-27 browser-security-web** — CSP-L3 nonces, Trusted Types,
  COOP/COEP/CORP, SRI, cookie posture (Clerk session / __client_uat),
  Permissions-Policy, postMessage origin checks on checkout iframes.
- **agent-28 compliance-regulatory** — PSD3/PSR, MiCA + EBA NAL, DORA
  TPRM, EU AI Act risk classification, LGPD ANPD (BR), GDPR Art 17/20,
  PCI DSS 4.0.1 SAQ-A confirmation.
- **agent-29 ota-update-channel** — channel ↔ runtimeVersion 1:1, signing
  cert hygiene, kill-switch (`appGates.otaDisabled`), force-update
  (`appGates.minAppVersion`), phased rollout, fingerprint parity,
  rollback drill.

## Threat-model coverage closed (mapping)

| Threat / surface                                                       | Closed by              |
| ---------------------------------------------------------------------- | ---------------------- |
| OWASP LLM01–10 (prompt injection, system prompt leakage, RAG)         | agent-17               |
| Webhook HMAC replay / non-constant-time compare / idempotency drift   | agent-18               |
| Double-spend, FIFO divergence, idempotency-key drift                  | agent-19               |
| Sigstore/cosign provenance gap, dep-confusion, Shai-Hulud V2 IOC      | agent-20               |
| JWT alg confusion (Hono CVE-2026-22817), HMAC timing, AES-GCM nonce   | agent-21               |
| App Attest entitlement gap, anti-Frida absence, Hermes bundle leak    | agent-22               |
| Subscription promo abuse, refund abuse, sanctions, mass-bot scraping  | agent-23               |
| LGPD / GDPR DSAR pipeline absence, Sentry+PostHog PII leak            | agent-24               |
| CAA + DNSSEC + DMARC + MTA-STS + CT-log rogue cert                    | agent-25               |
| ATO via credential stuffing / brute-force MFA, BotID degraded by CF   | agent-26               |
| CSP-L3, Trusted Types, postMessage origin spoof, Clerk cookie posture | agent-27               |
| PSD3 / MiCA / DORA / AI Act / LGPD / GDPR / PCI 4.0.1 readiness gaps  | agent-28               |
| OTA kill-switch unreachable, signing cert leak, fingerprint drift     | agent-29               |

## Smoke-test (Salvador, one-liner)

```bash
cd /Users/salvadorreis/travus/audit
python3 tools/validate-skill.py --all                                   # 68/68 PASS expected
ls -1 templates/agent-prompts/numbered/agent-{17..29}.md | wc -l         # 13
ls -1 templates/agent-prompts/raw/{17..29}-*.txt           | wc -l       # 13
ls -1 templates/claude-agents/{llm-redteam,webhook-signature,race-toctou-statemachine,supply-chain-attestation,crypto-review,mobile-rasp-runtime,anti-fraud-fintech,privacy-pii-dsar,dns-email-cert,bot-abuse-ato,browser-security-web,compliance-regulatory,ota-update-channel}-auditor.md | wc -l   # 13
git log --oneline origin/main..HEAD | grep -c "feat(audit): add agent-"  # 13
```

## How to invoke (any new agent)

```bash
# Self-contained numbered prompt:
cat templates/agent-prompts/numbered/agent-17.md | pbcopy
# → paste into a fresh Claude Code terminal

# Raw paste variant (references the claude-agents specialist):
cat templates/agent-prompts/raw/17-llm-redteam.txt | pbcopy

# Or load the specialist file as a subagent:
# (project-level .claude/agents/<name>-auditor.md)
```
