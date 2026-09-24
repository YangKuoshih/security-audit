<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/header-dark.svg">
  <img alt="security-audit — Find secrets before attackers do." src="assets/header.svg" width="680">
</picture>

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Tests](https://github.com/YangKuoshih/security-audit/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/YangKuoshih/security-audit/actions/workflows/tests.yml)
[![Patterns](https://img.shields.io/badge/patterns-60%20rules-orange.svg)](skills/security-audit/scripts/patterns.dat)

</div>

---

## Why

Every leaked secret starts the same way — a key hardcoded "just for testing" that makes it to production. Existing tools catch some of these, but they're standalone binaries that don't understand your code's context.

**security-audit** combines deterministic pattern scanning and context-aware triage with agent reasoning. The scanner removes common noise consistently; the coding agent validates the remaining source-level risks and explains what to fix.

## What It Catches

<table>
<tr>
<td width="50%">

**Secrets** — vendor signatures and high-signal heuristics informed by [GitLeaks](https://github.com/gitleaks/gitleaks)

- AWS, GCP, Azure credentials
- GitHub, GitLab, Slack tokens
- Stripe, Twilio, SendGrid API keys
- Database connection strings
- Private keys (RSA, SSH, PGP)
- OpenAI, Heroku, NPM, PyPI tokens
- DigitalOcean, HashiCorp Vault, Terraform Cloud
- Grafana, Shopify, Anthropic, Docker Hub
- JWT tokens and signing secrets
- High-entropy strings (charset-aware: hex, base64, generic)

</td>
<td width="50%">

**Vulnerabilities** — 14 patterns mapped to [OWASP Top 10](https://owasp.org/Top10/)

- SQL injection sinks
- XSS vectors (innerHTML, dangerouslySetInnerHTML)
- Command injection
- Server-side request forgery (SSRF)
- Insecure deserialization (pickle, yaml.load)
- Weak cryptography (MD5, SHA1, DES)
- Disabled SSL verification
- Debug mode in production

</td>
</tr>
<tr>
<td colspan="2">

**Dangerous File Types** — 15 file patterns checked via `git ls-files`

Files that should never be committed, regardless of contents: Terraform state (`.tfstate`), private keys (`.pem`, `.key`, `.p12`, `.pfx`), Java keystores (`.jks`), cloud credentials (`credentials.json`, `service-account*.json`), Terraform cache (`.terraform/`), database files (`.sqlite`, `.db`), and files with "secret" in the name. Only git-tracked files are flagged — gitignored files are fine.

</td>
</tr>
</table>

## Quick Start

**Install globally for supported coding agents:**
```bash
npx skills add YangKuoshih/security-audit -g --all
```

**Or install per-project:**
```bash
npx skills add YangKuoshih/security-audit
```

**Or use directly as a Claude Code plugin:**
```bash
git clone https://github.com/YangKuoshih/security-audit.git

# From any project directory
claude --plugin-dir /path/to/security-audit
```

**Run it:**
```
/security-audit                    # full scan, markdown output
/security-audit --incremental      # changed files only (git diff)
/security-audit --format sarif     # SARIF 2.1.0 for GitHub Code Scanning
/security-audit --severity high    # Critical + High only
/security-audit --path src/        # target specific directory
```

For CI, the Python scanner can enforce a policy after safely writing its output:

```bash
python3 skills/security-audit/scripts/scan-secrets.py \
  --target . \
  --patterns skills/security-audit/scripts/patterns.dat \
  --output security-findings.jsonl \
  --fail-on high
```

Exit code `3` means the configured finding threshold was met; scanner/configuration
errors use a different non-zero exit code.

## How It Works

```
              ┌─────────────────────────────────────────────────┐
              │              /security-audit                     │
              └────────────────────┬────────────────────────────┘
                                   │
               ┌───────────────┬───┴───┬───────────────┐
               ▼               ▼       ▼               ▼
        ┌─────────────┐ ┌──────────┐ ┌──────────┐ ┌─────────────┐
        │   Phase 1   │ │ Phase 2  │ │Phase 2b  │ │   Phase 3   │
        │   Setup     │ │ Scan     │ │ File     │ │   Analyze   │
        │             │ │          │ │ Types    │ │             │
        │ Detect env  │ │ 60 regex │ │ 15 file  │ │Agent review │
        │ Load config │ │ + context│ │ patterns │ │of remaining │
        │ Build file  │ │ +entropy │ │ via git  │ │ Correlates  │
        │ list        │ │detection │ │ ls-files │ │ + exec sum  │
        └──────┬──────┘ └────┬─────┘ └────┬─────┘ └──────┬──────┘
               │             │            │               │
               └─────────────┴─────┬──────┴───────────────┘
                                   ▼
                        ┌─────────────────────┐
                        │      Phase 4        │
                        │      Report         │
                        │                     │
                        │  Markdown / SARIF   │
                        │  / JSON output      │
                        └─────────────────────┘
```

**Shell available?** Runs `scan-secrets.py` (Python, preferred for production) or `scan-secrets.sh` (reduced bash/grep fallback). The Python scanner applies deterministic context rules, entropy detection, complete-PEM validation, user-controlled SSRF checks, and dangerous-file detection via `git ls-files`. The agent then validates only the remaining redacted candidates.

**No shell?** The coding agent reads files directly using the pattern knowledge from `references/` — slower but works on sandboxed platforms. Dangerous file types are flagged without reading their contents.

**Secret safety:** Discovered secrets are never passed to the coding agent or any third party. Scanner output is redacted before agent review. The report is a local file — you decide what to do with it.

## Report Output

Every finding gets an ID, redacted match, and actionable remediation:

```markdown
# Security Audit Report

Scan date: 2026-03-08 21:41 UTC
Total findings: 18
Summary: 3 Critical, 4 High, 8 Medium, 3 Low

## Critical (3)

### [C-001] AWS Access Key ID
- File: src/config/aws.js:8
- Pattern: aws-access-key
- Match: `AKIA...MPLE`
- Remediation: Remove the key from source code. Use environment variables
  or AWS Secrets Manager. Rotate the key immediately via the AWS IAM console.

### [C-002] Stripe Secret Key
- File: src/config/aws.js:35
- Pattern: stripe-secret-key
- Match: `sk_l...uvwx`
- Remediation: Remove the key from source code. Use environment variables.
  Rotate the key in the Stripe dashboard.
```

**Three output formats:**

| Format | Use Case | Destination |
|--------|----------|-------------|
| **Markdown** | Human review, PR comments | Terminal, docs |
| **SARIF 2.1.0** | CI/CD integration | GitHub Code Scanning, VS Code |
| **JSON** | Programmatic consumption | Dashboards, scripts |

## Severity Classification

| Level | Criteria | Response Time | Examples |
|-------|----------|--------------|---------|
| **Critical** | Broad/production access. Immediate exploitation risk. | Hours | AWS root keys, private keys, Stripe live keys |
| **High** | Scoped access. Exploitation needs context. | 1-2 days | GitHub PATs, Slack tokens, DB connection strings |
| **Medium** | Needs verification, or confirmed vuln pattern. | 1-2 weeks | SQL injection sinks, high-entropy strings, XSS |
| **Low** | Best practice violation. No direct exploit. | Next cycle | Debug mode, permissive CORS, disabled SSL verify |

The Python scanner assigns reproducible contextual severity and confidence before agent review. It downgrades likely test placeholders, suppresses documentation-only vulnerability heuristics, and treats standard Firebase client keys as Low while leaving non-Firebase Google API keys Critical. See [`references/severity-guide.md`](skills/security-audit/references/severity-guide.md) for the full ruleset.

## Configuration

Drop a `.security-audit.yml` in your repo root. Everything is optional — sensible defaults apply.

```yaml
scan:
  mode: full                    # full | incremental | paths
  base_branch: main

exclude:
  directories: [vendor, third_party]
  files: ["*.min.js", "*.lock"]
  patterns: ["test_fixtures/**"]

severity:
  minimum: medium               # skip Low findings

ci:
  fail_on: high                 # exit 3 after writing results

output:
  format: markdown              # markdown | sarif | json

custom_patterns:
  secrets:
    - name: "Internal Token"
      regex: "MYCOMPANY_[A-Z0-9]{32}"
      severity: critical
  allowlist:
    - file: "docs/examples.md"
      reason: "Placeholder keys"
```

See [`examples/security-audit.yml`](skills/security-audit/examples/security-audit.yml) for all options with inline documentation.

## Project Structure

```
security-audit/
├── .claude-plugin/
│   └── plugin.json                     # Plugin manifest for Claude Code
├── skills/
│   └── security-audit/                 # The distributable skill
│       ├── SKILL.md                    # Agent-neutral orchestration workflow
│       ├── agents/openai.yaml          # Codex UI metadata and invocation policy
│       ├── references/
│       │   ├── secret-patterns.md      # Secret and dangerous-file guidance
│       │   ├── vulnerability-patterns.md   # 14 patterns (OWASP Top 10)
│       │   └── severity-guide.md       # Classification rules + adjustments
│       ├── scripts/
│       │   ├── scan-secrets.sh         # Bash scanner (grep, PCRE/ERE)
│       │   ├── scan-secrets.py         # Preferred scanner + entropy detection
│       │   ├── patterns.dat            # 60 compiled patterns for scanners
│       │   └── generate-report.py      # Report generator (MD/SARIF/JSON)
│       └── examples/
│           ├── sample-report.md        # Example Markdown output
│           ├── sample-report.sarif.json    # Example SARIF output
│           └── security-audit.yml      # Example configuration
├── tests/
│   ├── test-e2e.sh                     # Portable test runner
│   ├── test_e2e.py                     # 24 end-to-end regression tests
│   └── fixtures/sample-repo/           # Test files with known secrets/vulns
├── docs/plans/                         # Design documents
├── LICENSE                             # Apache 2.0
├── NOTICE                              # Attribution
└── README.md
```

## Testing

Run the dependency-free regression suite with:

```bash
bash tests/test-e2e.sh
```

Current coverage includes Python and bash scanning, secret redaction, file exclusions,
severity and CI thresholds, strict incremental failures, dangerous-file scope,
contextual Firebase handling, complete PEM validation, SSRF user-input gating,
weak-crypto filtering, deduplication, report permissions, and JSON/Markdown/SARIF output.

## Design

Full design documentation is available in [`docs/plans/`](docs/plans/):
- [Design Document](docs/plans/2026-03-08-security-audit-design.md) — architecture, scanning workflow, severity system, report structure
- [Implementation Plan](docs/plans/2026-03-08-security-audit-implementation.md) — 12-task build plan

## Contributing

Contributions welcome — especially new detection patterns. See the pattern format in [`references/secret-patterns.md`](skills/security-audit/references/secret-patterns.md) and add matching test cases to `tests/fixtures/`.

## License

Copyright 2026 Kuoshih Yang

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the full text.
