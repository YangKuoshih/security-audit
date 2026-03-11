<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/header-dark.svg">
  <img alt="security-audit — Find secrets before attackers do." src="assets/header.svg" width="680">
</picture>

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-58%20passing-brightgreen.svg)](#testing)
[![Patterns](https://img.shields.io/badge/patterns-44%20rules-orange.svg)](skills/security-audit/scripts/patterns.dat)

</div>

---

## Why

Every leaked secret starts the same way — a key hardcoded "just for testing" that makes it to production. Existing tools catch some of these, but they're standalone binaries that don't understand your code's context.

**security-audit** combines deterministic pattern scanning with LLM-powered reasoning. The scanner finds candidates fast. The AI filters false positives, understands context, and writes remediation steps tailored to your stack.

## What It Catches

<table>
<tr>
<td width="50%">

**Secrets** — 34 patterns validated against [GitLeaks](https://github.com/gitleaks/gitleaks)

- AWS, GCP, Azure credentials
- GitHub, GitLab, Slack tokens
- Stripe, Twilio, SendGrid API keys
- Database connection strings
- Private keys (RSA, SSH, PGP)
- OpenAI, Heroku, NPM, PyPI tokens
- JWT tokens and signing secrets
- High-entropy strings (Shannon entropy)

</td>
<td width="50%">

**Vulnerabilities** — 15 patterns mapped to [OWASP Top 10](https://owasp.org/Top10/)

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
</table>

## Quick Start

**Install via skills registry:**
```bash
claude plugin add security-audit
```

**Or clone and use locally:**
```bash
git clone https://github.com/YangKuoshih/security-audit.git

# Use as a Claude Code plugin (from any project directory)
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

## How It Works

```
                ┌─────────────────────────────────────────────────┐
                │              /security-audit                     │
                └────────────────────┬────────────────────────────┘
                                     │
                     ┌───────────────┼───────────────┐
                     ▼               ▼               ▼
              ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
              │   Phase 1   │ │   Phase 2   │ │   Phase 3   │
              │   Setup     │ │   Scan      │ │   Analyze   │
              │             │ │             │ │             │
              │ Detect env  │ │ 44 regex    │ │ LLM filters │
              │ Load config │ │ patterns    │ │ false pos.  │
              │ Build file  │ │ + entropy   │ │ Classifies  │
              │ list        │ │ detection   │ │ severity    │
              └──────┬──────┘ └──────┬──────┘ └──────┬──────┘
                     │               │               │
                     └───────────────┼───────────────┘
                                     ▼
                          ┌─────────────────────┐
                          │      Phase 4        │
                          │      Report         │
                          │                     │
                          │  Markdown / SARIF   │
                          │  / JSON output      │
                          └─────────────────────┘
```

**Shell available?** Runs `scan-secrets.sh` (bash/grep) or `scan-secrets.py` (Python with entropy detection) for fast deterministic scanning, then the LLM analyzes results.

**No shell?** The LLM reads files directly using the pattern knowledge from `references/` — slower but works on sandboxed platforms.

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

The LLM adjusts severity based on context — findings in test files get downgraded, findings in deployment scripts get upgraded. See [`references/severity-guide.md`](skills/security-audit/references/severity-guide.md) for the full ruleset.

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
│       ├── SKILL.md                    # LLM orchestration and workflow
│       ├── references/
│       │   ├── secret-patterns.md      # 34 patterns (validated against GitLeaks)
│       │   ├── vulnerability-patterns.md   # 15 patterns (OWASP Top 10)
│       │   └── severity-guide.md       # Classification rules + adjustments
│       ├── scripts/
│       │   ├── scan-secrets.sh         # Bash scanner (grep, PCRE/ERE)
│       │   ├── scan-secrets.py         # Python fallback + entropy detection
│       │   ├── patterns.dat            # 44 compiled patterns for scanners
│       │   └── generate-report.py      # Report generator (MD/SARIF/JSON)
│       └── examples/
│           ├── sample-report.md        # Example Markdown output
│           ├── sample-report.sarif.json    # Example SARIF output
│           └── security-audit.yml      # Example configuration
├── tests/
│   ├── test-e2e.sh                     # 58-assertion integration test
│   └── fixtures/sample-repo/           # Test files with known secrets/vulns
├── docs/plans/                         # Design documents
├── LICENSE                             # Apache 2.0
├── NOTICE                              # Attribution
└── README.md
```

## Testing

> **Note:** The test suite (`tests/`) has been designed but not yet committed to this repository. The fixture files contain realistic fake credentials that require `.github/secret_scanning.yml` paths-ignore to commit safely — that config is already in place. Contributions to add `tests/test-e2e.sh` and `tests/fixtures/` are welcome.

Once committed, run with:

```bash
bash tests/test-e2e.sh
```

Planned coverage:
- Bash scanner (21 assertions) — pattern detection, safe file validation, output format, redaction
- Python scanner (6 assertions) — parity with bash, entropy detection, safe file
- Report generation (25 assertions) — Markdown structure, SARIF 2.1.0 compliance, JSON validity
- Self-scan (1 assertion) — our own code contains zero Critical findings

## Design

Full design documentation is available in [`docs/plans/`](docs/plans/):
- [Design Document](docs/plans/2026-03-08-security-audit-design.md) — architecture, scanning workflow, severity system, report structure
- [Implementation Plan](docs/plans/2026-03-08-security-audit-implementation.md) — 12-task build plan

## Contributing

Contributions welcome — especially new detection patterns. See the pattern format in [`references/secret-patterns.md`](skills/security-audit/references/secret-patterns.md) and add matching test cases to `tests/fixtures/`.

## License

Copyright 2026 Kuoshih Yang

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the full text.
