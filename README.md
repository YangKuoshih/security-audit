# security-audit

A universal, tool-agnostic skill that scans codebases for hardcoded secrets, credentials, API keys, and common security vulnerabilities. Designed to work across any agentic AI platform.

## Features

- **Hybrid scanning** — deterministic pattern matching + LLM-assisted reasoning for low false positives
- **Secrets detection** — AWS keys, GCP credentials, GitHub tokens, private keys, database connection strings, JWT secrets, and more
- **Vulnerability scanning** — SQL injection, XSS, insecure deserialization, weak crypto, exposed debug endpoints
- **Incremental scanning** — scan only changed files via git diff for fast CI/PR workflows
- **Dual output** — Markdown reports for human review, SARIF/JSON for CI integration
- **Configurable** — custom patterns, allowlists, severity thresholds via `.security-audit.yml`
- **Tool-agnostic** — works on Claude Code, Cursor, Windsurf, Cline, and any agentic platform

## Quick Start

### Installation

**Via skills registry:**
```bash
claude plugin add security-audit
```

**Via git:**
```bash
git clone https://github.com/your-org/security-audit.git
# Copy to your platform's skills/plugins directory
```

### Usage

```
/security-audit                    # full scan, markdown output
/security-audit --incremental      # scan changed files only (git diff)
/security-audit --format sarif     # SARIF output for CI
/security-audit --severity high    # only Critical + High findings
/security-audit --path src/        # scan specific directory
```

## Severity Levels

| Severity | Description | Examples |
|----------|-------------|---------|
| **Critical** | Credentials granting broad/production access. Immediate risk. | AWS root keys, private keys, database root passwords |
| **High** | Scoped credentials or tokens. | GitHub PATs, Slack tokens, SMTP credentials |
| **Medium** | Suspected secrets or confirmed vulnerability patterns. | High-entropy strings, SQL injection sinks, XSS vectors |
| **Low** | Best practice violations, no direct exploit path. | Debug mode in production, insecure HTTP endpoints |

## Configuration

Create a `.security-audit.yml` in your repo root:

```yaml
scan:
  mode: full              # full | incremental | paths
  base_branch: main       # for incremental mode

exclude:
  directories:
    - node_modules
    - venv
  patterns:
    - "test_fixtures/**"

severity:
  minimum: medium         # only report findings >= this level

output:
  format: markdown        # markdown | sarif | json

custom_patterns:
  secrets:
    - name: "Internal Token"
      regex: "MYCOMPANY_[A-Z0-9]{32}"
      severity: critical
  allowlist:
    - file: "docs/examples.md"
      reason: "Placeholder keys"
```

## Report Example

```
# Security Audit Report

Scan date: 2026-03-08 | Files scanned: 342
Findings: 2 Critical, 5 High, 3 Medium, 1 Low

## Critical (2)

### [C-001] AWS Access Key Found
- File: src/config/aws.js:14
- Commit: a3f8c2d (2026-02-15, dev@example.com)
- Confidence: High
- Remediation: Move to environment variable or secrets manager. Rotate immediately.
```

## Skill Structure

```
security-audit/
├── SKILL.md                 # Orchestration and workflow
├── references/
│   ├── secret-patterns.md   # Regex patterns for secrets
│   ├── vulnerability-patterns.md
│   └── severity-guide.md
├── scripts/
│   ├── scan-secrets.sh      # Bash scanner (primary)
│   ├── scan-secrets.py      # Python fallback
│   └── generate-report.sh   # Report formatter
└── examples/
    ├── sample-report.md
    └── sample-report.sarif.json
```

## Design Documentation

See [docs/plans/2026-03-08-security-audit-design.md](docs/plans/2026-03-08-security-audit-design.md) for the full design document.

## Contributing

Contributions are welcome. See [LICENSE](LICENSE) for details.

## License

Copyright 2026 Tony Yang

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the full license text.
