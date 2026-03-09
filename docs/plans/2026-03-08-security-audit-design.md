# Security Audit Skill — Design Document

**Date:** 2026-03-08
**Status:** Approved
**Author:** Kuoshih Yang

---

## 1. Overview

**Name:** `security-audit`
**Type:** Universal skill (tool-agnostic, agentic platform portable)
**Distribution:** agentskills.io / skills.sh / git clone
**Invocation:** `/security-audit` or skill trigger via description matching

**Purpose:** Scan entire codebases for hardcoded secrets, credentials, API keys, and common security vulnerabilities (OWASP-style). Produces structured reports with severity-classified findings and remediation guidance.

### Core Principles

- **Hybrid scanning:** deterministic pattern matching + LLM-assisted reasoning
- **Local-first:** shell scripts for fast scanning, graceful pure-prompt fallback for sandboxed agents
- **Incremental scanning:** git diff support for CI/PR workflows
- **Dual output:** Markdown (default) for human review, SARIF/JSON for tool integration
- **Tool-agnostic:** works on any agentic platform (Claude Code, Cursor, Windsurf, Cline, etc.)

### Scope

**In scope (v1):**
- Hardcoded secrets detection (API keys, tokens, passwords, private keys, connection strings)
- Common vulnerability patterns (SQL injection, XSS, insecure deserialization, weak crypto, exposed debug endpoints)

**Out of scope (v2+):**
- Dependency/CVE scanning (tools like `npm audit`, `pip-audit` already cover this)
- Compliance mapping (SOC2, PCI-DSS rule references)

---

## 2. Architecture

### Skill Structure

```
security-audit/
├── SKILL.md                          # Orchestration, prompts, workflow (1500-2000 words)
├── references/
│   ├── secret-patterns.md            # Regex patterns for secrets detection
│   ├── vulnerability-patterns.md     # OWASP-style vulnerability patterns
│   └── severity-guide.md             # Severity classification rules
├── scripts/
│   ├── scan-secrets.sh               # Bash pattern scanner (primary)
│   ├── scan-secrets.py               # Python fallback scanner
│   └── generate-report.sh            # Report formatter (Markdown/SARIF)
└── examples/
    ├── sample-report.md              # Example Markdown report
    └── sample-report.sarif.json      # Example SARIF output
```

### Design Rationale

- **SKILL.md stays lean** (1,500-2,000 words) — orchestration and workflow only
- **Heavy content in references/** — pattern databases and severity rules loaded as needed
- **Scripts handle deterministic work** — pattern scanning via shell, not LLM token-burning
- **Progressive disclosure** — metadata always loaded, SKILL.md on trigger, references/scripts as needed
- **Follows skill development best practices** — folder structure with SKILL.md, references/, scripts/, examples/

---

## 3. Scanning Workflow

### Phase 1: Setup & Configuration

- Detect environment capabilities (shell access? git available? python?)
- Load config from `.security-audit.yml` if present, otherwise use defaults
- Determine scan mode: full scan, incremental (diff against base branch), or target specific paths
- Build file list: respect `.gitignore`, skip binaries, skip vendor dirs (`node_modules`, `venv`, `.git`, `dist`, `build`, `__pycache__`)

### Phase 2: Pattern Scanning (Deterministic)

- Execute `scripts/scan-secrets.sh` (or Python fallback) against the file list
- Match against pattern databases in `references/secret-patterns.md` and `references/vulnerability-patterns.md`
- Categories scanned:
  - **Secrets:** AWS keys, GCP credentials, GitHub/GitLab tokens, Slack tokens, private keys (RSA/SSH/PGP), database connection strings, JWT secrets, generic high-entropy strings
  - **Vulnerabilities:** SQL injection sinks, XSS vectors, insecure deserialization, weak crypto usage, hardcoded passwords in config, exposed debug/admin endpoints, insecure HTTP usage
- Output raw findings as structured intermediate data (file, line, match, pattern category)

### Phase 3: LLM Analysis (Reasoning)

- Review raw findings to filter false positives (e.g., example keys in docs, test fixtures, placeholder values)
- Assess context: is this a real secret or a dummy? Is this SQL injection actually reachable?
- Classify severity: Critical / High / Medium / Low
- Assign confidence level: High / Medium / Low
- Generate remediation suggestions per finding, tailored to the repo's tech stack

### Phase 4: Report Generation

- Produce Markdown report (default) with: executive summary, findings by severity, file locations, remediation steps
- Optionally produce SARIF/JSON for CI integration
- Include scan metadata: timestamp, scan mode, files scanned, patterns used

### Fallback Mode (No Shell Access)

- Skip Phase 2 scripts
- LLM reads files directly and applies pattern knowledge from references
- Slower and more token-intensive, but functional on sandboxed/cloud agents

---

## 4. Configuration

An optional `.security-audit.yml` file in the repo root customizes scan behavior:

```yaml
# .security-audit.yml
scan:
  mode: full              # full | incremental | paths
  base_branch: main       # for incremental mode
  paths:                  # for paths mode
    - src/
    - config/

exclude:
  directories:
    - node_modules
    - venv
    - .git
    - dist
    - build
    - __pycache__
  files:
    - "*.min.js"
    - "*.lock"
  patterns:
    - "test_fixtures/**"

severity:
  minimum: medium         # only report findings >= this level

output:
  format: markdown        # markdown | sarif | json
  file: security-report   # output filename (extension added automatically)

custom_patterns:
  secrets:
    - name: "Internal API Token"
      regex: "MYCOMPANY_[A-Z0-9]{32}"
      severity: critical
  allowlist:              # known false positives to suppress
    - file: "docs/examples.md"
      reason: "Example placeholder keys"
    - pattern: "EXAMPLE_KEY_.*"
```

When no config file exists, sensible defaults apply: full scan, skip standard vendor directories, Markdown output, all severities reported.

---

## 5. Severity Classification

| Severity | Criteria | Examples |
|----------|----------|---------|
| **Critical** | Credentials granting broad or production access. Immediate exploitation risk. | AWS root access keys, cloud service account JSON keys, RSA/SSH private keys, database root passwords, Stripe live secret keys |
| **High** | Scoped credentials or tokens. Exploitation requires some context. | GitHub PATs, Slack tokens, SMTP credentials, JWT signing secrets, database connection strings |
| **Medium** | Suspected secrets needing verification, or confirmed vulnerability patterns. | High-entropy strings in config, SQL injection sinks, XSS vectors, insecure deserialization, weak crypto usage |
| **Low** | Best practice violations with no direct exploit path. | Debug mode enabled in production, insecure HTTP for non-sensitive endpoints, overly permissive CORS |

### Contextual Adjustment Logic

The LLM adjusts base severity based on context:

- **Downgrade** if found in test/example/docs files
- **Upgrade** if found in production config or deployment scripts
- **Downgrade** if value looks like a placeholder (`xxx`, `changeme`, `TODO`)
- **Upgrade** if paired with production URLs or live service endpoints

---

## 6. Report Structure

### Markdown Report (Default)

```markdown
# Security Audit Report

**Scan date:** 2026-03-08
**Mode:** full
**Files scanned:** 342
**Findings:** 2 Critical, 5 High, 3 Medium, 1 Low

---

## Critical (2)

### [C-001] AWS Access Key Found
- **File:** `src/config/aws.js:14`
- **Commit:** `a3f8c2d` (2026-02-15, tony.yang)
- **Pattern:** AWS Access Key ID
- **Match:** `AKIA...` (redacted)
- **Confidence:** High
- **Context:** Hardcoded in production config, paired with live S3 endpoint
- **Remediation:** Move to environment variable or secrets manager. Rotate this key immediately.

## High (5)
...

## Medium (3)
...

## Low (1)
...

---

## Scan Configuration
- Excluded: node_modules, .git, dist
- Patterns: 147 secret patterns, 23 vulnerability patterns
- Config: .security-audit.yml (custom)
```

### Report Features

- **Finding IDs** (C-001, H-001, M-001, L-001) for tracking and ticket referencing
- **Redacted matches** — never echo full secrets into the report
- **Confidence levels** (High/Medium/Low) to flag findings needing manual verification
- **Git blame info** (commit hash, date, author) when git is available
- **Actionable remediation** tailored to the repo's tech stack
- **Summary count at top** for quick triage
- **Scan metadata at bottom** for reproducibility

### SARIF Output

SARIF 2.1.0 schema output includes:
- `tool.driver` with rule definitions (required by GitHub Code Scanning)
- `results[]` with `ruleId`, `level`, `locations`, and `message`
- Compatible with GitHub Code Scanning, VS Code SARIF Viewer, and other SARIF consumers

---

## 7. Installation & Usage

### Installation Methods

1. **Skills registry:** `claude plugin add security-audit` (or platform equivalent)
2. **Git clone:** Clone repo into plugins/skills directory
3. **First-run bootstrap:** Skill verifies prerequisites (grep, python3) on first invocation

### Usage

```
/security-audit                    # full scan, markdown output
/security-audit --incremental      # scan changed files only (git diff)
/security-audit --format sarif     # SARIF output for CI
/security-audit --severity high    # only Critical + High findings
/security-audit --path src/        # scan specific directory
```

### Target Environments

- **Primary:** Developer local machines with shell access (Claude Code, Cursor, Windsurf, Cline)
- **Secondary:** Cloud/sandboxed agents via pure-prompt fallback mode (degraded performance, full functionality)

---

## 8. Audience Considerations

### Solo Developers

- Concise, actionable reports without noise
- Confidence levels prevent wasted time chasing false positives
- Finding IDs for tracking fixes in commit messages
- Zero-config defaults that work out of the box

### Enterprise Teams

- Commit attribution for incident response workflows
- SARIF output feeds existing security dashboards and CI pipelines
- Finding IDs map to Jira/Linear tickets
- Confidence levels help triage queues
- Allowlist config for suppressing known findings across repos
- Customizable patterns for internal secret formats
