---
name: security-audit
description: >
  Scans source code files for hardcoded secrets, leaked credentials, and
  security vulnerability patterns, then produces a severity-classified audit
  report (Markdown, SARIF, or JSON). Use this skill — not ad-hoc grep — when
  the user wants to: scan for hardcoded secrets or API keys, do a security
  audit, find leaked credentials or tokens, check whether sensitive values were
  committed, run an incremental scan of files changed since a branch, generate
  a SARIF file for GitHub Code Scanning, or get a report of findings grouped by
  Critical / High / Medium / Low. Do NOT use for: fixing individual bugs the
  user has already identified, writing CI/CD pipeline config, checking package
  dependency CVEs (use a dependency scanner for that), or general code review
  without a security focus.
license: Apache-2.0
compatibility: Requires bash and grep for primary scanning, or Python 3 as fallback. Works without shell access in degraded mode.
metadata:
  author: Kuoshih Yang
  version: "0.1.0"
  repository: https://github.com/YangKuoshih/security-audit
---

# Security Audit

Scan a codebase for hardcoded secrets, credentials, API keys, and common security vulnerabilities. Produce a severity-classified report with remediation guidance.

## Path Resolution

Throughout this skill, `${CLAUDE_PLUGIN_ROOT}` refers to the directory where this plugin is installed. Claude Code sets this automatically when loading a plugin. If the variable is not available in your environment, resolve it as the parent directory of the `skills/` folder containing this file (i.e., the repository root of the security-audit plugin).

## Secret Data Safety

**This skill MUST NOT exfiltrate discovered secrets.** All findings are for the user's eyes only — to help them remediate issues in their own codebase.

Rules that apply to ALL phases:

1. **Never read files known or suspected to contain secrets into LLM context.** When Phase 2 flags a file, do NOT use the Read tool to open that file. Work only from the redacted JSONL output.
2. **Never echo, log, or output raw secret values.** All matches in scanner output are already redacted. If you must reference a finding, use the redacted form only.
3. **Never send findings or file contents to external services** — no web fetches, no API calls, no MCP tool calls that transmit finding data outside the local machine.
4. **The report is a local file.** Do not offer to upload, share, or transmit the report. The user decides what to do with it.
5. **No-shell fallback caution:** If you must read source files directly (no shell access), do NOT read files that match dangerous file patterns (`.tfstate`, `.pem`, `.key`, `.p12`, `.pfx`, `.jks`, `credentials.json`, `service-account*.json`). For other files, scan line by line and discard each line's content from your response after checking it — never quote raw secret values in your output.

## Workflow

Execute the following four phases in order. Adapt based on environment capabilities detected in Phase 1.

### Phase 1: Setup

1. Detect environment capabilities:
   - Shell access: attempt `echo "shell-ok"` via bash
   - Git available: attempt `git --version`
   - Python available: attempt `python3 --version` or `python --version` (use whichever works)
2. Check for `.security-audit.yml` in the repo root. If present, read and apply configuration. If absent, use defaults:
   - Scan mode: `full`
   - Excluded dirs: `node_modules`, `venv`, `.git`, `dist`, `build`, `__pycache__`, `.next`, `vendor`, `target`
   - Excluded files: `*.min.js`, `*.lock`, `*.map`
   - Severity minimum: all
   - Output format: markdown
3. Determine scan mode:
   - **Full:** scan all files
   - **Incremental:** use `git diff --name-only <base_branch>...HEAD` to get changed files
   - **Paths:** scan only specified directories
4. Build the file list. If git is available, use `git ls-files`. Otherwise, walk the directory tree with exclusions.

### Phase 2: Pattern Scanning

**If shell access is available (primary path):**

Run the bash scanner script:

```bash
bash "${CLAUDE_PLUGIN_ROOT}/skills/security-audit/scripts/scan-secrets.sh" "<target_dir>" "${CLAUDE_PLUGIN_ROOT}/skills/security-audit/scripts/patterns.dat" "<output_file>"
```

For incremental mode, add `--base-branch <branch>`.

If bash scanning fails but Python is available, fall back to (use `python3` or `python` depending on what is available):

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/skills/security-audit/scripts/scan-secrets.py" --target "<target_dir>" --patterns "${CLAUDE_PLUGIN_ROOT}/skills/security-audit/scripts/patterns.dat" --output "<output_file>"
```

**If no shell access (fallback path):**

Read files directly and apply pattern knowledge from `references/secret-patterns.md` and `references/vulnerability-patterns.md`. **Important: follow Secret Data Safety rules** — skip files matching dangerous file patterns entirely (`.tfstate`, `.pem`, `.key`, `.p12`, `.pfx`, `.jks`, `credentials.json`, `service-account*.json`) and flag them as file-level findings without reading their contents. For other files, scan for:
- Known secret formats (AWS keys, GitHub tokens, private keys, etc.)
- Vulnerability patterns (SQL injection sinks, XSS vectors, weak crypto)
- High-entropy strings that may be secrets

When a secret is found, **redact it immediately** — never include the raw value in your output. Output findings in the same format: file, line number, redacted match, pattern name, base severity.

### Phase 2b: Dangerous File Type Scan

This phase runs automatically as part of the scanner scripts (both bash and Python). It detects files that should never be committed to git, regardless of their contents.

**How it works:** Uses `git ls-files --cached` to check only tracked files. Gitignored files are NOT flagged. Results are appended to the same output file as Phase 2 findings, using `line: 0` to indicate file-level findings.

**Detected file types:** Terraform state (`.tfstate`), private keys (`.pem`, `.key`, `.p12`, `.pfx`), Java keystores (`.jks`), cloud credentials (`credentials.json`, `service-account*.json`), Terraform cache (`.terraform/`), database files (`.sqlite`, `.db`), Terraform output files, and files with "secret" in the name.

See `references/secret-patterns.md` § Dangerous File Types for the complete list with pattern IDs and descriptions.

**If no shell access (fallback path):**

Use `git ls-files --cached` knowledge to ask the user about tracked files matching dangerous patterns. Flag any matches with `line: 0` and `match: "(entire file)"` in findings.

### Phase 3: LLM Analysis

Review the **redacted** findings from Phase 2 (the JSONL output file). Follow Secret Data Safety rules — work from scanner output only, not original source files, for secret findings.

#### 3a. Tech Stack Detection

Before analyzing findings, identify the project's tech stack by checking for:
- `package.json` → Node.js (recommend: `process.env`, AWS Secrets Manager, GitHub Secrets)
- `requirements.txt` / `pyproject.toml` → Python (recommend: `os.environ`, python-dotenv, Vault)
- `go.mod` → Go (recommend: `os.Getenv`, Vault, cloud-native secrets)
- `pom.xml` / `build.gradle` → Java (recommend: Spring Vault, AWS Secrets Manager)
- `Gemfile` → Ruby (recommend: `ENV[]`, dotenv, Rails credentials)
- `*.tf` files → Terraform (recommend: remote state, variable files, Vault provider)
- `Dockerfile` / `docker-compose.yml` → containerized (recommend: Docker secrets, not build args for secrets)

Use this context to tailor all remediation advice to the actual stack.

#### 3b. Cross-Finding Correlation

Group related findings before classifying:
- **Same credential, multiple files**: If the same pattern ID matches in multiple files with identical redacted prefixes, consolidate into a single finding with all locations listed. Severity = max of all locations.
- **Related infrastructure**: If Terraform state + Terraform output + cloud credentials are all found, note these form a compound exposure (attacker gets infrastructure map + credentials).
- **Cascading access**: If a cloud provider key + a database connection string are both found, note the blast radius (cloud key may grant broader access than the DB string alone).

#### 3c. Finding Triage

For each finding (or correlated group):

1. **Filter false positives** using redacted match text and file path context:
   - Discard matches in test/example/docs paths with placeholder patterns
   - For dangerous file-type findings (`line: 0`), check if file is in `examples/`, `docs/`, or `test/` for potential downgrade
   - Use `references/vulnerability-patterns.md` § Framework-Specific False Positive Notes to evaluate vuln findings

2. **Classify severity** using `references/severity-guide.md`:
   - Start with base severity from pattern match
   - Apply contextual adjustments (file path, production indicators)
   - For correlated groups, use the highest severity in the group

3. **Assess exploitability** (vulnerability findings only — NOT secret findings):
   - For vuln findings (SQL injection, XSS, command injection, SSRF), you MAY read the surrounding function (~10 lines above/below) to assess whether user input can reach the sink
   - Do NOT read files flagged for secret findings
   - Rate: Exploitable / Likely Exploitable / Needs Investigation / Likely False Positive

4. **Assign confidence**: High (vendor-specific prefix or unambiguous file type), Medium (generic pattern needing context), Low (heuristic match)

#### 3d. Executive Summary

Before the detailed findings, produce a prioritized summary:

1. **Top 3 actions** — the three most impactful things to fix first, with one sentence each explaining why
2. **Blast radius assessment** — what an attacker could access if the worst findings are exploited
3. **Positive observations** — note good security practices observed (e.g., "secrets are properly gitignored", "no production credentials found")

#### 3e. Augmented Findings

After triage, produce an **augmented findings list** by adding three fields to each finding:
- `"confidence"`: `"High"`, `"Medium"`, or `"Low"`
- `"context"`: one sentence explaining the severity rating and confidence — e.g., *"Live Stripe key in a production deploy script; no placeholder markers present."*
- `"commit"`: the git commit hash and author for the line, if available from `git log -L <line>,<line>:<file>`; omit if git is unavailable

This augmented list is what gets passed to report generation.

### Phase 4: Report Generation

**If shell access is available (Python required):**

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/skills/security-audit/scripts/generate-report.py" "<findings_file>" "<format>" "<output_file>"
```

Supported formats: `markdown`, `sarif`, `json`. Use `-` as output file for stdout.

**If no shell access:**

Format the report directly following this structure:

```markdown
# Security Audit Report

**Scan date:** <date>
**Mode:** <full|incremental>
**Files scanned:** <count>
**Findings:** <N> Critical, <N> High, <N> Medium, <N> Low

---

## Critical (<count>)

### [C-001] <Pattern Name>
- **File:** `<path>:<line>`
- **Commit:** `<hash>` (<date>, <author>) [if git available]
- **Pattern:** <pattern name>
- **Match:** <redacted>
- **Confidence:** <High|Medium|Low>
- **Context:** <LLM assessment>
- **Remediation:** <actionable steps>
```

Group findings by severity (Critical, High, Medium, Low). Assign sequential IDs per severity tier (C-001, H-001, M-001, L-001). **Never echo full secret values — always use the redacted form from scanner output.** For file-level findings (`line: 0`), display as `<path>:0 (entire file)` and include the file-type-specific remediation from `references/secret-patterns.md`.

End with scan metadata: excluded directories, pattern counts, config source.

## Configuration Reference

The skill reads `.security-audit.yml` from the repo root. See `examples/security-audit.yml` for all supported options including:
- `scan.mode` — full, incremental, or paths
- `exclude.directories` / `exclude.files` — skip patterns
- `severity.minimum` — filter output by minimum severity
- `output.format` — markdown, sarif, or json
- `custom_patterns.secrets` — add custom regex patterns
- `custom_patterns.allowlist` — suppress known false positives

**Applying configuration to script invocations:**
- `exclude.directories` → pass as `--exclude-dirs` (comma-separated) to both scanner scripts
- `scan.mode: incremental` + `scan.base_branch` → pass as `--base-branch` to scanner scripts
- `output.format` → pass as the `<format>` argument to `generate-report.py`
- `severity.minimum` — filter applied by the LLM during Phase 3; not a script flag
- `exclude.patterns` (glob patterns) — not supported by the scanner scripts; apply filtering manually before invoking the scripts, or skip files that match during Phase 3 analysis
- `custom_patterns.secrets` — not passed to scanner scripts at runtime; to use custom patterns with the scripts, add them to `scripts/patterns.dat` in the format: `<SEVERITY>\t<id>\t<name>\t<regex>`
- `custom_patterns.allowlist` — applied by the LLM during Phase 3; check each finding's file path and matched value against the allowlist and suppress matching findings

## Additional Resources

### Reference Files

Consult these for detailed patterns and classification rules:
- **`references/secret-patterns.md`** — regex patterns for 20+ secret types organized by severity
- **`references/vulnerability-patterns.md`** — OWASP-style vulnerability detection patterns
- **`references/severity-guide.md`** — severity tier definitions and contextual adjustment rules

### Scripts

- **`scripts/scan-secrets.sh`** — primary bash-based pattern scanner
- **`scripts/scan-secrets.py`** — Python fallback with entropy detection
- **`scripts/patterns.dat`** — compiled patterns file used by scanner scripts
- **`scripts/generate-report.py`** — report formatter (Markdown, SARIF, JSON) with built-in remediation guidance

### Examples

- **`examples/sample-report.md`** — example Markdown report
- **`examples/sample-report.sarif.json`** — example SARIF output
- **`examples/security-audit.yml`** — example configuration file
