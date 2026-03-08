---
name: security-audit
description: >
  This skill should be used when the user asks to "scan for secrets",
  "security audit", "find hardcoded keys", "check for vulnerabilities",
  "scan for API keys", "find leaked credentials", "check for security issues",
  "audit codebase security", "find exposed secrets", or mentions security
  scanning of a codebase. Provides hybrid deterministic + LLM-assisted
  security scanning with severity-classified reports.
---

# Security Audit

Scan a codebase for hardcoded secrets, credentials, API keys, and common security vulnerabilities. Produce a severity-classified report with remediation guidance.

## Workflow

Execute the following four phases in order. Adapt based on environment capabilities detected in Phase 1.

### Phase 1: Setup

1. Detect environment capabilities:
   - Shell access: attempt `echo "shell-ok"` via bash
   - Git available: attempt `git --version`
   - Python available: attempt `python3 --version`
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
bash "${SKILL_DIR}/scripts/scan-secrets.sh" "<target_dir>" "${SKILL_DIR}/scripts/patterns.dat" "<output_file>"
```

For incremental mode, add `--base-branch <branch>`.

If bash scanning fails but Python is available, fall back to:

```bash
python3 "${SKILL_DIR}/scripts/scan-secrets.py" --target "<target_dir>" --patterns "${SKILL_DIR}/scripts/patterns.dat" --output "<output_file>"
```

**If no shell access (fallback path):**

Read files directly and apply pattern knowledge from `references/secret-patterns.md` and `references/vulnerability-patterns.md`. Scan each file for:
- Known secret formats (AWS keys, GitHub tokens, private keys, etc.)
- Vulnerability patterns (SQL injection sinks, XSS vectors, weak crypto)
- High-entropy strings that may be secrets

Output findings in the same format: file, line number, redacted match, pattern name, base severity.

### Phase 3: LLM Analysis

Review the raw findings from Phase 2 and for each finding:

1. **Filter false positives:**
   - Discard matches in test fixtures, example files, documentation, and comments that use placeholder values
   - Recognize common placeholders: `xxx`, `changeme`, `TODO`, `example`, `test`, `dummy`, `fake`, `sample`, `your-key-here`, `INSERT_KEY`
   - Check if the file path suggests non-production context: `test/`, `spec/`, `__tests__/`, `examples/`, `docs/`, `fixtures/`

2. **Classify severity** using `references/severity-guide.md`:
   - Start with the base severity from the pattern match
   - Downgrade if in test/example/docs files
   - Upgrade if in production config or deployment scripts
   - Downgrade if value matches placeholder patterns
   - Upgrade if paired with production URLs or live service endpoints

3. **Assign confidence:**
   - **High:** exact match on known secret format (e.g., `AKIA` prefix, `ghp_` prefix)
   - **Medium:** generic pattern match requiring context (e.g., password assignment, high-entropy string)
   - **Low:** heuristic match with uncertain value

4. **Generate remediation:** tailor advice to the repo's tech stack. Reference environment variables, secrets managers, or `.gitignore` as appropriate.

### Phase 4: Report Generation

**If shell access is available (Python required):**

```bash
python3 "${SKILL_DIR}/scripts/generate-report.py" "<findings_file>" "<format>" "<output_file>"
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

Group findings by severity (Critical, High, Medium, Low). Assign sequential IDs per severity tier (C-001, H-001, M-001, L-001). Never echo full secret values — always redact.

End with scan metadata: excluded directories, pattern counts, config source.

## Configuration Reference

The skill reads `.security-audit.yml` from the repo root. See `examples/security-audit.yml` for all supported options including:
- `scan.mode` — full, incremental, or paths
- `exclude.directories` / `exclude.files` — skip patterns
- `severity.minimum` — filter output by minimum severity
- `output.format` — markdown, sarif, or json
- `custom_patterns.secrets` — add custom regex patterns
- `custom_patterns.allowlist` — suppress known false positives

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
