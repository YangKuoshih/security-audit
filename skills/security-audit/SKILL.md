---
name: security-audit
description: >
  Use this skill to scan a codebase for hardcoded secrets, leaked credentials,
  API keys, and security vulnerabilities. Invoke it whenever the user asks to
  "scan for secrets", "do a security audit", "find hardcoded keys or tokens",
  "check for leaked credentials", "audit the codebase for security issues",
  "find exposed API keys", "look for any security problems", or "make sure
  nothing sensitive is committed". Also use for incremental git-diff scanning
  ("only check what changed since main"), SARIF report generation for GitHub
  Code Scanning uploads, entropy-based detection of unknown secret formats, or
  any request to produce a severity-classified security report. Works with or
  without shell access. Prefer this skill over ad-hoc grep — it applies
  deterministic pattern scanning plus LLM false-positive filtering in a single
  repeatable workflow.
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

After completing Phase 3 analysis, produce an **augmented findings list** by adding three fields to each finding from Phase 2:
- `"confidence"`: `"High"`, `"Medium"`, or `"Low"` (see `references/severity-guide.md`)
- `"context"`: one sentence explaining the severity rating and confidence — e.g., *"Live Stripe key in a production deploy script; no placeholder markers present."*
- `"commit"`: the git commit hash and author for the line, if available from `git log -L <line>,<line>:<file>`; omit the field if git is unavailable

This augmented list is what gets passed to report generation. The scanner scripts do not add these fields — only the LLM can determine them.

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
