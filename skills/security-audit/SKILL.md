---
name: security-audit
description: >
  Run a lightweight, local security scan of source repositories for hardcoded
  secrets, risky tracked files, and common vulnerability patterns, then triage
  redacted findings and produce Markdown, JSON, or SARIF. Use for secret scans,
  incremental security checks, repository security audits, or GitHub Code
  Scanning output. Do not use as a dependency-CVE scanner, a substitute for a
  full SAST/DAST assessment, or for ordinary non-security code review.
license: Apache-2.0
metadata:
  author: Kuoshih Yang
  version: "0.2.0"
  repository: https://github.com/YangKuoshih/security-audit
---

# Security Audit

Run deterministic local scanning first, then use agent reasoning to remove false
positives and prioritize remediation. Describe the result as a lightweight
pattern-based audit, not proof that a repository is secure.

The preferred scanner requires Python 3.10+. Bash and grep provide a reduced
fallback.

## Resolve the skill

Let `SKILL_DIR` be the directory containing this `SKILL.md`. Resolve every bundled
resource relative to it:

- scanner: `SKILL_DIR/scripts/scan-secrets.py`
- fallback scanner: `SKILL_DIR/scripts/scan-secrets.sh`
- patterns: `SKILL_DIR/scripts/patterns.dat`
- report generator: `SKILL_DIR/scripts/generate-report.py`

Do not assume a product-specific environment variable or installation layout.

## Safety invariants

- Keep scanning and reports local. Never transmit findings, source, or suspected
  secrets to web services, remote tools, connectors, or telemetry.
- Never print or quote raw matches. Scanner output is redacted; preserve that
  redaction in commentary, reports, logs, and errors.
- Do not open files flagged for secret or dangerous-file findings. Triage those
  from redacted JSONL, path, pattern, and severity only.
- For vulnerability-pattern findings, read only the small surrounding region
  needed to assess reachability. If the same file also has a secret finding, do
  not read it.
- Create temporary findings and custom-pattern files with owner-only permissions
  (`umask 077`) and remove temporary files when finished. Preserve a report only
  when the user requested a file.
- Never rotate, revoke, delete, purge git history, upload SARIF, or change source
  code unless the user separately asks for that mutation.

## Scan workflow

### 1. Establish scope

Use the user's requested target, mode, severity, and format. Defaults:

- target: current repository
- mode: full
- minimum severity: low
- format: markdown
- output: return a concise summary in conversation; write a report file only if
  requested or needed for SARIF/JSON

If `.security-audit.yml` exists at the target root, read it and map supported
settings as described below. User arguments override configuration.

Incremental mode must have a valid git base ref. If it does not, stop with the
scanner error; never silently replace an incremental scan with a full scan.

### 2. Run the deterministic scanner

Prefer Python and use a private temporary JSONL file:

```bash
umask 077
python3 "$SKILL_DIR/scripts/scan-secrets.py" \
  --target "$TARGET" \
  --patterns "$SKILL_DIR/scripts/patterns.dat" \
  --output "$FINDINGS"
```

Add only the flags required by scope or configuration:

- incremental: `--base-branch <ref>`
- extra excluded directories: `--exclude-dirs dir1,dir2`
- excluded file/path globs: `--exclude-files '*.min.js,fixtures/**'`
- severity threshold: `--severity-min low|medium|high|critical`
- custom pattern file: `--extra-patterns <path>` (repeatable)
- deterministic-only scan: `--no-entropy`
- skip tracked dangerous-file checks: `--no-dangerous-files`
- change the 5 MiB per-file safety limit: `--max-file-bytes <positive integer>`

The Python scanner does not follow symlinks, which prevents a repository from
causing an audit to read files outside the requested target.

If Python is unavailable, use the bash scanner. The bash fallback has a smaller
option surface; apply unsupported filtering during triage and disclose that in
scan metadata.

Do not combine scanning with network calls. Capture stderr because it contains
mode, file count, pattern count, and errors but no raw secret values.

### 3. Triage once

Read the redacted JSONL once and analyze all findings in one pass.

1. Remove clear placeholders and findings in fixtures/examples/docs when the
   path and redacted evidence make the intent unambiguous. Do not suppress a
   vendor-shaped credential only because it is in a test path.
2. Correlate related findings. The report generator removes common weaker
   duplicates (for example, entropy plus a vendor-specific token on one line),
   but preserve genuinely different risks at the same location.
3. Adjust severity by at most one tier from the scanner's base severity unless
   there is strong evidence:
   - downgrade for unmistakable placeholders or development-only context;
   - upgrade for production/deployment paths or broad production access;
   - never downgrade below Low or upgrade above Critical.
4. Assign confidence:
   - High: exact vendor format or unambiguously dangerous tracked file;
   - Medium: structured but context-dependent match;
   - Low: entropy or broad vulnerability heuristic.
5. For vulnerability findings only, assess whether untrusted input reaches the
   sink and label it `Exploitable`, `Likely exploitable`, `Needs investigation`,
   or `Likely false positive`.
6. Add a one-sentence `context` and tailored `remediation` where useful. For
   confirmed credentials, recommend both removal and rotation; remind the user
   that removing a value from the working tree does not erase git history.

When classification is unclear, consult only the relevant reference:

- secret formats and dangerous files: [references/secret-patterns.md](references/secret-patterns.md)
- vulnerability heuristics: [references/vulnerability-patterns.md](references/vulnerability-patterns.md)
- severity and deduplication: [references/severity-guide.md](references/severity-guide.md)

### 4. Report

For machine-readable output, pass the augmented redacted JSONL to:

```bash
python3 "$SKILL_DIR/scripts/generate-report.py" "$FINDINGS" sarif "$REPORT"
```

Formats are `markdown`, `json`, and `sarif`. Do not wrap JSON or SARIF in a
Markdown fence when the user requested machine-readable output.

For a conversational result, lead with:

- counts by severity and number of files scanned;
- the top three remediation actions;
- blast radius of the highest-confidence findings;
- important limitations or skipped checks;
- report path, if one was written.

A clean scan must say that no pattern findings were detected, not that the code
is secure. Recommend a dependency audit or deeper SAST only when relevant to the
user's goal.

## Configuration mapping

The example schema is in [examples/security-audit.yml](examples/security-audit.yml).
Apply it without editing the installed skill:

- `scan.mode` and `scan.base_branch` -> `--base-branch` for incremental mode.
- `scan.paths` -> scan each requested path and merge redacted JSONL findings.
- `exclude.directories` -> `--exclude-dirs`.
- `exclude.files` plus `exclude.patterns` -> `--exclude-files`.
- `severity.minimum` -> `--severity-min`.
- `output.format` and `output.file` -> report-generator arguments.
- `custom_patterns.secrets` -> write a private temporary tab-delimited pattern
  file (`SEVERITY<TAB>ID<TAB>NAME<TAB>REGEX`) and pass `--extra-patterns`.
- `custom_patterns.allowlist` entries with `file` -> merge into
  `--exclude-files`. Raw-value allowlists are intentionally unsupported because
  applying them outside the scanner would expose values to agent context.

Validate custom IDs as lowercase letters, digits, and hyphens; validate severity
against Critical/High/Medium/Low. If a custom regex is invalid, report the
scanner warning and do not claim it was applied.

## Boundaries

This skill does not inspect package vulnerability databases, execute application
code, probe running services, prove exploitability, or search deleted git history.
Use specialized tools for dependency CVEs, DAST, container/image scanning, IaC
policy engines, or historical-secret scanning when the requested assurance needs
those capabilities.
