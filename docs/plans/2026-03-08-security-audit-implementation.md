# Security Audit Skill — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build the `security-audit` universal skill that scans codebases for hardcoded secrets and common vulnerabilities, producing severity-classified reports.

**Architecture:** A skill folder with SKILL.md (orchestration/prompts), references/ (pattern databases), scripts/ (bash/python scanners), and examples/ (sample reports). Hybrid approach: deterministic pattern scanning via scripts, LLM reasoning for false-positive filtering and severity classification.

**Tech Stack:** Bash (primary scanner), Python 3 (fallback scanner), YAML (config), Markdown + SARIF 2.1.0 (output formats)

**Design Doc:** `docs/plans/2026-03-08-security-audit-design.md`

---

## Task 1: Create Skill Directory Structure and SKILL.md

**Files:**
- Create: `skill/SKILL.md`
- Create: `skill/references/` (empty dir)
- Create: `skill/scripts/` (empty dir)
- Create: `skill/examples/` (empty dir)

**Step 1: Create the directory structure**

```bash
mkdir -p skill/{references,scripts,examples}
```

**Step 2: Write SKILL.md**

Create `skill/SKILL.md` with:
- YAML frontmatter: `name: security-audit`, `description` with third-person trigger phrases (`"This skill should be used when the user asks to 'scan for secrets', 'security audit', 'find hardcoded keys', 'check for vulnerabilities', 'scan for API keys', 'find leaked credentials', or mentions security scanning of a codebase."`)
- Body sections (target 1,500-2,000 words):
  1. **Purpose** — one paragraph describing what the skill does
  2. **Workflow** — the 4-phase scanning process (Setup, Pattern Scan, LLM Analysis, Report)
  3. **Environment Detection** — instructions for detecting shell/git/python availability
  4. **Running the Scanner** — how to invoke `scripts/scan-secrets.sh` or fallback to `scripts/scan-secrets.py`, or pure-prompt mode
  5. **Analyzing Results** — LLM instructions for false-positive filtering, severity classification, confidence assignment
  6. **Report Generation** — how to invoke `scripts/generate-report.sh` or format manually
  7. **Configuration** — how to read and apply `.security-audit.yml`
  8. **Additional Resources** — reference file pointers and example file pointers

**Step 3: Verify SKILL.md is under 2,000 words**

```bash
wc -w skill/SKILL.md
```

Expected: 1,500-2,000 words.

**Step 4: Commit**

```bash
git add skill/
git commit -m "feat: add SKILL.md and skill directory structure"
```

---

## Task 2: Create Secret Patterns Reference

**Files:**
- Create: `skill/references/secret-patterns.md`

**Step 1: Write the secret patterns file**

Create `skill/references/secret-patterns.md` with categorized regex patterns. Each entry should have:
- Pattern name
- Regex
- Base severity (Critical/High/Medium)
- Description
- Example match (redacted/fake)

Categories to include:

**Critical patterns:**
- AWS Access Key ID: `(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`
- AWS Secret Access Key: `(?i)aws(.{0,20})?(?-i)['\"][0-9a-zA-Z\/+]{40}['\"]`
- RSA/SSH/PGP Private Keys: `-----BEGIN (RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY( BLOCK)?-----`
- GCP Service Account JSON: `"type"\s*:\s*"service_account"`
- Stripe Live Secret Key: `sk_live_[0-9a-zA-Z]{24,}`
- Database root passwords: `(?i)(root|admin).*password\s*[:=]\s*['\"][^'\"]{8,}['\"]`

**High patterns:**
- GitHub PAT: `ghp_[0-9a-zA-Z]{36}` (classic), `github_pat_[0-9a-zA-Z_]{82}` (fine-grained)
- GitLab PAT: `glpat-[0-9a-zA-Z\-\_]{20}`
- Slack Token: `xox[baprs]-[0-9a-zA-Z\-]{10,}`
- Slack Webhook: `https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[a-zA-Z0-9]{24}`
- SMTP/Sendgrid: `SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}`
- Twilio API Key: `SK[0-9a-fA-F]{32}`
- JWT Secret: `(?i)(jwt|token)[\s_-]*(secret|key)\s*[:=]\s*['\"][^'\"]{8,}['\"]`
- Database connection strings: `(?i)(mongodb|postgres|mysql|redis|mssql):\/\/[^\s'\"]{10,}`
- Generic password assignment: `(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{8,}['\"]`
- Azure Storage Key: `DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+\/=]{88}`
- Heroku API Key: `(?i)heroku(.{0,20})?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`

**Medium patterns:**
- Generic API key assignment: `(?i)(api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*['\"][0-9a-zA-Z]{16,}['\"]`
- Generic secret assignment: `(?i)(secret|token|credential)\s*[:=]\s*['\"][^'\"]{12,}['\"]`
- Base64-encoded secrets (long): `(?i)(secret|key|token|password)\s*[:=]\s*['\"][A-Za-z0-9+\/=]{40,}['\"]`
- High-entropy strings in config files: (note: this requires entropy calculation in the scanner script, not just regex)

**Step 2: Verify pattern count and formatting**

```bash
grep -c "^- " skill/references/secret-patterns.md
```

Expected: 20+ patterns organized by severity.

**Step 3: Commit**

```bash
git add skill/references/secret-patterns.md
git commit -m "feat: add secret detection patterns reference"
```

---

## Task 3: Create Vulnerability Patterns Reference

**Files:**
- Create: `skill/references/vulnerability-patterns.md`

**Step 1: Write the vulnerability patterns file**

Create `skill/references/vulnerability-patterns.md` with categorized patterns:

**Medium patterns (vulnerability):**
- SQL Injection sinks: `(?i)(execute|query|raw|cursor\.execute)\s*\(\s*[f'\"].*(%s|\{|\\$|\+\s*[a-zA-Z])` — string concatenation/interpolation in SQL calls
- XSS vectors: `(?i)(innerHTML|outerHTML|document\.write|\.html\()\s*[=(].*[\+\$\{]` — dynamic HTML insertion with variables
- Insecure deserialization: `(?i)(pickle\.loads?|yaml\.load\s*\((?!.*Loader)|unserialize|Marshal\.load|eval\s*\()` — dangerous deserialization functions
- Weak crypto: `(?i)(MD5|SHA1|DES|RC4|md5|sha1)\s*[\(.]` — usage of deprecated algorithms
- Hardcoded IP/hostnames in config: `(?i)(host|server|endpoint)\s*[:=]\s*['\"](\d{1,3}\.){3}\d{1,3}['\"]`
- Insecure HTTP: `(?i)(url|endpoint|host|api)\s*[:=]\s*['\"]http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)` — non-localhost HTTP URLs

**Low patterns (best practices):**
- Debug mode enabled: `(?i)(debug|DEBUG)\s*[:=]\s*(true|True|1|['\"]true['\"])` — in non-test files
- Permissive CORS: `(?i)(Access-Control-Allow-Origin|cors.*origin)\s*[:=]\s*['\"]?\*['\"]?`
- TODO security comments: `(?i)(TODO|FIXME|HACK|XXX).{0,50}(security|auth|password|secret|encrypt|vulnerability)`
- Disabled SSL verification: `(?i)(verify\s*[:=]\s*False|CURLOPT_SSL_VERIFYPEER\s*[:=]\s*false|rejectUnauthorized\s*[:=]\s*false|InsecureSkipVerify\s*[:=]\s*true)`

**Step 2: Verify pattern count**

```bash
grep -c "^- " skill/references/vulnerability-patterns.md
```

Expected: 10+ patterns.

**Step 3: Commit**

```bash
git add skill/references/vulnerability-patterns.md
git commit -m "feat: add vulnerability detection patterns reference"
```

---

## Task 4: Create Severity Guide Reference

**Files:**
- Create: `skill/references/severity-guide.md`

**Step 1: Write the severity guide**

Create `skill/references/severity-guide.md` with:
- Severity tier definitions table (Critical/High/Medium/Low) — criteria and examples
- Contextual adjustment rules:
  - File path context: test/example/docs → downgrade; production config/deploy scripts → upgrade
  - Value context: placeholder patterns (`xxx`, `changeme`, `TODO`, `example`, `test`, `dummy`, `fake`, `sample`) → downgrade
  - Environment context: paired with production URLs or live endpoints → upgrade
- Confidence level assignment rules:
  - High: exact pattern match on known secret format (e.g., `AKIA` prefix for AWS)
  - Medium: generic pattern match needing context (e.g., high-entropy string, generic password assignment)
  - Low: heuristic match (e.g., suspicious variable name but uncertain value)
- Finding ID format: `C-NNN`, `H-NNN`, `M-NNN`, `L-NNN`

**Step 2: Commit**

```bash
git add skill/references/severity-guide.md
git commit -m "feat: add severity classification guide reference"
```

---

## Task 5: Write the Bash Scanner Script

**Files:**
- Create: `skill/scripts/scan-secrets.sh`

**Step 1: Write a test fixture with known secrets**

Create `tests/fixtures/sample-repo/leaky-config.js`:

```javascript
// Test fixture: DO NOT use in production
const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
const AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const GITHUB_TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234";
const SLACK_TOKEN = "FAKE_SLACK_TOKEN_FOR_TESTING";
const DB_URL = "postgres://admin:supersecret@prod-db.example.com:5432/mydb";
const SAFE_VAR = "this is not a secret";
const API_URL = "http://external-api.example.com/v1";
const DEBUG = true;
```

Create `tests/fixtures/sample-repo/safe-file.js`:

```javascript
// This file should produce no findings
const APP_NAME = "my-app";
const VERSION = "1.0.0";
const MAX_RETRIES = 3;
```

**Step 2: Write scan-secrets.sh**

Create `skill/scripts/scan-secrets.sh`:
- Accept arguments: target directory, patterns file path, output file path, optional exclude dirs
- Read patterns from a simplified patterns file (one regex per line with metadata: `SEVERITY|PATTERN_NAME|REGEX`)
- Use `grep -rnP` (or `grep -rnE` as fallback) to scan files
- Skip binary files (`-I` flag), respect exclude dirs
- Build file list: use `git ls-files` if in a git repo, otherwise `find` with exclusions
- Support incremental mode: accept `--base-branch` flag, use `git diff --name-only` to get changed files
- Output format: one JSON line per finding: `{"file":"path","line":N,"match":"redacted","pattern":"name","severity":"level"}`
- Redact matches: show first 4 and last 4 chars, mask middle with `...`
- Make executable: `chmod +x`

**Step 3: Run scanner against test fixtures**

```bash
bash skill/scripts/scan-secrets.sh tests/fixtures/sample-repo/ skill/scripts/patterns.dat /dev/stdout
```

Expected: findings for AWS key, AWS secret, GitHub token, Slack token, DB URL, HTTP URL, debug mode. No findings for safe-file.js.

**Step 4: Verify no findings on safe file**

```bash
bash skill/scripts/scan-secrets.sh tests/fixtures/sample-repo/safe-file.js skill/scripts/patterns.dat /dev/stdout
```

Expected: 0 findings.

**Step 5: Commit**

```bash
git add skill/scripts/scan-secrets.sh tests/fixtures/
git commit -m "feat: add bash scanner script with test fixtures"
```

---

## Task 6: Create the Compiled Patterns Data File

**Files:**
- Create: `skill/scripts/patterns.dat`

**Step 1: Write patterns.dat**

This is the machine-readable version of the patterns from references/, used by scan-secrets.sh. Format: `SEVERITY|PATTERN_NAME|REGEX` — one per line.

Extract all patterns from `skill/references/secret-patterns.md` and `skill/references/vulnerability-patterns.md` into this format.

Example lines:
```
CRITICAL|AWS Access Key ID|(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}
CRITICAL|RSA Private Key|-----BEGIN (RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY( BLOCK)?-----
HIGH|GitHub PAT (Classic)|ghp_[0-9a-zA-Z]{36}
HIGH|Slack Token|xox[baprs]-[0-9a-zA-Z\-]{10,}
MEDIUM|SQL Injection Sink|(?i)(execute|query|raw)\s*\(.*[\+\$\{]
LOW|Debug Mode Enabled|(?i)(debug|DEBUG)\s*[:=]\s*(true|True|1)
```

**Step 2: Verify pattern count matches references**

```bash
wc -l skill/scripts/patterns.dat
```

Expected: matches total pattern count from references.

**Step 3: Test scanner with real patterns file**

```bash
bash skill/scripts/scan-secrets.sh tests/fixtures/sample-repo/ skill/scripts/patterns.dat /dev/stdout
```

Expected: findings match expected secrets in test fixtures.

**Step 4: Commit**

```bash
git add skill/scripts/patterns.dat
git commit -m "feat: add compiled patterns data file for scanner"
```

---

## Task 7: Write the Python Fallback Scanner

**Files:**
- Create: `skill/scripts/scan-secrets.py`

**Step 1: Write scan-secrets.py**

Create `skill/scripts/scan-secrets.py`:
- Same interface as scan-secrets.sh: accept target dir, patterns file, output path, exclude dirs
- Use `argparse` for CLI args
- Read patterns from `patterns.dat` (same format)
- Use `re` module for pattern matching
- Walk directory tree, skip excluded dirs and binary files
- Output same JSON-lines format as bash script
- Add entropy calculation for high-entropy string detection (Shannon entropy > 4.5 on strings > 20 chars)
- Support `--base-branch` for incremental mode via `subprocess.run(["git", "diff", ...])`

**Step 2: Run Python scanner against test fixtures**

```bash
python3 skill/scripts/scan-secrets.py --target tests/fixtures/sample-repo/ --patterns skill/scripts/patterns.dat --output /dev/stdout
```

Expected: same findings as bash scanner.

**Step 3: Verify output matches bash scanner**

```bash
diff <(bash skill/scripts/scan-secrets.sh tests/fixtures/sample-repo/ skill/scripts/patterns.dat /dev/stdout | sort) <(python3 skill/scripts/scan-secrets.py --target tests/fixtures/sample-repo/ --patterns skill/scripts/patterns.dat --output /dev/stdout | sort)
```

Expected: identical findings (or Python has additional entropy-based findings).

**Step 4: Commit**

```bash
git add skill/scripts/scan-secrets.py
git commit -m "feat: add Python fallback scanner with entropy detection"
```

---

## Task 8: Write the Report Generator Script

**Files:**
- Create: `skill/scripts/generate-report.sh`

**Step 1: Write a test input file**

Create `tests/fixtures/sample-findings.jsonl` with sample scanner output:

```json
{"file":"src/config.js","line":14,"match":"AKIA...MPLE","pattern":"AWS Access Key ID","severity":"CRITICAL"}
{"file":"src/config.js","line":15,"match":"wJal...EKEY","pattern":"AWS Secret Access Key","severity":"CRITICAL"}
{"file":"src/app.js","line":42,"match":"ghp_...f1234","pattern":"GitHub PAT (Classic)","severity":"HIGH"}
{"file":"src/db.js","line":8,"match":"post...mydb","pattern":"Database Connection String","severity":"HIGH"}
{"file":"src/query.js","line":23,"match":"exec...var","pattern":"SQL Injection Sink","severity":"MEDIUM"}
{"file":"src/server.js","line":5,"match":"debu...true","pattern":"Debug Mode Enabled","severity":"LOW"}
```

**Step 2: Write generate-report.sh**

Create `skill/scripts/generate-report.sh`:
- Accept arguments: findings JSONL file, output format (`markdown`|`sarif`|`json`), output file path
- **Markdown mode:**
  - Parse JSONL, group findings by severity
  - Generate finding IDs (C-001, H-001, M-001, L-001)
  - Output report header with summary counts
  - Output findings grouped by severity section
  - Include scan metadata footer
- **SARIF mode:**
  - Generate valid SARIF 2.1.0 JSON
  - Include `tool.driver` with `name`, `version`, `rules[]`
  - Include `results[]` with `ruleId`, `level` (error/warning/note), `locations`, `message`
  - Map: Critical/High → error, Medium → warning, Low → note
- **JSON mode:**
  - Output the findings as a JSON array with metadata wrapper
- Make executable: `chmod +x`

**Step 3: Test Markdown output**

```bash
bash skill/scripts/generate-report.sh tests/fixtures/sample-findings.jsonl markdown /dev/stdout
```

Expected: valid Markdown report with 2 Critical, 2 High, 1 Medium, 1 Low.

**Step 4: Test SARIF output**

```bash
bash skill/scripts/generate-report.sh tests/fixtures/sample-findings.jsonl sarif /dev/stdout
```

Expected: valid SARIF JSON with `tool.driver` and `results[]`.

**Step 5: Commit**

```bash
git add skill/scripts/generate-report.sh tests/fixtures/sample-findings.jsonl
git commit -m "feat: add report generator with Markdown and SARIF output"
```

---

## Task 9: Create Example Reports

**Files:**
- Create: `skill/examples/sample-report.md`
- Create: `skill/examples/sample-report.sarif.json`

**Step 1: Generate sample Markdown report from test fixtures**

```bash
bash skill/scripts/generate-report.sh tests/fixtures/sample-findings.jsonl markdown skill/examples/sample-report.md
```

**Step 2: Generate sample SARIF report from test fixtures**

```bash
bash skill/scripts/generate-report.sh tests/fixtures/sample-findings.jsonl sarif skill/examples/sample-report.sarif.json
```

**Step 3: Review both files for correctness**

- Markdown: verify finding IDs, severity grouping, redacted matches, summary counts
- SARIF: verify valid JSON, `tool.driver.rules` present, `results` array, severity mapping

**Step 4: Commit**

```bash
git add skill/examples/
git commit -m "feat: add sample report examples (Markdown and SARIF)"
```

---

## Task 10: Integration Test — End-to-End Scan

**Files:**
- Create: `tests/test-e2e.sh`

**Step 1: Write end-to-end test script**

Create `tests/test-e2e.sh` that:
1. Runs `scan-secrets.sh` against `tests/fixtures/sample-repo/` → outputs to temp JSONL
2. Runs `generate-report.sh` on the JSONL → outputs Markdown to temp file
3. Runs `generate-report.sh` on the JSONL → outputs SARIF to temp file
4. Asserts:
   - JSONL contains expected number of findings (>= 5)
   - Markdown report contains "Critical" and "High" sections
   - Markdown report contains finding IDs (C-001, H-001)
   - SARIF file is valid JSON (via `python3 -m json.tool`)
   - SARIF contains `"$schema"` and `"runs"` keys
   - No raw secrets appear in reports (only redacted)
5. Cleans up temp files
6. Exits 0 on success, 1 on failure with descriptive error

**Step 2: Run the end-to-end test**

```bash
bash tests/test-e2e.sh
```

Expected: all assertions pass, exit 0.

**Step 3: Commit**

```bash
git add tests/test-e2e.sh
git commit -m "test: add end-to-end integration test"
```

---

## Task 11: Add .security-audit.yml Config Example

**Files:**
- Create: `skill/examples/security-audit.yml`

**Step 1: Write example config**

Create `skill/examples/security-audit.yml` with a fully-commented example config matching the design doc's configuration section. Include all supported options with inline comments.

**Step 2: Commit**

```bash
git add skill/examples/security-audit.yml
git commit -m "docs: add example .security-audit.yml config"
```

---

## Task 12: Final Validation and Cleanup

**Files:**
- Modify: `skill/SKILL.md` (verify all file references are correct)
- Modify: `README.md` (update if needed)

**Step 1: Verify all referenced files exist**

```bash
find skill/ -type f | sort
```

Expected: all files referenced in SKILL.md and README exist.

**Step 2: Verify SKILL.md word count**

```bash
wc -w skill/SKILL.md
```

Expected: 1,500-2,000 words.

**Step 3: Run end-to-end test one final time**

```bash
bash tests/test-e2e.sh
```

Expected: exit 0, all assertions pass.

**Step 4: Verify no secrets in our own repo**

```bash
bash skill/scripts/scan-secrets.sh skill/ skill/scripts/patterns.dat /dev/stdout
```

Expected: 0 findings (our skill code should not contain any secrets).

**Step 5: Final commit**

```bash
git add -A
git commit -m "chore: final validation and cleanup"
```

---

## Summary

| Task | Component | Key Deliverable |
|------|-----------|----------------|
| 1 | SKILL.md | Orchestration file with workflow and prompts |
| 2 | secret-patterns.md | 20+ secret detection regex patterns |
| 3 | vulnerability-patterns.md | 10+ vulnerability detection patterns |
| 4 | severity-guide.md | Severity tiers and contextual adjustment rules |
| 5 | scan-secrets.sh | Primary bash scanner with test fixtures |
| 6 | patterns.dat | Machine-readable patterns for scanner scripts |
| 7 | scan-secrets.py | Python fallback scanner with entropy detection |
| 8 | generate-report.sh | Report generator (Markdown + SARIF + JSON) |
| 9 | examples/ | Sample reports generated from test data |
| 10 | test-e2e.sh | End-to-end integration test |
| 11 | security-audit.yml | Example configuration file |
| 12 | Validation | Final checks and cleanup |
