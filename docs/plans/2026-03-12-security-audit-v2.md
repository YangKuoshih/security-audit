# Security Audit v2 Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Transform the security-audit skill from a basic secret scanner into a credible lightweight SAST tool with broader pattern coverage, IaC security, better performance, and smarter LLM analysis.

**Architecture:** Three tiers of improvements applied incrementally. Each tier produces a working, tested skill. Tier 1 fixes performance and fills immediate gaps (patterns, entropy, LLM prompting). Tier 2 adds IaC scanning, OWASP vulnerability coverage, and composable skill architecture. Tier 3 adds dependency scanning and git history scanning.

**Tech Stack:** Bash/grep, Python 3.8+ stdlib, SKILL.md (LLM orchestration), patterns.dat (TAB-delimited regex rules)

---

## File Map

### Existing files to modify

| File | Lines | Changes |
|------|-------|---------|
| `skills/security-audit/scripts/scan-secrets.sh` | 352 | Performance: replace per-file filtering with piped grep, single-pass dangerous file scan |
| `skills/security-audit/scripts/scan-secrets.py` | 562 | Hex/base64 entropy split, UUID/URL false positive filters, IaC scanning, dependency scanning |
| `skills/security-audit/scripts/patterns.dat` | 49 | Add ~20 new secret patterns, ~25 vuln patterns, ~25 IaC patterns |
| `skills/security-audit/scripts/generate-report.py` | 405 | Remediation entries for new patterns, executive summary support |
| `skills/security-audit/references/secret-patterns.md` | 308 | Document new secret patterns |
| `skills/security-audit/references/vulnerability-patterns.md` | 164 | Document new OWASP vuln patterns |
| `skills/security-audit/references/severity-guide.md` | 157 | Add IaC severity guidance, dependency finding guidance |
| `skills/security-audit/SKILL.md` | 191 | Rewrite Phase 3 for cross-finding correlation, executive summary, tech stack detection |
| `tests/test-e2e.sh` | 304 | Add tests for each tier's new functionality |
| `README.md` | 274 | Update counts, add IaC/dependency sections |

### New files to create

| File | Purpose |
|------|---------|
| `skills/security-audit/references/iac-patterns.md` | IaC security pattern documentation (Tier 2) |
| `tests/fixtures/sample-repo/insecure-infra.tf` | Terraform fixture with misconfigs (Tier 2) |
| `tests/fixtures/sample-repo/package.json` | Node.js manifest with vulnerable deps (Tier 3) |
| `tests/fixtures/sample-repo/requirements.txt` | Python manifest with vulnerable deps (Tier 3) |

---

## Chunk 1: Tier 1 — Performance, Patterns, Entropy, LLM

### Task 1: Bash scanner performance — file filtering

**Files:**
- Modify: `skills/security-audit/scripts/scan-secrets.sh:163-177`

The current filtering loop spawns 2 grep subprocesses per file. Replace with a single piped grep chain.

- [ ] **Step 1: Write a benchmark baseline**

Run the bash scanner against the test fixtures and time it:
```bash
time bash skills/security-audit/scripts/scan-secrets.sh tests/fixtures/sample-repo skills/security-audit/scripts/patterns.dat /dev/null 2>/dev/null
```
Record the baseline time.

- [ ] **Step 2: Replace per-file filtering loop with piped grep**

In `scan-secrets.sh`, replace lines 163-177 (the `while IFS= read -r filepath` filtering loop) with:

```bash
# Filter: exclude directories and binary extensions (single pass, no per-file forks)
FILTERED_LIST=$(mktemp)
trap 'rm -f "$FILE_LIST" "$FILTERED_LIST" 2>/dev/null' EXIT

grep -vE "/(${EXCLUDE_DIRS})(/|$)" "$FILE_LIST" | grep -viE "$BINARY_EXTENSIONS" > "$FILTERED_LIST"

FILE_COUNT=$(wc -l < "$FILTERED_LIST" | tr -d ' ')
echo "Files to scan: $FILE_COUNT" >&2
```

- [ ] **Step 3: Run tests to verify no regressions**

```bash
bash tests/test-e2e.sh
```
Expected: ALL TESTS PASSED (83/83)

- [ ] **Step 4: Benchmark again and record improvement**

```bash
time bash skills/security-audit/scripts/scan-secrets.sh tests/fixtures/sample-repo skills/security-audit/scripts/patterns.dat /dev/null 2>/dev/null
```

- [ ] **Step 5: Commit**

```bash
git add skills/security-audit/scripts/scan-secrets.sh
git commit -m "perf: replace per-file filtering loop with piped grep in bash scanner"
```

---

### Task 2: Bash scanner performance — single-pass dangerous file scan

**Files:**
- Modify: `skills/security-audit/scripts/scan-secrets.sh:251-338` (the `scan_dangerous_files` function)

Currently reads the tracked_files temp file multiple times (once per special pattern). Combine into a single pass.

- [ ] **Step 1: Refactor scan_dangerous_files to single-pass**

Replace the multiple `while IFS= read` loops for credentials.json, service-account*.json, .terraform/, and *secret* with a single pass:

```bash
scan_dangerous_files() {
  local target="$1" output="$2"

  if ! command -v git > /dev/null 2>&1; then return; fi
  if ! git -C "$target" rev-parse --is-inside-work-tree > /dev/null 2>&1; then return; fi

  local tracked_files
  tracked_files=$(mktemp)
  git -C "$target" ls-files --cached 2>/dev/null > "$tracked_files"

  local count=0

  while IFS= read -r filepath; do
    [[ -z "$filepath" ]] && continue
    local base pid pname sev matched=false
    base=$(basename "$filepath")
    local lower_base="${base,,}"
    local lower_path="${filepath,,}"

    # Extension-based patterns
    case "$lower_base" in
      *.tfstate.backup) pid="dangerous-file-tfstate-backup"; pname="Terraform State Backup Committed"; sev="HIGH"; matched=true ;;
      *.tfstate) pid="dangerous-file-tfstate"; pname="Terraform State Committed"; sev="HIGH"; matched=true ;;
      *.pem) pid="dangerous-file-pem"; pname="Private Key File Committed"; sev="CRITICAL"; matched=true ;;
      *.key) pid="dangerous-file-key"; pname="Private Key File Committed"; sev="CRITICAL"; matched=true ;;
      *.p12) pid="dangerous-file-p12"; pname="Certificate Bundle Committed"; sev="CRITICAL"; matched=true ;;
      *.pfx) pid="dangerous-file-pfx"; pname="Certificate Bundle Committed"; sev="CRITICAL"; matched=true ;;
      *.jks) pid="dangerous-file-jks"; pname="Java Keystore Committed"; sev="HIGH"; matched=true ;;
      *.sqlite) pid="dangerous-file-sqlite"; pname="Database File Committed"; sev="MEDIUM"; matched=true ;;
      *.db) pid="dangerous-file-db"; pname="Database File Committed"; sev="MEDIUM"; matched=true ;;
    esac

    # Name-based patterns (only if not already matched by extension)
    if [[ "$matched" == "false" ]]; then
      case "$lower_base" in
        credentials.json) pid="dangerous-file-credentials-json"; pname="Credentials File Committed"; sev="HIGH"; matched=true ;;
        service-account*.json) pid="dangerous-file-service-account"; pname="Service Account Key Committed"; sev="HIGH"; matched=true ;;
      esac
    fi

    # Wildcard-name patterns
    if [[ "$matched" == "false" ]]; then
      case "$lower_base" in
        *terraform-apply-output*) pid="dangerous-file-tf-apply-output"; pname="Terraform Apply Output Committed"; sev="MEDIUM"; matched=true ;;
        *terraform-plan-output*) pid="dangerous-file-tf-plan-output"; pname="Terraform Plan Output Committed"; sev="MEDIUM"; matched=true ;;
      esac
    fi

    # .terraform/ directory
    if [[ "$matched" == "false" && ("$lower_path" == .terraform/* || "$lower_path" == */.terraform/*) ]]; then
      pid="dangerous-file-terraform-cache"; pname="Terraform Provider Cache Committed"; sev="MEDIUM"; matched=true
    fi

    # *secret* in filename (excluding .example, .sample, .template, .md)
    if [[ "$matched" == "false" && "$lower_base" == *secret* ]]; then
      case "$lower_base" in
        *.example|*.sample|*.template|*.md) ;;
        *) pid="dangerous-file-secret-name"; pname="Possible Secrets File Committed"; sev="MEDIUM"; matched=true ;;
      esac
    fi

    if [[ "$matched" == "true" ]]; then
      emit_finding "${target%/}/$filepath" 0 "(entire file)" "$pid" "$pname" "$sev" "$output"
      count=$((count + 1))
      FINDING_COUNT=$((FINDING_COUNT + 1))
    fi
  done < "$tracked_files"

  rm -f "$tracked_files"
  echo "Dangerous file types found: $count" >&2
}
```

- [ ] **Step 2: Run tests**

```bash
bash tests/test-e2e.sh
```
Expected: ALL TESTS PASSED (83/83)

- [ ] **Step 3: Commit**

```bash
git add skills/security-audit/scripts/scan-secrets.sh
git commit -m "perf: single-pass dangerous file scan in bash scanner"
```

---

### Task 3: Fix entropy detection for hex secrets

**Files:**
- Modify: `skills/security-audit/scripts/scan-secrets.py:52-64,69-80,296-321`
- Modify: `tests/fixtures/sample-repo/leaky-config.js` (add hex secret fixture)

Current entropy threshold (4.5) exceeds the maximum entropy of hex strings (4.0), making hex-encoded secrets invisible.

- [ ] **Step 1: Add a hex secret to the test fixture**

Append to `tests/fixtures/sample-repo/leaky-config.js`:
```javascript
// Hex-encoded HMAC key
const hmac_secret = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4";
```

- [ ] **Step 2: Run Python scanner to confirm it misses the hex secret**

```bash
python skills/security-audit/scripts/scan-secrets.py --target tests/fixtures/sample-repo --patterns skills/security-audit/scripts/patterns.dat --output /dev/stdout 2>/dev/null | grep -c "hmac"
```
Expected: 0 (not detected)

- [ ] **Step 3: Implement charset-aware entropy detection**

In `scan-secrets.py`, replace the `shannon_entropy` function and entropy scanning section:

```python
# Character set detection for entropy thresholds
HEX_CHARS = set("0123456789abcdefABCDEF")
BASE64_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")

ENTROPY_THRESHOLDS = {
    "hex": 3.5,      # max theoretical: 4.0 bits
    "base64": 4.2,   # max theoretical: 6.0 bits
    "generic": 4.5,  # max theoretical: ~6.5 bits
}

def detect_charset(value: str) -> str:
    """Detect the character set of a string value."""
    chars = set(value)
    if chars <= HEX_CHARS:
        return "hex"
    if chars <= BASE64_CHARS:
        return "base64"
    return "generic"

# False positive filters for entropy detection
UUID_PATTERN = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I)
URL_PATH_PATTERN = re.compile(r'^(https?://|/[a-z])', re.I)
SEMVER_PATTERN = re.compile(r'^\d+\.\d+\.\d+')

def is_false_positive_entropy(value: str) -> bool:
    """Filter out high-entropy strings that aren't secrets."""
    if UUID_PATTERN.match(value):
        return True
    if URL_PATH_PATTERN.match(value):
        return True
    if SEMVER_PATTERN.match(value):
        return True
    return False
```

Update the entropy scanning section (around line 297) to use charset-aware thresholds:

```python
# Entropy-based detection
if enable_entropy:
    for line_num, line in enumerate(lines, start=1):
        if not ENTROPY_VARIABLE_NAMES.search(line):
            continue
        for m in STRING_VALUE_PATTERN.finditer(line):
            value = m.group(1)
            if len(value) < ENTROPY_MIN_LENGTH:
                continue
            if is_placeholder(value):
                continue
            if is_false_positive_entropy(value):
                continue
            charset = detect_charset(value)
            threshold = ENTROPY_THRESHOLDS[charset]
            entropy = shannon_entropy(value)
            if entropy >= threshold:
                findings.append({
                    "file": filepath,
                    "line": line_num,
                    "match": redact(value),
                    "pattern_id": "high-entropy",
                    "pattern_name": f"High-Entropy String ({charset}, entropy={entropy:.2f})",
                    "severity": "MEDIUM",
                })
```

- [ ] **Step 4: Run Python scanner to confirm hex secret is now detected**

```bash
python skills/security-audit/scripts/scan-secrets.py --target tests/fixtures/sample-repo --patterns skills/security-audit/scripts/patterns.dat --output /dev/stdout 2>/dev/null | grep "hmac\|hex"
```
Expected: 1 finding with `high-entropy` pattern

- [ ] **Step 5: Run full tests**

```bash
bash tests/test-e2e.sh
```
Expected: ALL TESTS PASSED

- [ ] **Step 6: Commit**

```bash
git add skills/security-audit/scripts/scan-secrets.py tests/fixtures/sample-repo/leaky-config.js
git commit -m "feat: charset-aware entropy detection (hex threshold 3.5, base64 4.2)"
```

---

### Task 4: Add high-confidence secret patterns

**Files:**
- Modify: `skills/security-audit/scripts/patterns.dat`
- Modify: `skills/security-audit/references/secret-patterns.md`
- Modify: `skills/security-audit/scripts/generate-report.py` (remediation entries)

Add ~16 new patterns with distinctive prefixes. These all have near-zero false positive rates.

- [ ] **Step 1: Add new patterns to patterns.dat**

Append to `patterns.dat` (TAB-delimited, no trailing whitespace):

```
CRITICAL	digitalocean-pat	DigitalOcean Personal Access Token	dop_v1_[a-f0-9]{64}
CRITICAL	hashicorp-vault-token	HashiCorp Vault Token	hvs\.[a-zA-Z0-9_-]{24,}
CRITICAL	terraform-cloud-token	Terraform Cloud Token	[a-zA-Z0-9]{14}\.atlasv1\.[a-zA-Z0-9_-]{60,}
HIGH	docker-hub-pat	Docker Hub Personal Access Token	dckr_pat_[a-zA-Z0-9_-]{27,}
HIGH	grafana-cloud-token	Grafana Cloud Token	glc_[a-zA-Z0-9_+/=-]{32,}
HIGH	grafana-service-account	Grafana Service Account Token	glsa_[a-zA-Z0-9_+/=-]{32,}
HIGH	shopify-private-app	Shopify Private App Token	shppa_[a-fA-F0-9]{32}
HIGH	shopify-access-token	Shopify Access Token	shpat_[a-fA-F0-9]{32}
HIGH	shopify-shared-secret	Shopify Shared Secret	shpss_[a-fA-F0-9]{32}
HIGH	anthropic-api-key	Anthropic API Key	sk-ant-[a-zA-Z0-9_-]{20,}
HIGH	linear-api-key	Linear API Key	lin_api_[a-zA-Z0-9]{40}
HIGH	planetscale-token	PlanetScale Token	pscale_tkn_[a-zA-Z0-9_-]{40,}
HIGH	figma-pat	Figma Personal Access Token	figd_[a-zA-Z0-9_-]{40,}
HIGH	digitalocean-oauth	DigitalOcean OAuth Token	doo_v1_[a-f0-9]{64}
MEDIUM	datadog-api-key	Datadog API Key	(?i)(DD_API_KEY|datadog_api_key)\s*[:=]\s*['"]?[a-f0-9]{32}['"]?
MEDIUM	discord-bot-token	Discord Bot Token	[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}
```

- [ ] **Step 2: Document each new pattern in secret-patterns.md**

Add a new section `## Additional SaaS & Cloud Tokens` after the existing secrets section, before the Dangerous File Types section. Document each new pattern with: regex, description, severity, and false positive guidance.

- [ ] **Step 3: Add remediation entries in generate-report.py**

Add entries to the `REMEDIATION` dict for each new pattern ID (e.g., `"digitalocean-pat": "Revoke token in DigitalOcean console..."`).

- [ ] **Step 4: Update patterns.dat test assertion count**

In `tests/test-e2e.sh`, the bash scanner test asserts `BASH_COUNT -ge 10`. Verify the count is still accurate — the new patterns won't fire on existing fixtures, so counts should be unchanged.

- [ ] **Step 5: Run tests**

```bash
bash tests/test-e2e.sh
```
Expected: ALL TESTS PASSED

- [ ] **Step 6: Commit**

```bash
git add skills/security-audit/scripts/patterns.dat skills/security-audit/references/secret-patterns.md skills/security-audit/scripts/generate-report.py
git commit -m "feat: add 16 secret patterns (DigitalOcean, Vault, Grafana, Shopify, Anthropic, etc.)"
```

---

### Task 5: Upgrade LLM analysis phase in SKILL.md

**Files:**
- Modify: `skills/security-audit/SKILL.md:97-140` (Phase 3)

Rewrite Phase 3 to leverage LLM capabilities that regex cannot replicate.

- [ ] **Step 1: Rewrite Phase 3 in SKILL.md**

Replace the current Phase 3 section with:

```markdown
### Phase 3: LLM Analysis

Review the **redacted** findings from Phase 2 (the JSONL output file). Follow Secret Data Safety rules — work from scanner output only, not original source files, for secret findings.

#### 3a. Tech Stack Detection

Before analyzing findings, identify the project's tech stack by checking for:
- `package.json` → Node.js/JavaScript (recommend: `process.env`, AWS Secrets Manager, GitHub Secrets)
- `requirements.txt` / `pyproject.toml` / `setup.py` → Python (recommend: `os.environ`, python-dotenv, Vault)
- `go.mod` → Go (recommend: `os.Getenv`, Vault, cloud-native secrets)
- `pom.xml` / `build.gradle` → Java (recommend: Spring Vault, AWS Secrets Manager)
- `Gemfile` → Ruby (recommend: `ENV[]`, dotenv, Rails credentials)
- `*.tf` files → Terraform (recommend: remote state, variable files, Vault provider)
- `Dockerfile` / `docker-compose.yml` → containerized (recommend: Docker secrets, build args for non-sensitive config only)

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

2. **Classify severity** using `references/severity-guide.md`:
   - Start with base severity from pattern match
   - Apply contextual adjustments (file path, production indicators)
   - For correlated groups, use the highest severity in the group

3. **Assess exploitability** (vulnerability findings only — NOT secret findings):
   - For vuln findings (SQL injection, XSS, command injection, SSRF), you MAY read the surrounding function (10 lines above/below) to assess whether user input can reach the sink
   - Do NOT read files flagged for secret findings
   - Rate: Exploitable / Likely Exploitable / Needs Investigation / Likely False Positive

4. **Assign confidence**: High (vendor-specific format or unambiguous file type), Medium (generic pattern needing context), Low (heuristic match)

#### 3d. Executive Summary

Before the detailed findings, produce a prioritized summary:

1. **Top 3 actions** — the three most impactful things to fix first, with one sentence each explaining why
2. **Blast radius assessment** — what an attacker could access if the worst findings are exploited
3. **Positive observations** — note good security practices observed (e.g., "secrets are properly gitignored", "no production credentials found")
```

- [ ] **Step 2: Run a smoke test**

Verify SKILL.md is well-formed and the phase references are internally consistent.

- [ ] **Step 3: Commit**

```bash
git add skills/security-audit/SKILL.md
git commit -m "feat: rewrite Phase 3 LLM analysis with correlation, exec summary, tech stack detection"
```

---

### Task 6: Update README and test counts for Tier 1

**Files:**
- Modify: `README.md`
- Modify: `tests/test-e2e.sh` (update pattern count assertions if needed)

- [ ] **Step 1: Update README pattern count badge**

Change `44%20rules` to `60%20rules` (44 original + 16 new secret patterns).

- [ ] **Step 2: Update "What It Catches" section**

Update: "**Secrets** — 34 patterns" → "**Secrets** — 50 patterns" (34 original + 16 new).

- [ ] **Step 3: Run full test suite one more time**

```bash
bash tests/test-e2e.sh
```
Expected: ALL TESTS PASSED

- [ ] **Step 4: Commit**

```bash
git add README.md tests/test-e2e.sh
git commit -m "docs: update README for Tier 1 changes (60 patterns, improved entropy, LLM rewrite)"
```

---

## Chunk 2: Tier 2 — IaC Security, OWASP Coverage, Composability

### Task 7: Add IaC security patterns for Terraform

**Files:**
- Create: `skills/security-audit/references/iac-patterns.md`
- Modify: `skills/security-audit/scripts/patterns.dat`
- Modify: `skills/security-audit/scripts/generate-report.py` (remediation entries)
- Create: `tests/fixtures/sample-repo/insecure-infra.tf`

Add ~20 regex patterns that detect common Terraform/Docker/K8s misconfigs without requiring HCL parsing.

- [ ] **Step 1: Create test fixture `insecure-infra.tf`**

```hcl
# Intentionally insecure Terraform for testing
resource "aws_security_group" "open" {
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "exposed" {
  publicly_accessible = true
  storage_encrypted   = false
  engine              = "mysql"
  instance_class      = "db.t3.micro"
}

resource "aws_s3_bucket" "logs" {
  bucket        = "my-logs-bucket"
  force_destroy = true
}

resource "aws_s3_bucket_acl" "public" {
  bucket = aws_s3_bucket.logs.id
  acl    = "public-read"
}

resource "aws_instance" "web" {
  ami           = "ami-12345"
  instance_type = "t3.micro"
  # No metadata service hardening
  metadata_options {
    http_tokens = "optional"
  }
}

resource "aws_rds_cluster" "db" {
  # No encryption, no backup
  storage_encrypted       = false
  skip_final_snapshot     = true
  backup_retention_period = 0
}

resource "aws_iam_policy" "admin" {
  policy = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = ["*"]
      Resource = ["*"]
    }]
  })
}
```

- [ ] **Step 2: Add IaC patterns to patterns.dat**

```
HIGH	iac-open-cidr	Open CIDR Block (0.0.0.0/0)	cidr_blocks\s*=\s*\[.*["']0\.0\.0\.0/0["']
HIGH	iac-public-db	Publicly Accessible Database	publicly_accessible\s*=\s*true
HIGH	iac-unencrypted-storage	Unencrypted Storage	storage_encrypted\s*=\s*false
HIGH	iac-all-traffic-protocol	All-Traffic Security Group Rule	protocol\s*=\s*["']-1["']
HIGH	iac-wildcard-iam	Wildcard IAM Policy	Action\s*[:=]\s*\[?\s*["']\*["']
HIGH	iac-imdsv1-enabled	IMDSv1 Enabled (Instance Metadata)	http_tokens\s*=\s*["']optional["']
MEDIUM	iac-public-acl	Public S3 Bucket ACL	acl\s*=\s*["']public-(read|read-write|write)["']
MEDIUM	iac-force-destroy	Force Destroy Enabled	force_destroy\s*=\s*true
MEDIUM	iac-no-backup	Backup Disabled	backup_retention_period\s*=\s*0
MEDIUM	iac-skip-snapshot	Skip Final Snapshot	skip_final_snapshot\s*=\s*true
MEDIUM	iac-privileged-container	Privileged Docker Container	privileged\s*[:=]\s*true
MEDIUM	iac-host-network	Host Network Mode	(?i)(hostNetwork|network_mode)\s*[:=]\s*["']?(true|host)["']?
MEDIUM	iac-no-resource-limits	No K8s Resource Limits	(?i)containers:(?:(?!limits).)*$
LOW	iac-latest-tag	Container Using :latest Tag	image\s*[:=]\s*["'][^"']+:latest["']
LOW	iac-no-healthcheck	No Healthcheck Defined	(?i)^\s*(FROM|image:)(?:(?!HEALTHCHECK|healthcheck).)*$
```

- [ ] **Step 3: Create `references/iac-patterns.md`**

Document each pattern with: description, severity, what it detects, why it matters, false positive guidance, and remediation. Organized by cloud provider (AWS, multi-cloud, Kubernetes, Docker).

- [ ] **Step 4: Add remediation entries in `generate-report.py`**

Add entries for each `iac-*` pattern ID.

- [ ] **Step 5: Add IaC test assertions to `test-e2e.sh`**

Add a new test section:
```bash
section "IaC Pattern Detection"
# Scan the Terraform fixture
IAC_OUTPUT="$TMPDIR/iac-findings.jsonl"
bash "$SKILL_DIR/scripts/scan-secrets.sh" "$FIXTURES_DIR/insecure-infra.tf" "$PATTERNS" "$IAC_OUTPUT" 2>/dev/null
IAC_COUNT=$(wc -l < "$IAC_OUTPUT" | tr -d ' ')
assert "IaC scanner produces findings (got $IAC_COUNT)" "[[ $IAC_COUNT -ge 8 ]]"
assert "Detects open CIDR" "grep -q 'iac-open-cidr' '$IAC_OUTPUT'"
assert "Detects public DB" "grep -q 'iac-public-db' '$IAC_OUTPUT'"
assert "Detects unencrypted storage" "grep -q 'iac-unencrypted-storage' '$IAC_OUTPUT'"
assert "Detects wildcard IAM" "grep -q 'iac-wildcard-iam' '$IAC_OUTPUT'"
assert "Detects public ACL" "grep -q 'iac-public-acl' '$IAC_OUTPUT'"
assert "Detects force destroy" "grep -q 'iac-force-destroy' '$IAC_OUTPUT'"
assert "Detects skip snapshot" "grep -q 'iac-skip-snapshot' '$IAC_OUTPUT'"
assert "Detects IMDSv1" "grep -q 'iac-imdsv1-enabled' '$IAC_OUTPUT'"
```

- [ ] **Step 6: Run tests**

```bash
bash tests/test-e2e.sh
```
Expected: ALL TESTS PASSED

- [ ] **Step 7: Commit**

```bash
git add skills/security-audit/scripts/patterns.dat skills/security-audit/references/iac-patterns.md skills/security-audit/scripts/generate-report.py tests/fixtures/sample-repo/insecure-infra.tf tests/test-e2e.sh
git commit -m "feat: add 15 IaC security patterns for Terraform, K8s, and Docker"
```

---

### Task 8: Expand OWASP vulnerability patterns

**Files:**
- Modify: `skills/security-audit/scripts/patterns.dat`
- Modify: `skills/security-audit/references/vulnerability-patterns.md`
- Modify: `skills/security-audit/scripts/generate-report.py`
- Modify: `tests/fixtures/sample-repo/vulnerable-app.py` (add new vuln fixtures)

Add patterns for OWASP categories with zero current coverage: A01 (Broken Access Control), A07 (Auth Failures), A09 (Logging Failures), plus expand A02/A05.

- [ ] **Step 1: Add new vulnerability test cases to fixture**

Append to `vulnerable-app.py`:

```python
# A01: Path traversal
def read_user_file(filename):
    with open("/uploads/" + filename, "r") as f:
        return f.read()

# A07: Hardcoded default password
DEFAULT_PASSWORD = "admin123"
users = {"admin": "password123"}

# A09: Bare except swallowing errors
try:
    process_payment(order)
except:
    pass

# A02: ECB mode
from Crypto.Cipher import AES
cipher = AES.new(key, AES.MODE_ECB)

# A02: Math.random for security — add to JS fixture instead
```

- [ ] **Step 2: Add new patterns to patterns.dat**

```
MEDIUM	path-traversal	Path Traversal	(?i)(open|read|include|require|fopen|readFile|readFileSync)\s*\([^)]*(\.\./|\+\s*[a-zA-Z]|\$\{|f['\"])
MEDIUM	mass-assignment	Mass Assignment	(?i)(\.create|\.update|\.insert)\s*\(\s*(req\.body|request\.json|params)
MEDIUM	ecb-mode	ECB Encryption Mode	(?i)(MODE_ECB|AES\/ECB|DES\/ECB|"ECB")
MEDIUM	math-random-security	Insecure Random for Security	(?i)(Math\.random|rand\(\)|random\.random)\s*\(\).*(?:token|secret|key|password|nonce|salt)
MEDIUM	bare-except	Bare Exception Handler	(?i)^\s*except\s*:\s*$
MEDIUM	empty-catch	Empty Catch Block	(?i)catch\s*\([^)]*\)\s*\{\s*\}
MEDIUM	hardcoded-default-password	Hardcoded Default Password	(?i)(default.?password|admin.?password|root.?password)\s*[:=]\s*['"][^'"]{3,}['"]
LOW	e-printstacktrace	Verbose Error Exposure	(?i)(e\.printStackTrace|traceback\.print_exc|console\.error\(err)
LOW	missing-csrf	Missing CSRF Protection	(?i)(csrf|xsrf)\s*[:=]\s*(false|False|disabled|off)
LOW	unvalidated-redirect	Unvalidated Redirect	(?i)(redirect|redirect_to|location\.href)\s*[:=(]\s*[^'"\s]*\b(req|request|params|query)\b
```

- [ ] **Step 3: Document in vulnerability-patterns.md**

Add sections for each new pattern under appropriate OWASP categories.

- [ ] **Step 4: Add remediation entries**

- [ ] **Step 5: Add test assertions**

- [ ] **Step 6: Run tests**

```bash
bash tests/test-e2e.sh
```

- [ ] **Step 7: Commit**

```bash
git add skills/security-audit/scripts/patterns.dat skills/security-audit/references/vulnerability-patterns.md skills/security-audit/scripts/generate-report.py tests/fixtures/sample-repo/vulnerable-app.py tests/test-e2e.sh
git commit -m "feat: add 10 OWASP vuln patterns (A01 path traversal, A07 auth, A09 logging, A02 ECB)"
```

---

### Task 9: Add severity guidance for IaC and vuln pattern updates

**Files:**
- Modify: `skills/security-audit/references/severity-guide.md`

- [ ] **Step 1: Add IaC Findings section to severity-guide.md**

After the "File-Type Findings" section, add:

```markdown
### IaC Findings (Infrastructure-as-Code)

IaC findings detect misconfigurations in Terraform, Kubernetes, and Docker files.

**Base severities:**
- **HIGH**: Open network access (0.0.0.0/0), public databases, wildcard IAM, unencrypted storage, IMDSv1 — direct paths to data exposure or unauthorized access
- **MEDIUM**: Operational risks (force destroy, no backups, public ACLs, privileged containers) — increase blast radius of other vulnerabilities
- **LOW**: Best practices (latest tag, no healthcheck) — operational hygiene

**Contextual adjustments:**
- Upgrade if file is in `production/`, `infra/prod/`, or references production account IDs
- Downgrade if file is in `examples/`, `modules/` (reusable module defaults may be overridden)
- A security group with 0.0.0.0/0 on port 443 is different from 0.0.0.0/0 on all ports — the LLM should note the specific port range
```

- [ ] **Step 2: Commit**

```bash
git add skills/security-audit/references/severity-guide.md
git commit -m "docs: add IaC severity classification guidance"
```

---

### Task 10: Update README and tests for Tier 2

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Update counts**

- Pattern badge: 60 → ~85 rules
- Secrets: 50 patterns
- Vulnerabilities: 15 → 25 patterns
- IaC: 0 → 15 patterns
- Tests: update assertion count

- [ ] **Step 2: Add IaC section to "What It Catches"**

Add a third column or row for IaC patterns.

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: update README for Tier 2 (IaC patterns, expanded OWASP coverage)"
```

---

## Chunk 3: Tier 3 — Dependency Scanning, Git History

### Task 11: Basic dependency vulnerability scanning

**Files:**
- Modify: `skills/security-audit/scripts/scan-secrets.py` (add `scan_dependencies()`)
- Modify: `skills/security-audit/scripts/scan-secrets.sh` (add `scan_dependencies()`)
- Create: `tests/fixtures/sample-repo/package.json`
- Create: `tests/fixtures/sample-repo/requirements.txt`
- Modify: `skills/security-audit/references/severity-guide.md`

Not a full CVE database — a curated list of the ~30 most critical known-vulnerable package versions that affected widely-used packages.

- [ ] **Step 1: Create test fixture `package.json`**

```json
{
  "name": "test-app",
  "dependencies": {
    "lodash": "4.17.20",
    "express": "4.17.1",
    "minimist": "1.2.5",
    "node-fetch": "2.6.1",
    "axios": "0.21.0",
    "jsonwebtoken": "8.5.1",
    "safe-package": "1.0.0"
  }
}
```

- [ ] **Step 2: Create test fixture `requirements.txt`**

```
Django==3.1
requests==2.25.0
PyYAML==5.3
Jinja2==2.11.2
cryptography==3.3
flask==1.1.2
safe-package==1.0.0
```

- [ ] **Step 3: Add `scan_dependencies()` to scan-secrets.py**

Create a curated dict of known-vulnerable packages with version ranges:

```python
# Curated list of high-impact CVEs — NOT a full database
# Format: (package_name, vulnerable_version_prefix, cve, severity, description)
KNOWN_VULNERABLE_PACKAGES = {
    "npm": [
        ("lodash", "<4.17.21", "CVE-2021-23337", "HIGH", "Command injection via template"),
        ("minimist", "<1.2.6", "CVE-2021-44906", "CRITICAL", "Prototype pollution"),
        ("node-fetch", "<2.6.7", "CVE-2022-0235", "HIGH", "Exposure of sensitive info"),
        ("axios", "<0.21.1", "CVE-2020-28168", "HIGH", "SSRF via redirect"),
        ("jsonwebtoken", "<9.0.0", "CVE-2022-23529", "HIGH", "Insecure key handling"),
        ("express", "<4.17.3", "CVE-2022-24999", "MEDIUM", "Prototype pollution via qs"),
        ("log4js", "<6.4.0", "CVE-2022-21704", "MEDIUM", "Arbitrary file write"),
        ("shell-quote", "<1.7.3", "CVE-2021-42740", "CRITICAL", "Command injection"),
        ("glob-parent", "<5.1.2", "CVE-2020-28469", "HIGH", "ReDoS"),
        ("tar", "<6.1.9", "CVE-2021-37712", "HIGH", "Arbitrary file creation"),
    ],
    "pip": [
        ("Django", "<3.2.4", "CVE-2021-33203", "MEDIUM", "Directory traversal"),
        ("requests", "<2.25.1", "CVE-2023-32681", "MEDIUM", "Proxy credential leak"),
        ("PyYAML", "<5.4", "CVE-2020-14343", "CRITICAL", "Arbitrary code execution"),
        ("Jinja2", "<2.11.3", "CVE-2020-28493", "MEDIUM", "ReDoS"),
        ("cryptography", "<3.3.2", "CVE-2021-3449", "HIGH", "NULL pointer dereference"),
        ("Flask", "<2.0", "CVE-2023-30861", "HIGH", "Cookie injection"),
        ("Pillow", "<8.1.2", "CVE-2021-27921", "HIGH", "Buffer overflow"),
        ("urllib3", "<1.26.5", "CVE-2021-33503", "MEDIUM", "ReDoS"),
        ("setuptools", "<65.5.1", "CVE-2022-40897", "MEDIUM", "ReDoS"),
        ("certifi", "<2022.12.07", "CVE-2022-23491", "HIGH", "Untrusted root CA"),
    ],
}
```

Implement version comparison using simple prefix matching (not full semver — we compare `<major.minor.patch` strings). Parse `package.json` dependencies and `requirements.txt` pinned versions.

Output format:
```json
{"file": "package.json", "line": 0, "match": "lodash@4.17.20", "pattern_id": "vuln-dep-npm-lodash", "pattern_name": "Vulnerable Dependency: lodash <4.17.21 (CVE-2021-23337)", "severity": "HIGH"}
```

- [ ] **Step 4: Add equivalent `scan_dependencies()` to scan-secrets.sh**

Bash version uses `grep` + `sed` to extract package names and versions from `package.json` and `requirements.txt`, then matches against a hardcoded known-vulnerable list (same CVEs as Python version).

- [ ] **Step 5: Add dependency severity guidance to severity-guide.md**

```markdown
### Dependency Findings (Vulnerable Components)

Dependency findings flag packages with known CVEs based on a curated list of high-impact vulnerabilities.

**Important limitations:**
- This is NOT a complete CVE database — it covers ~20 high-impact CVEs per ecosystem
- For comprehensive dependency scanning, use dedicated tools (npm audit, pip-audit, Snyk, Dependabot)
- Version matching is approximate (prefix-based, not full semver range)

**Base severities:** Inherited from the CVE severity rating.

**Contextual adjustments:**
- Downgrade if the package is a devDependency (not shipped to production)
- Upgrade if the package handles auth, crypto, or user input
- Note: even a MEDIUM-severity dependency may be critical if it's in the request processing path
```

- [ ] **Step 6: Add test assertions**

```bash
section "Dependency Scanning"
DEP_OUTPUT="$TMPDIR/dep-findings.jsonl"
bash "$SKILL_DIR/scripts/scan-secrets.sh" "$FIXTURES_DIR" "$PATTERNS" "$DEP_OUTPUT" 2>/dev/null
assert "Detects vulnerable lodash" "grep -q 'vuln-dep.*lodash' '$DEP_OUTPUT'"
assert "Detects vulnerable PyYAML" "grep -q 'vuln-dep.*PyYAML' '$DEP_OUTPUT'"
assert "Does not flag safe-package" "! grep -q 'safe-package' '$DEP_OUTPUT'"
```

- [ ] **Step 7: Run tests**

```bash
bash tests/test-e2e.sh
```

- [ ] **Step 8: Commit**

```bash
git add skills/security-audit/scripts/scan-secrets.py skills/security-audit/scripts/scan-secrets.sh skills/security-audit/references/severity-guide.md tests/fixtures/sample-repo/package.json tests/fixtures/sample-repo/requirements.txt tests/test-e2e.sh
git commit -m "feat: add basic dependency vulnerability scanning (20 curated CVEs per ecosystem)"
```

---

### Task 12: Git history scanning for high-confidence secrets

**Files:**
- Modify: `skills/security-audit/scripts/scan-secrets.sh` (add `scan_git_history()`)
- Modify: `skills/security-audit/scripts/scan-secrets.py` (add `scan_git_history()`)
- Modify: `skills/security-audit/SKILL.md` (document Phase 2c)

Scan `git log` for secrets that were committed and later removed. Only scan for high-confidence patterns (AKIA, ghp_, sk_live_, etc.) to keep it fast.

- [ ] **Step 1: Add `scan_git_history()` to scan-secrets.sh**

```bash
scan_git_history() {
  local target="$1" output="$2"

  if ! command -v git > /dev/null 2>&1; then return; fi
  if ! git -C "$target" rev-parse --is-inside-work-tree > /dev/null 2>&1; then return; fi

  # Only high-confidence patterns to keep this fast
  local -a HISTORY_PATTERNS=(
    'CRITICAL|hist-aws-key|AWS Key in Git History|(AKIA|ASIA)[A-Z2-7]{16}'
    'CRITICAL|hist-private-key|Private Key in Git History|-----BEGIN[A-Z ]*PRIVATE KEY'
    'CRITICAL|hist-stripe-key|Stripe Key in Git History|sk_(live|test)_[a-zA-Z0-9]{10,}'
    'HIGH|hist-github-token|GitHub Token in Git History|gh[ps]_[A-Za-z0-9_]{36,}'
    'HIGH|hist-slack-token|Slack Token in Git History|xox[bpas]-[0-9]{10,}'
    'HIGH|hist-vault-token|Vault Token in Git History|hvs\.[a-zA-Z0-9_-]{24,}'
  )

  local count=0
  for entry in "${HISTORY_PATTERNS[@]}"; do
    IFS='|' read -r sev pid pname regex <<< "$entry"
    # Search git log diffs, limit to 1000 commits for performance
    while IFS= read -r match_line; do
      [[ -z "$match_line" ]] && continue
      # Extract commit hash
      local commit_hash
      commit_hash=$(echo "$match_line" | head -1 | cut -d: -f1)
      local matched_text
      matched_text=$(echo "$match_line" | grep -oE "$regex" | head -1) || true
      [[ -z "$matched_text" ]] && continue

      local redacted
      redacted=$(redact_match "$matched_text")

      emit_finding "git-history:${commit_hash}" 0 "$matched_text" "$pid" "$pname" "$sev" "$output"
      count=$((count + 1))
      FINDING_COUNT=$((FINDING_COUNT + 1))
    done < <(git -C "$target" log --all -n 1000 --diff-filter=D -p 2>/dev/null | grep -nE "$regex" | head -50 || true)
  done

  echo "Git history secrets found: $count" >&2
}
```

Note: Uses `--diff-filter=D` (deleted files) and `-p` (patch output), limited to 1000 commits and 50 matches per pattern to avoid performance issues on large repos.

- [ ] **Step 2: Add equivalent to scan-secrets.py**

Python version using `subprocess.run(["git", "log", ...])`.

- [ ] **Step 3: Document Phase 2c in SKILL.md**

```markdown
### Phase 2c: Git History Scan

Scans git commit history for high-confidence secrets that were committed and later removed. These are still exploitable because git history is preserved.

**Scope:** Only 6 high-confidence patterns (AWS keys, private keys, Stripe keys, GitHub tokens, Slack tokens, Vault tokens). Limited to 1000 most recent commits for performance.

**Output format:** Uses `file: "git-history:<commit-hash>"` and `line: 0` to indicate a historical finding.

**Important:** Historical secrets require immediate rotation even if they've been removed from the current codebase. An attacker with repo access (or a repo clone) can view the full history.
```

- [ ] **Step 4: Add test for git history scanning**

Create a temp git repo, commit a secret, remove it, then scan:

```bash
section "Git History Scanning"
HIST_REPO="$TMPDIR/hist-repo"
mkdir -p "$HIST_REPO"
echo 'AWS_KEY="AKIAIOSFODNN7EXAMPLE"' > "$HIST_REPO/config.py"
(cd "$HIST_REPO" && git init -q && git add -A && git commit -q -m "add config" 2>/dev/null)
echo 'AWS_KEY="use-env-variable"' > "$HIST_REPO/config.py"
(cd "$HIST_REPO" && git add -A && git commit -q -m "remove secret" 2>/dev/null)

HIST_OUTPUT="$TMPDIR/hist-findings.jsonl"
bash "$SKILL_DIR/scripts/scan-secrets.sh" "$HIST_REPO" "$PATTERNS" "$HIST_OUTPUT" 2>/dev/null
assert "Detects secret in git history" "grep -q 'hist-aws-key\|git-history' '$HIST_OUTPUT'"
```

- [ ] **Step 5: Run tests**

```bash
bash tests/test-e2e.sh
```

- [ ] **Step 6: Commit**

```bash
git add skills/security-audit/scripts/scan-secrets.sh skills/security-audit/scripts/scan-secrets.py skills/security-audit/SKILL.md tests/test-e2e.sh
git commit -m "feat: add git history scanning for high-confidence secrets (6 patterns, 1000 commit limit)"
```

---

### Task 13: Final README update, test count, and version bump

**Files:**
- Modify: `README.md`
- Modify: `skills/security-audit/SKILL.md` (version number if applicable)

- [ ] **Step 1: Update all counts and sections in README**

Final state should reflect:
- ~85 regex patterns (44 original + 16 Tier 1 secrets + 15 Tier 2 IaC + 10 Tier 2 OWASP)
- 15 dangerous file type patterns
- ~20 curated dependency CVEs per ecosystem (npm, pip)
- Git history scanning (6 high-confidence patterns)
- Updated test count
- New "Dependency Scanning" and "Git History" sections

- [ ] **Step 2: Update the How It Works diagram**

Add Phase 2c (Git History) to the diagram.

- [ ] **Step 3: Run final test suite**

```bash
bash tests/test-e2e.sh
```
Expected: ALL TESTS PASSED

- [ ] **Step 4: Commit**

```bash
git add README.md skills/security-audit/SKILL.md
git commit -m "docs: final README update for v2 (85 patterns, dep scanning, git history)"
```

---

## Implementation Order Summary

| Task | Tier | Description | Est. Steps |
|------|------|-------------|------------|
| 1 | T1 | Bash file filtering performance | 5 |
| 2 | T1 | Single-pass dangerous file scan | 3 |
| 3 | T1 | Charset-aware entropy detection | 6 |
| 4 | T1 | Add 16 secret patterns | 6 |
| 5 | T1 | Rewrite LLM Phase 3 | 3 |
| 6 | T1 | README + test updates for Tier 1 | 4 |
| 7 | T2 | IaC security patterns (15 patterns) | 7 |
| 8 | T2 | OWASP vuln patterns (10 patterns) | 7 |
| 9 | T2 | IaC severity guidance | 2 |
| 10 | T2 | README + test updates for Tier 2 | 3 |
| 11 | T3 | Dependency vulnerability scanning | 8 |
| 12 | T3 | Git history scanning | 6 |
| 13 | T3 | Final README and version bump | 4 |
| **Total** | | | **64 steps** |
