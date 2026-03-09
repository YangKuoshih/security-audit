# Severity Classification Guide

Rules for classifying and adjusting finding severity. Used by the LLM during Phase 3
(Analysis) to produce consistent, defensible severity ratings.

---

## Severity Tier Definitions

| Severity | Criteria | Action Timeline | Examples |
|----------|----------|----------------|---------|
| **Critical** | Credentials granting broad or production-level access. Immediate exploitation risk if exposed. Attacker can access production systems, customer data, or infrastructure. | Immediate — rotate credential and remediate within hours | AWS root keys, cloud service account keys, RSA/SSH private keys, database root passwords, Stripe live secret keys |
| **High** | Scoped credentials or tokens. Exploitation requires some context but provides meaningful access to systems or data. | Urgent — remediate within 1-2 business days | GitHub PATs, Slack tokens, SMTP credentials, JWT signing secrets, database connection strings with credentials, OpenAI API keys |
| **Medium** | Suspected secrets needing verification, or confirmed vulnerability patterns (injection sinks, weak crypto). May or may not be exploitable depending on context. | Standard — remediate within 1-2 weeks | High-entropy strings in config, SQL injection sinks, XSS vectors, insecure deserialization, generic API key assignments |
| **Low** | Best practice violations with no direct exploit path. Security hygiene issues that increase attack surface over time. | Planned — address in next maintenance cycle | Debug mode in production, permissive CORS, disabled SSL verification in non-guarded code, security TODOs |

---

## Contextual Adjustment Rules

Every finding starts with a **base severity** from the pattern match. The LLM adjusts
this based on context. Adjustments are documented in the finding's Context field.

### Downgrade Triggers (Reduce Severity by One Tier)

Apply these when evidence suggests the finding is less impactful than the base severity implies. Multiple downgrade triggers can stack, but never reduce below Low.

**File path context — test/example/documentation:**
- File path contains: `test/`, `tests/`, `spec/`, `__tests__/`, `__mocks__/`
- File path contains: `example/`, `examples/`, `sample/`, `demo/`, `tutorial/`
- File path contains: `doc/`, `docs/`, `documentation/`
- File path contains: `fixtures/`, `testdata/`, `mock/`, `mocks/`, `stubs/`
- File extension: `.md`, `.rst`, `.txt`, `.adoc` (documentation files)
- File name: `README`, `CONTRIBUTING`, `CHANGELOG`

**Value context — placeholder patterns:**
- Value matches common placeholders: `xxx`, `XXX`, `changeme`, `CHANGEME`, `TODO`, `FIXME`
- Value matches example markers: `example`, `EXAMPLE`, `test`, `TEST`, `dummy`, `DUMMY`
- Value matches filler patterns: `fake`, `sample`, `placeholder`, `your-key-here`, `INSERT_KEY`, `replace-me`
- Value is all same character: `aaaa...`, `0000...`, `****...`
- Value matches AWS example format: `AKIAIOSFODNN7EXAMPLE`, `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`

**Configuration context — development environment:**
- File name contains: `.env.development`, `.env.local`, `.env.test`
- Variable name contains: `dev`, `local`, `test`, `staging` (in combination with secret-like value)
- Docker Compose file with `environment` section in development context

### Upgrade Triggers (Increase Severity by One Tier)

Apply these when evidence suggests the finding is more impactful than the base severity implies. Multiple upgrade triggers can stack, but never increase above Critical.

**File path context — production/deployment:**
- File path contains: `deploy/`, `deployment/`, `production/`, `infra/`, `terraform/`, `ansible/`
- File path contains: `k8s/`, `kubernetes/`, `helm/`, `.github/workflows/`
- File name: `.env.production`, `.env.prod`, `docker-compose.prod.yml`
- File name: `Dockerfile`, `serverless.yml`, `cloudbuild.yaml`

**Environment context — production indicators:**
- Value is paired with production URLs (e.g., `prod.example.com`, `api.example.com`)
- Value is paired with production database hostnames or cloud resource identifiers
- File contains other production configuration (production endpoints, production bucket names)
- Connection string points to a non-localhost, non-private-range host

**Pattern context — high-specificity match:**
- Secret matches a vendor-specific format exactly (e.g., `AKIA` prefix, `ghp_` prefix, `sk_live_`)
- Private key block is complete (header + content + footer), not just a header reference

---

## Confidence Level Assignment

Confidence indicates how certain we are that the finding is a real security issue.

| Confidence | Criteria | Guidance |
|------------|----------|----------|
| **High** | Exact match on vendor-specific format with correct structure (prefix, length, character set). Pattern is highly specific with very low false-positive rate. | Report as-is. Typically no manual verification needed. |
| **Medium** | Generic pattern match that could be a real secret or could be a false positive. Requires context to determine. | Report with note that verification is recommended. The LLM should provide its contextual assessment. |
| **Low** | Heuristic match based on variable naming, entropy, or proximity to sensitive operations. Significant chance of false positive. | Report with clear caveat. User should verify before taking action. Consider omitting if severity minimum is set. |

### Confidence by Pattern Type

**High confidence patterns** (vendor-specific formats):
- AWS Access Key ID (`AKIA`, `ASIA` prefixes with base32)
- GitHub PATs (`ghp_`, `github_pat_`)
- GitLab PATs (`glpat-`)
- Slack tokens (`xoxb-`, `xoxp-` with numeric segments)
- Stripe keys (`sk_live_`, `sk_test_`)
- SendGrid (`SG.` with exact length)
- Private key PEM blocks (full header + content + footer)
- OpenAI keys (`sk-proj-`, `sk-admin-` with `T3BlbkFJ` marker)

**Medium confidence patterns** (format match but context-dependent):
- Database connection strings (may or may not contain credentials)
- JWT tokens (may be expired or test tokens)
- Password assignments (may be placeholders)
- Heroku keys, Twilio keys (format is less distinctive)
- Generic API key assignments

**Low confidence patterns** (heuristic/broad):
- High-entropy string detection
- Generic secret/token assignments
- Base64-encoded values in secret-like variables
- Vulnerability patterns (SQL injection sinks, XSS vectors — require reachability analysis)

---

## Finding ID Format

Assign sequential IDs per severity tier within each report:

| Severity | Prefix | Format | Example |
|----------|--------|--------|---------|
| Critical | C | C-NNN | C-001, C-002 |
| High | H | H-NNN | H-001, H-002 |
| Medium | M | M-NNN | M-001, M-002 |
| Low | L | L-NNN | L-001, L-002 |

IDs are scoped to a single report run. They are not globally unique across scans.

---

## Deduplication Rules

When multiple patterns match the same line or finding:

1. **Same secret, multiple patterns**: Keep the most specific pattern match (e.g., if both "AWS Access Key ID" and "Generic API Key Assignment" match, keep "AWS Access Key ID")
2. **Same line, different finding types**: Report both (e.g., a line with both a hardcoded password and SQL concatenation)
3. **PEM key + variable assignment**: If a private key PEM block is detected AND the same key is assigned to a variable, report only the PEM block finding (higher confidence)
4. **Overlapping vulnerability patterns**: If a function call matches both "SQL Injection" and "Command Injection" patterns, report both — they represent different risk categories

---

## Remediation Guidance Principles

When generating remediation advice:

1. **Be specific to the finding**: "Move AWS key to environment variable" not "Fix the security issue"
2. **Reference the tech stack**: If the repo uses Node.js, suggest `process.env.AWS_ACCESS_KEY_ID`. If Python, suggest `os.environ.get('AWS_ACCESS_KEY_ID')`
3. **Credential rotation**: For any confirmed secret (High confidence, High+ severity), always recommend rotation in addition to removal
4. **Suggest tools**: Reference relevant secrets managers (AWS Secrets Manager, HashiCorp Vault, GitHub Secrets) based on the detected ecosystem
5. **Git history warning**: Note that removing a secret from code does not remove it from git history. Recommend `git filter-repo` or BFG Repo-Cleaner for committed secrets
6. **Don't over-prescribe**: For Medium/Low confidence findings, suggest investigation rather than immediate action
