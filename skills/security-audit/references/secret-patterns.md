# Secret Detection Patterns

Regex patterns for detecting hardcoded secrets in source code. Organized by base severity.

Patterns are validated against [GitLeaks](https://github.com/gitleaks/gitleaks) and
[GitHub Secret Scanning](https://docs.github.com/en/code-security/secret-scanning) to
ensure accuracy. Where our patterns diverge, the rationale is documented.

Each pattern includes:
- **Name**: human-readable identifier (maps to pattern ID in reports)
- **Regex**: detection pattern (PCRE-compatible where possible, ERE fallback noted)
- **Severity**: base severity before contextual adjustment
- **Description**: what this pattern detects and why it matters
- **Source**: which tool/standard this pattern is validated against

---

## Critical Patterns

Credentials that grant broad or production-level access. Immediate remediation required.

### AWS Access Key ID

- **Regex**: `\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b`
- **Description**: AWS access key IDs use base32 encoding (A-Z, 2-7) after a 4-character prefix. AKIA = long-term, ASIA = temporary (STS), ABIA = AWS STS service bearer token, ACCA = context-specific credential.
- **Source**: GitLeaks `aws-access-token`. Uses `[A-Z2-7]` (not `[A-Z0-9]`) because AWS keys are base32-encoded.

### Private Key (PEM Block)

- **Regex**: `-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----[\s\S-]{64,}?KEY(?: BLOCK)?-----`
- **Description**: Matches full PEM-encoded private key blocks including content, not just the header. Catches RSA, DSA, EC, OPENSSH, PGP, and other private key types. Matching the full block reduces false positives from comments or documentation that mention the header format.
- **Source**: GitLeaks `private-key`. Matching the full block (not just header) is important to avoid flagging comments that mention the header string.

### GCP Service Account Key

- **Regex**: `"type"\s*:\s*"service_account"`
- **Description**: Google Cloud service account JSON key file marker. When present alongside `"private_key"`, confirms a full service account credential. Grants programmatic access to GCP resources scoped to the service account's IAM roles.
- **Source**: Custom pattern. GCP service account JSON files always contain this exact field. Pair with a check for `"private_key"` in the same file for higher confidence.

### GCP API Key

- **Regex**: `\b(AIza[\w-]{35})\b`
- **Description**: Google API keys follow the `AIza` prefix with 35 alphanumeric/dash/underscore characters. Severity depends on key restrictions — unrestricted keys are critical, restricted keys may be lower.
- **Source**: GitLeaks `gcp-api-key`.

### Stripe Secret Key

- **Regex**: `\b((?:sk|rk)_(?:test|live|prod)_[a-zA-Z0-9]{10,99})\b`
- **Description**: Stripe secret keys (`sk_`) and restricted keys (`rk_`) across all environments (live, test, prod). Live keys grant full production access. Test keys are lower severity but still should not be committed.
- **Source**: GitLeaks `stripe-access-token`. Includes `rk_` (restricted keys) and all environment prefixes, not just `sk_live_`.

### Azure Storage Connection String

- **Regex**: `DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+\/=]{86,}`
- **Description**: Azure Storage connection string with embedded account key. The AccountKey is a base64-encoded 512-bit key (86+ chars).
- **Source**: Custom pattern validated against Azure documentation. The 86-char minimum matches the base64 encoding of a 512-bit key.

### Azure AD Client Secret

- **Regex**: `([a-zA-Z0-9_~.]{3}\dQ~[a-zA-Z0-9_~.-]{31,34})`
- **Description**: Azure Active Directory client secrets follow a specific format with `Q~` as a distinguishing marker.
- **Source**: GitLeaks `azure-ad-client-secret`.

### Database Root/Admin Password

- **Regex**: `(?i)(root|admin)(.{0,20})password\s*[:=]\s*['\"][^'\"]{8,}['\"]`
- **Description**: Hardcoded root or admin database password in assignments or configuration. The 8-char minimum avoids flagging empty or trivially short placeholders.
- **Source**: Custom pattern. Contextual — the LLM should verify this isn't a placeholder or documentation example.

---

## High Patterns

Scoped credentials or tokens. Exploitation requires some additional context.

### GitHub Personal Access Token (Classic)

- **Regex**: `ghp_[0-9a-zA-Z]{36}`
- **Description**: GitHub classic PAT with configurable scopes (repo, workflow, admin, etc.).
- **Source**: GitLeaks `github-pat`. Matches GitHub's documented token format.

### GitHub Personal Access Token (Fine-Grained)

- **Regex**: `github_pat_\w{82}`
- **Description**: GitHub fine-grained PAT with repository-level and permission-level scoping.
- **Source**: GitLeaks `github-fine-grained-pat`.

### GitHub OAuth Token

- **Regex**: `gho_[0-9a-zA-Z]{36}`
- **Description**: GitHub OAuth access token generated through OAuth app authorization flows.
- **Source**: GitLeaks `github-oauth`.

### GitLab Personal Access Token

- **Regex**: `glpat-[\w-]{20}`
- **Description**: GitLab PAT granting API access scoped to user permissions.
- **Source**: GitLeaks `gitlab-pat`.

### GitLab Runner Authentication Token

- **Regex**: `glrt-[0-9a-zA-Z_\-]{20}`
- **Description**: GitLab CI runner registration/authentication token.
- **Source**: GitLeaks `gitlab-runner-authentication-token`.

### Slack Bot Token

- **Regex**: `xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*`
- **Description**: Slack bot token granting API access to a workspace. The format includes workspace and bot IDs as numeric segments.
- **Source**: GitLeaks `slack-bot-token`. More specific than a generic `xox[baprs]-` catch-all, reducing false positives.

### Slack User Token

- **Regex**: `xox[pe](?:-[0-9]{10,13}){3}-[a-zA-Z0-9-]{28,34}`
- **Description**: Slack user or enterprise token with broader permissions than bot tokens.
- **Source**: GitLeaks `slack-user-token`.

### Slack Webhook URL

- **Regex**: `hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9+/]{43,56}`
- **Description**: Slack incoming webhook, workflow webhook, or trigger URL. Allows posting messages or triggering automations.
- **Source**: GitLeaks `slack-webhook-url`. Covers services, workflows, and triggers paths.

### SendGrid API Key

- **Regex**: `\b(SG\.(?i)[a-z0-9=_\-\.]{66})\b`
- **Description**: SendGrid API key. The `SG.` prefix followed by 66 characters is the documented format.
- **Source**: GitLeaks `sendgrid-api-token`. Fixed-length match is more accurate than our original split format.

### Twilio API Key

- **Regex**: `SK[0-9a-fA-F]{32}`
- **Description**: Twilio API key SID (32 hex chars after `SK` prefix).
- **Source**: GitLeaks `twilio-api-key`. Confirmed format.

### Database Connection String

- **Regex**: `(?i)(mongodb(\+srv)?|postgres(ql)?|mysql|redis|mssql|mariadb):\/\/[^\s'\"]{10,}`
- **Description**: Database connection URI likely containing embedded credentials (user:pass@host format). Severity depends on whether credentials are present in the string.
- **Source**: Custom pattern. The LLM should verify credentials are actually embedded (look for `user:pass@` format) vs credential-less URIs.

### Generic Password Assignment

- **Regex**: `(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{8,}['\"]`
- **Description**: Hardcoded password in an assignment or configuration. The 8-char minimum filters out empty or trivially short values.
- **Source**: Custom pattern. High false-positive rate — the LLM should verify context (test file? placeholder?).

### Heroku API Key

- **Regex**: `\b(HRKU-AA[0-9a-zA-Z_-]{58})\b`
- **Description**: Heroku platform API key in the current v2 format.
- **Source**: GitLeaks `heroku-api-key-v2`. The older UUID-based format is deprecated.

### Mailgun Private API Token

- **Regex**: `(key-[a-f0-9]{32})`
- **Description**: Mailgun private API key (32 hex chars after `key-` prefix).
- **Source**: GitLeaks `mailgun-private-api-token`.

### NPM Access Token

- **Regex**: `\b(npm_[a-z0-9]{36})\b`
- **Description**: NPM automation or publish token for the npm registry.
- **Source**: GitLeaks `npm-access-token`. Note: lowercase alphanumeric only.

### PyPI Upload Token

- **Regex**: `pypi-AgEIcHlwaS5vcmc[\w-]{50,1000}`
- **Description**: PyPI upload token with the fixed `pypi-AgEIcHlwaS5vcmc` prefix (base64-encoded "pypi.org" issuer).
- **Source**: GitLeaks `pypi-upload-token`. The fixed prefix is more accurate than a generic `pypi-` match.

### Rubygems API Token

- **Regex**: `\b(rubygems_[a-f0-9]{48})\b`
- **Description**: Rubygems API token for publishing Ruby gems.
- **Source**: GitLeaks `rubygems-api-token`.

### OpenAI API Key

- **Regex**: `\b(sk-(?:proj|svcacct|admin)-(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})T3BlbkFJ)\b`
- **Description**: OpenAI API key with project, service account, or admin prefix. Contains embedded `T3BlbkFJ` (base64 "OpenAI") marker.
- **Source**: GitLeaks `openai-api-key`.

### JWT (Exposed Token)

- **Regex**: `\b(ey[a-zA-Z0-9]{17,}\.ey[a-zA-Z0-9\/\\_-]{17,}\.(?:[a-zA-Z0-9\/\\_-]{10,}={0,2})?)\b`
- **Description**: Actual JWT token value (base64url-encoded header.payload.signature). Detects hardcoded tokens, not variable names. The `ey` prefix is the base64url encoding of `{"` which all JWT headers start with.
- **Source**: GitLeaks `jwt`. Note: this detects token values, not signing secrets. The LLM should assess if the token is expired, a test token, or contains sensitive claims.

---

## Medium Patterns

Suspected secrets needing manual verification. Higher false-positive rate.

### JWT Signing Secret (Variable Assignment)

- **Regex**: `(?i)(jwt|token)[\s_-]*(secret|key)\s*[:=]\s*['\"][^'\"]{8,}['\"]`
- **Description**: Hardcoded JWT signing secret in a variable assignment. If real, allows forging valid tokens. Moved from High to Medium because variable assignments have a high false-positive rate (test values, placeholders).
- **Source**: Custom pattern. Requires LLM verification of whether the value is a real secret or placeholder.

### Generic API Key Assignment

- **Regex**: `(?i)(api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*['\"][0-9a-zA-Z]{16,}['\"]`
- **Description**: Generic API key or secret in an assignment. May be a real key or a placeholder.
- **Source**: Custom pattern. The LLM should check if the value looks random (real key) or structured (placeholder).

### Generic Secret/Token Assignment

- **Regex**: `(?i)(secret|token|credential|auth)[_-]?(key|token|secret)?\s*[:=]\s*['\"][^'\"]{12,}['\"]`
- **Description**: Generic secret or token assignment. Broad pattern with high recall but also high false positives.
- **Source**: Custom pattern. Context-dependent — downgrade if in test/example files.

### Base64-Encoded Secret

- **Regex**: `(?i)(secret|key|token|password)\s*[:=]\s*['\"][A-Za-z0-9+\/=]{40,}['\"]`
- **Description**: Long base64-encoded string assigned to a secret-like variable name.
- **Source**: Custom pattern. The length threshold (40+) reduces noise but still requires LLM verification.

### Private Key in Variable

- **Regex**: `(?i)(private[_-]?key|priv[_-]?key)\s*[:=]\s*['\"][^'\"]{20,}['\"]`
- **Description**: Private key content stored in a variable rather than a PEM file.
- **Source**: Custom pattern. May overlap with PEM block detection — LLM should deduplicate.

### Encryption Key/IV

- **Regex**: `(?i)(encryption[_-]?key|aes[_-]?key|cipher[_-]?key|iv|initialization[_-]?vector)\s*[:=]\s*['\"][0-9a-fA-F]{16,}['\"]`
- **Description**: Hardcoded encryption key or initialization vector in hex format.
- **Source**: Custom pattern. Hex-only constraint reduces false positives.

### High-Entropy String Detection

- **Note**: Not a regex pattern. Implemented in `scripts/scan-secrets.py` using Shannon entropy calculation. Strings > 20 characters with entropy > 4.5 in assignment contexts (`key`, `secret`, `token`, `password`, `credential` variable names) are flagged.
- **Description**: Catches secrets that don't match any specific format pattern but exhibit high randomness.
- **Source**: Based on [detect-secrets](https://github.com/Yelp/detect-secrets) entropy detection approach.

---

## Dangerous File Types

File-level findings where the mere presence of the file in a git repository is a security issue, regardless of contents. These are detected via `git ls-files --cached` (only tracked files are flagged — gitignored files are fine).

All dangerous file findings use `line: 0` to indicate a file-level finding, not a line-level match. The match field is set to `"(entire file)"`.

### Terraform State Files

- **Pattern**: `*.tfstate`, `*.tfstate.backup`
- **Severity**: HIGH
- **Pattern IDs**: `dangerous-file-tfstate`, `dangerous-file-tfstate-backup`
- **Description**: Terraform state files contain a full inventory of infrastructure: resource IDs, ARNs, account IDs, VPC IDs, S3 bucket names, endpoints, and sometimes secrets (database passwords, API keys stored in resource attributes). They should never be committed to version control — use remote state backends (S3, GCS, Terraform Cloud) instead.
- **Remediation**: Add `*.tfstate` and `*.tfstate.backup` to `.gitignore`. Remove from git history with `git filter-repo`. Configure a remote state backend.

### Terraform Output Files

- **Pattern**: `*terraform-apply-output*`, `*terraform-plan-output*`
- **Severity**: MEDIUM
- **Pattern IDs**: `dangerous-file-tf-apply-output`, `dangerous-file-tf-plan-output`
- **Description**: Captured output from `terraform apply` or `terraform plan` commands. These expose resource inventory details (VPC IDs, ARNs, endpoints, IP addresses) that aid infrastructure mapping by attackers. Apply output is higher risk than plan output as it reflects actual deployed state.
- **Remediation**: Add these files to `.gitignore`. If infrastructure details must be shared, use Terraform outputs with `sensitive = true` and share via secure channels.

### Private Key Files

- **Pattern**: `*.pem`, `*.key`, `*.p12`, `*.pfx`
- **Severity**: CRITICAL
- **Pattern IDs**: `dangerous-file-pem`, `dangerous-file-key`, `dangerous-file-p12`, `dangerous-file-pfx`
- **Description**: Private key files (PEM, DER, PKCS#12) should never be committed. Even if the key is password-protected (`.p12`, `.pfx`), the encrypted file in a public repo enables offline brute-force attacks. `.pem` and `.key` files are often unencrypted.
- **Remediation**: Add `*.pem *.key *.p12 *.pfx` to `.gitignore`. Remove from git history. Rotate any exposed key material. Store keys in secrets managers or use certificate authorities that issue short-lived certs.

### Java Keystore

- **Pattern**: `*.jks`
- **Severity**: HIGH
- **Pattern ID**: `dangerous-file-jks`
- **Description**: Java KeyStore files contain private keys and certificates. Though password-protected, they enable offline brute-force attacks if committed.
- **Remediation**: Add `*.jks` to `.gitignore`. Remove from git history. Rotate keystores and re-issue certificates.

### Cloud Credentials Files

- **Pattern**: `credentials.json` (exact name), `service-account*.json`
- **Severity**: HIGH
- **Pattern IDs**: `dangerous-file-credentials-json`, `dangerous-file-service-account`
- **Description**: Cloud provider credential files, most commonly GCP service account keys or AWS credential exports. These grant programmatic access to cloud resources.
- **Remediation**: Add to `.gitignore`. Use workload identity federation or IAM roles instead of exported key files. Rotate compromised service account keys.

### Terraform Provider Cache

- **Pattern**: `.terraform/` directory contents
- **Severity**: MEDIUM
- **Pattern ID**: `dangerous-file-terraform-cache`
- **Description**: The `.terraform/` directory contains downloaded provider plugins, module caches, and state lock files. It should always be gitignored. Committing it bloats the repo and may expose internal module registry URLs.
- **Remediation**: Add `.terraform/` to `.gitignore`. Remove from git history.

### Database Files

- **Pattern**: `*.sqlite`, `*.db`
- **Severity**: MEDIUM
- **Pattern IDs**: `dangerous-file-sqlite`, `dangerous-file-db`
- **Description**: Database files may contain sensitive application data, user records, or credentials. They should not be committed to version control.
- **Remediation**: Add `*.sqlite *.db` to `.gitignore`. If test databases are needed, use fixtures or migration scripts instead.

### Files with "secret" in Name

- **Pattern**: `*secret*` (excluding `*.example`, `*.sample`, `*.template`, `*.md`)
- **Severity**: MEDIUM
- **Pattern ID**: `dangerous-file-secret-name`
- **Description**: Files with "secret" in their name often contain sensitive configuration, keys, or credentials. Excluded extensions (`.example`, `.sample`, `.template`, `.md`) are commonly used for documentation or templates.
- **Remediation**: Verify contents. If the file contains real secrets, remove from git and add to `.gitignore`. If it's a template, rename to include `.example` or `.template` extension.
