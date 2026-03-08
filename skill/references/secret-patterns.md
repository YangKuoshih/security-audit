# Secret Detection Patterns

Regex patterns for detecting hardcoded secrets in source code. Organized by base severity.

Each pattern includes:
- **Name**: human-readable identifier
- **Regex**: detection pattern (PCRE-compatible)
- **Severity**: base severity before contextual adjustment
- **Description**: what this pattern detects
- **Example**: redacted example of a match

---

## Critical Patterns

These patterns detect credentials that grant broad or production-level access. Findings require immediate action.

### AWS Access Key ID

- **Regex**: `(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`
- **Description**: AWS access key IDs start with known prefixes (AKIA for long-term, ASIA for temporary). These grant API access to AWS services.
- **Example**: `AKIA...EXAMPLE` (20 characters)

### AWS Secret Access Key

- **Regex**: `(?i)aws(.{0,20})?(?-i)['\"][0-9a-zA-Z\/+]{40}['\"]`
- **Description**: 40-character base64 string near the word "aws". Used alongside the Access Key ID.
- **Example**: `"wJal...EKEY"` (40 characters)

### RSA/SSH/PGP Private Key

- **Regex**: `-----BEGIN (RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY( BLOCK)?-----`
- **Description**: PEM-encoded private key header. Presence in a repo means the private key is fully exposed.
- **Example**: `-----BEGIN RSA PRIVATE KEY-----`

### GCP Service Account Key

- **Regex**: `"type"\s*:\s*"service_account"`
- **Description**: Google Cloud service account JSON key file. Grants programmatic access to GCP resources.
- **Example**: `"type": "service_account"`

### Stripe Live Secret Key

- **Regex**: `sk_live_[0-9a-zA-Z]{24,}`
- **Description**: Stripe live-mode secret key. Grants full access to a Stripe account in production.
- **Example**: `sk_live_abcd...wxyz`

### Database Root/Admin Password

- **Regex**: `(?i)(root|admin)(.{0,20})password\s*[:=]\s*['\"][^'\"]{8,}['\"]`
- **Description**: Hardcoded root or admin database password.
- **Example**: `root_password = "sup3r...t123"`

### Azure Storage Account Key

- **Regex**: `DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+\/=]{86,}`
- **Description**: Azure Storage connection string with embedded account key.
- **Example**: `DefaultEndpointsProtocol=https;AccountName=myacct;AccountKey=abc1...xyz=`

### Google API Key (restricted)

- **Regex**: `AIza[0-9A-Za-z\-_]{35}`
- **Description**: Google API key. Severity depends on key restrictions — unrestricted keys are critical.
- **Example**: `AIzaSy...abc123`

---

## High Patterns

These patterns detect scoped credentials or tokens. Exploitation requires some additional context.

### GitHub Personal Access Token (Classic)

- **Regex**: `ghp_[0-9a-zA-Z]{36}`
- **Description**: GitHub classic personal access token with configurable scopes.
- **Example**: `ghp_abcd...wxyz1234`

### GitHub Personal Access Token (Fine-Grained)

- **Regex**: `github_pat_[0-9a-zA-Z_]{82}`
- **Description**: GitHub fine-grained personal access token with repository-level permissions.
- **Example**: `github_pat_abcd...wxyz`

### GitLab Personal Access Token

- **Regex**: `glpat-[0-9a-zA-Z\-_]{20}`
- **Description**: GitLab personal access token.
- **Example**: `glpat-abcd...wxyz1234`

### Slack Token

- **Regex**: `xox[baprs]-[0-9a-zA-Z\-]{10,}`
- **Description**: Slack bot, app, or user token. Grants API access to a Slack workspace.
- **Example**: `xoxb-1234...mnop`

### Slack Webhook URL

- **Regex**: `https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[a-zA-Z0-9]{24}`
- **Description**: Slack incoming webhook URL. Allows posting messages to a channel.
- **Example**: `https://hooks.slack.com/services/T.../B.../abc...xyz`

### SendGrid API Key

- **Regex**: `SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}`
- **Description**: SendGrid API key for sending emails.
- **Example**: `SG.abcd...wxyz.1234...6789`

### Twilio API Key

- **Regex**: `SK[0-9a-fA-F]{32}`
- **Description**: Twilio API key SID.
- **Example**: `SKabcd...wxyz12345678`

### JWT Signing Secret

- **Regex**: `(?i)(jwt|token)[\s_-]*(secret|key)\s*[:=]\s*['\"][^'\"]{8,}['\"]`
- **Description**: Hardcoded JWT signing secret. Allows forging valid tokens.
- **Example**: `jwt_secret = "my_s...et_k"`

### Database Connection String

- **Regex**: `(?i)(mongodb(\+srv)?|postgres(ql)?|mysql|redis|mssql|mariadb):\/\/[^\s'\"]{10,}`
- **Description**: Database connection URI with embedded credentials.
- **Example**: `postgres://user:pa...@host:5432/db`

### Generic Password Assignment

- **Regex**: `(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{8,}['\"]`
- **Description**: Hardcoded password in an assignment or configuration.
- **Example**: `password = "my_s...ord"`

### Heroku API Key

- **Regex**: `(?i)heroku(.{0,20})?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`
- **Description**: Heroku API key in UUID format near the word "heroku".
- **Example**: `HEROKU_API_KEY=abcd1234-...`

### Mailgun API Key

- **Regex**: `key-[0-9a-zA-Z]{32}`
- **Description**: Mailgun API key.
- **Example**: `key-abcd1234...wxyz5678`

### NPM Access Token

- **Regex**: `npm_[0-9a-zA-Z]{36}`
- **Description**: NPM automation or publish token.
- **Example**: `npm_abcd1234...wxyz5678`

### PyPI API Token

- **Regex**: `pypi-[0-9a-zA-Z\-_]{16,}`
- **Description**: PyPI upload token for publishing Python packages.
- **Example**: `pypi-abcd1234...wxyz`

---

## Medium Patterns

These patterns detect suspected secrets needing manual verification.

### Generic API Key Assignment

- **Regex**: `(?i)(api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*['\"][0-9a-zA-Z]{16,}['\"]`
- **Description**: Generic API key or secret in an assignment. May be a real key or a placeholder.
- **Example**: `api_key = "abcd...wxyz"`

### Generic Secret/Token Assignment

- **Regex**: `(?i)(secret|token|credential|auth)[_-]?(key|token|secret)?\s*[:=]\s*['\"][^'\"]{12,}['\"]`
- **Description**: Generic secret or token assignment. Requires context to determine if real.
- **Example**: `auth_token = "abcd...wxyz"`

### Base64-Encoded Secret

- **Regex**: `(?i)(secret|key|token|password)\s*[:=]\s*['\"][A-Za-z0-9+\/=]{40,}['\"]`
- **Description**: Long base64-encoded string assigned to a secret-like variable. May be an encoded credential.
- **Example**: `secret = "dGhpc2lz...c2VjcmV0"`

### Private Key in Variable

- **Regex**: `(?i)(private[_-]?key|priv[_-]?key)\s*[:=]\s*['\"][^'\"]{20,}['\"]`
- **Description**: Private key content stored in a variable (not PEM-wrapped).
- **Example**: `private_key = "MIIEv..."`

### Encryption Key/IV

- **Regex**: `(?i)(encryption[_-]?key|aes[_-]?key|cipher[_-]?key|iv|initialization[_-]?vector)\s*[:=]\s*['\"][0-9a-fA-F]{16,}['\"]`
- **Description**: Hardcoded encryption key or initialization vector.
- **Example**: `aes_key = "0123...cdef"`

### High-Entropy String Detection

- **Note**: This pattern requires entropy calculation, not just regex. The Python scanner (`scan-secrets.py`) handles this by computing Shannon entropy on string values > 20 characters. Strings with entropy > 4.5 in secret-like contexts are flagged.
- **Description**: Strings with high randomness in configuration or assignment contexts that may be secrets.
