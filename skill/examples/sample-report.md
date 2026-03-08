# Security Audit Report

**Scan date:** 2026-03-08 22:49 UTC
**Total findings:** 21
**Summary:** 3 Critical, 4 High, 11 Medium, 3 Low

---

## Critical (3)

### [C-001] AWS Access Key ID

- **File:** `leaky-config.js:8`
- **Pattern:** aws-access-key
- **Match:** `AKIA...MPLE`
- **Remediation:** Remove the key from source code. Use environment variables or AWS Secrets Manager. Rotate the key immediately via the AWS IAM console.

### [C-002] Stripe Secret Key

- **File:** `leaky-config.js:35`
- **Pattern:** stripe-secret-key
- **Match:** `sk_l...uvwx`
- **Remediation:** Remove the key from source code. Use environment variables. Rotate the key in the Stripe dashboard. If this is a live key, check for unauthorized transactions.

### [C-003] Private Key (PEM Block)

- **File:** `private-key.pem:1`
- **Pattern:** private-key-block
- **Match:** `----... KEY`
- **Remediation:** Remove the private key from the repository. Add the file to .gitignore. Rotate the key pair. Use a secrets vault for key storage. Note: the key remains in git history — use git filter-repo or BFG Repo-Cleaner to purge it.

## High (4)

### [H-001] GitHub PAT (Classic)

- **File:** `leaky-config.js:15`
- **Pattern:** github-pat-classic
- **Match:** `ghp_...1234`
- **Remediation:** Remove the token from source code. Rotate it at github.com/settings/tokens. Use GitHub Actions secrets or environment variables.

### [H-002] Slack Bot Token

- **File:** `leaky-config.js:20`
- **Pattern:** slack-bot-token
- **Match:** `xoxb...mnop`
- **Remediation:** Remove the token from source code. Rotate it in the Slack app settings. Use environment variables.

### [H-003] Database Connection String

- **File:** `leaky-config.js:25`
- **Pattern:** db-connection-string
- **Match:** `post...yapp`
- **Remediation:** Remove credentials from the connection string. Use environment variables or a secrets manager for database credentials.

### [H-004] Password Assignment

- **File:** `leaky-config.js:30`
- **Pattern:** password-assignment
- **Match:** `pass...026"`
- **Remediation:** Remove hardcoded password. Use environment variables or a secrets manager.

## Medium (11)

### [M-001] Generic Secret/Token Assignment

- **File:** `leaky-config.js:15`
- **Pattern:** generic-secret
- **Match:** `toke...234"`
- **Remediation:** Verify this is a real secret. If confirmed, move to environment variables or a secrets manager.

### [M-002] High-Entropy String (entropy=5.32)

- **File:** `leaky-config.js:15`
- **Pattern:** high-entropy
- **Match:** `ghp_...1234`
- **Remediation:** Verify whether this high-entropy string is a real secret. If confirmed, move to environment variables.

### [M-003] High-Entropy String (entropy=4.62)

- **File:** `leaky-config.js:20`
- **Pattern:** high-entropy
- **Match:** `xoxb...mnop`
- **Remediation:** Verify whether this high-entropy string is a real secret. If confirmed, move to environment variables.

### [M-004] High-Entropy String (entropy=4.56)

- **File:** `leaky-config.js:35`
- **Pattern:** high-entropy
- **Match:** `sk_l...uvwx`
- **Remediation:** Verify whether this high-entropy string is a real secret. If confirmed, move to environment variables.

### [M-005] SQL Injection (String Concat)

- **File:** `vulnerable-app.py:17`
- **Pattern:** sql-injection-concat
- **Match:** `curs... + u`
- **Remediation:** Use parameterized queries or prepared statements instead of string concatenation in SQL. Example: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))

### [M-006] SQL Injection (String Build)

- **File:** `vulnerable-app.py:17`
- **Pattern:** sql-injection-build
- **Match:** `SELE... + u`
- **Remediation:** Use parameterized queries instead of building SQL strings with concatenation.

### [M-007] Insecure Deserialization

- **File:** `vulnerable-app.py:28`
- **Pattern:** insecure-deserialize
- **Match:** `pi...ds`
- **Remediation:** Avoid deserializing untrusted data. For Python YAML, use yaml.safe_load(). For pickle, consider using JSON instead. Validate and sanitize input before deserialization.

### [M-008] Insecure Deserialization

- **File:** `vulnerable-app.py:34`
- **Pattern:** insecure-deserialize
- **Match:** `ya...d(`
- **Remediation:** Avoid deserializing untrusted data. For Python YAML, use yaml.safe_load(). For pickle, consider using JSON instead. Validate and sanitize input before deserialization.

### [M-009] Weak Cryptographic Algorithm

- **File:** `vulnerable-app.py:39`
- **Pattern:** weak-crypto
- **Match:** `****`
- **Remediation:** Replace MD5/SHA1 with SHA-256 or SHA-3 for integrity checks. For password hashing, use bcrypt, scrypt, or Argon2.

### [M-010] Command Injection

- **File:** `vulnerable-app.py:23`
- **Pattern:** command-injection
- **Match:** `subp...l(f"`
- **Remediation:** Avoid passing user input to shell commands. Use subprocess with a list argument (not shell=True). Validate and sanitize all inputs.

### [M-011] SSRF (Dynamic URL)

- **File:** `vulnerable-app.py:44`
- **Pattern:** ssrf-dynamic-url
- **Match:** `re...f"`
- **Remediation:** Validate and allowlist URLs before making HTTP requests. Block requests to internal/private IP ranges.

## Low (3)

### [L-001] Debug Mode Enabled

- **File:** `vulnerable-app.py:49`
- **Pattern:** debug-enabled
- **Match:** `DE...ue`
- **Remediation:** Ensure debug mode is disabled in production configurations.

### [L-002] Disabled SSL/TLS Verification

- **File:** `vulnerable-app.py:53`
- **Pattern:** ssl-verify-disabled
- **Match:** `ve...se`
- **Remediation:** Enable SSL/TLS verification in production. Only disable for local development with self-signed certificates.

### [L-003] Security TODO Comment

- **File:** `vulnerable-app.py:57`
- **Pattern:** security-todo
- **Match:** `TODO...lity`
- **Remediation:** Address the security concern described in this TODO comment.

---

## Scan Metadata

- **Generated by:** security-audit v0.1.0
- **Timestamp:** 2026-03-08 22:49 UTC
- **Total findings:** 21
- **Unique patterns matched:** 18
