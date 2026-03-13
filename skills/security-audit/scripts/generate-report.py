#!/usr/bin/env python3
"""
generate-report.py — Report generator for security-audit findings

Reads JSON Lines findings from the scanner and produces reports in
Markdown, SARIF 2.1.0, or JSON format.

Usage:
    python3 generate-report.py <findings_file> <format> <output_file>

Arguments:
    findings_file   Path to JSONL file from scan-secrets.sh or scan-secrets.py
    format          Output format: markdown, sarif, or json
    output_file     Output path (use - for stdout)
"""

import hashlib
import json
import sys
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path

TOOL_NAME = "security-audit"
TOOL_VERSION = "0.1.0"

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
SEVERITY_PREFIX = {"CRITICAL": "C", "HIGH": "H", "MEDIUM": "M", "LOW": "L"}

# SARIF severity mapping per GitHub Code Scanning requirements
SARIF_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}

# SARIF security-severity scores (0.1-10.0 scale)
SARIF_SECURITY_SEVERITY = {
    "CRITICAL": "9.5",
    "HIGH": "7.5",
    "MEDIUM": "5.0",
    "LOW": "2.5",
}


# ─── Load Findings ─────────────────────────────────────────────────────────

def load_findings(filepath: str) -> list[dict]:
    """Load findings from JSON Lines file."""
    findings = []
    with open(filepath, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                finding = json.loads(line)
                findings.append(finding)
            except json.JSONDecodeError as e:
                print(f"WARNING: Skipping malformed JSON on line {line_num}: {e}", file=sys.stderr)
    return findings


def group_by_severity(findings: list[dict]) -> OrderedDict[str, list[dict]]:
    """Group findings by severity in display order."""
    grouped: OrderedDict[str, list[dict]] = OrderedDict()
    for sev in SEVERITY_ORDER:
        grouped[sev] = []
    for finding in findings:
        sev = finding.get("severity", "MEDIUM").upper()
        if sev in grouped:
            grouped[sev].append(finding)
        else:
            grouped["MEDIUM"].append(finding)
    return grouped


def severity_counts(grouped: OrderedDict[str, list[dict]]) -> str:
    """Format severity counts as a summary string."""
    parts = []
    for sev in SEVERITY_ORDER:
        count = len(grouped[sev])
        if count > 0:
            parts.append(f"{count} {sev.capitalize()}")
    return ", ".join(parts) if parts else "No findings"


# ─── Markdown Report ───────────────────────────────────────────────────────

def generate_markdown(findings: list[dict]) -> str:
    """Generate a Markdown security audit report."""
    grouped = group_by_severity(findings)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    total = len(findings)

    lines = [
        "# Security Audit Report",
        "",
        f"**Scan date:** {now}",
        f"**Total findings:** {total}",
        f"**Summary:** {severity_counts(grouped)}",
        "",
        "---",
        "",
    ]

    if total == 0:
        lines.append("No security findings detected. The scanned files appear clean.")
        return "\n".join(lines)

    for sev in SEVERITY_ORDER:
        sev_findings = grouped[sev]
        if not sev_findings:
            continue

        prefix = SEVERITY_PREFIX[sev]
        lines.append(f"## {sev.capitalize()} ({len(sev_findings)})")
        lines.append("")

        for idx, finding in enumerate(sev_findings, start=1):
            finding_id = f"{prefix}-{idx:03d}"
            pattern_name = finding.get("pattern_name", "Unknown Pattern")
            filepath = finding.get("file", "unknown")
            line_num = finding.get("line", 0)
            match = finding.get("match", "****")
            pattern_id = finding.get("pattern_id", "unknown")

            # Optional fields added by the LLM during Phase 3 analysis
            confidence = finding.get("confidence")
            context = finding.get("context")
            commit = finding.get("commit")

            lines.append(f"### [{finding_id}] {pattern_name}")
            lines.append("")
            lines.append(f"- **File:** `{filepath}:{line_num}`")
            if commit:
                lines.append(f"- **Commit:** {commit}")
            lines.append(f"- **Pattern:** {pattern_id}")
            lines.append(f"- **Match:** `{match}`")
            if confidence:
                lines.append(f"- **Confidence:** {confidence}")
            if context:
                lines.append(f"- **Context:** {context}")

            # Remediation: prefer LLM-generated (via context field) then fall back to built-in
            remediation = get_remediation(pattern_id, sev)
            if remediation:
                lines.append(f"- **Remediation:** {remediation}")

            lines.append("")

    # Scan metadata
    lines.extend([
        "---",
        "",
        "## Scan Metadata",
        "",
        f"- **Generated by:** {TOOL_NAME} v{TOOL_VERSION}",
        f"- **Timestamp:** {now}",
        f"- **Total findings:** {total}",
    ])

    # Unique pattern counts
    unique_patterns = set()
    for f in findings:
        unique_patterns.add(f.get("pattern_id", ""))
    lines.append(f"- **Unique patterns matched:** {len(unique_patterns)}")

    return "\n".join(lines)


# ─── SARIF Report ──────────────────────────────────────────────────────────

def generate_sarif(findings: list[dict]) -> dict:
    """Generate a SARIF 2.1.0 report compatible with GitHub Code Scanning."""

    # Build unique rules from findings
    rules_map: dict[str, dict] = {}
    for finding in findings:
        pid = finding.get("pattern_id", "unknown")
        if pid not in rules_map:
            sev = finding.get("severity", "MEDIUM").upper()
            pname = finding.get("pattern_name", pid)
            remediation = get_remediation(pid, sev)

            help_text = f"Pattern: {pid}. {remediation}" if remediation else f"Pattern: {pid}"

            rules_map[pid] = {
                "id": pid,
                "shortDescription": {"text": pname},
                "fullDescription": {"text": f"{pname} ({sev.lower()} severity)"},
                "help": {
                    "text": help_text,
                    "markdown": f"**{pname}**\n\n{help_text}",
                },
                "defaultConfiguration": {
                    "level": SARIF_LEVEL.get(sev, "warning"),
                },
                "properties": {
                    "security-severity": SARIF_SECURITY_SEVERITY.get(sev, "5.0"),
                    "precision": "high" if pid not in ("high-entropy", "generic-secret", "generic-api-key") else "medium",
                    "tags": ["security"],
                },
            }

    rules = list(rules_map.values())
    rule_index = {r["id"]: i for i, r in enumerate(rules)}

    # Build results
    results = []
    for finding in findings:
        pid = finding.get("pattern_id", "unknown")
        filepath = finding.get("file", "unknown")
        line_num = finding.get("line", 1)
        match = finding.get("match", "****")
        pname = finding.get("pattern_name", pid)
        sev = finding.get("severity", "MEDIUM").upper()

        # Optional LLM-augmented fields
        confidence = finding.get("confidence")
        context = finding.get("context")

        # Generate a stable partial fingerprint for deduplication
        fingerprint_source = f"{filepath}:{line_num}:{pid}"
        fingerprint = hashlib.sha256(fingerprint_source.encode()).hexdigest()[:16]

        # Build message text: include LLM context if available
        base_msg = f"{pname}: {match} in {filepath}:{line_num}"
        message_text = f"{base_msg} — {context}" if context else base_msg

        # Map confidence to SARIF precision (overrides rule-level default when present)
        confidence_to_precision = {"High": "high", "Medium": "medium", "Low": "low"}

        result = {
            "ruleId": pid,
            "ruleIndex": rule_index.get(pid, 0),
            "level": SARIF_LEVEL.get(sev, "warning"),
            "message": {
                "text": message_text,
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": filepath.replace("\\", "/"),
                        },
                        "region": {
                            "startLine": line_num,
                            "startColumn": 1,
                        },
                    },
                },
            ],
            "partialFingerprints": {
                "primaryLocationLineHash": fingerprint,
            },
        }

        # Add per-result precision override when LLM has assessed confidence
        if confidence and confidence in confidence_to_precision:
            result["properties"] = {"precision": confidence_to_precision[confidence]}

        results.append(result)

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": TOOL_VERSION,
                        "semanticVersion": TOOL_VERSION,
                        "rules": rules,
                    },
                },
                "results": results,
            },
        ],
    }

    return sarif


# ─── JSON Report ───────────────────────────────────────────────────────────

def generate_json(findings: list[dict]) -> dict:
    """Generate a JSON report with metadata wrapper."""
    grouped = group_by_severity(findings)
    now = datetime.now(timezone.utc).isoformat()

    # findings already contain any LLM-augmented fields (confidence, context, commit)
    return {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "timestamp": now,
        "summary": {
            "total": len(findings),
            "critical": len(grouped["CRITICAL"]),
            "high": len(grouped["HIGH"]),
            "medium": len(grouped["MEDIUM"]),
            "low": len(grouped["LOW"]),
        },
        "findings": findings,
    }


# ─── Remediation ───────────────────────────────────────────────────────────

def get_remediation(pattern_id: str, severity: str) -> str:
    """Return remediation guidance based on pattern type."""
    remediations = {
        # Critical
        "aws-access-key": "Remove the key from source code. Use environment variables or AWS Secrets Manager. Rotate the key immediately via the AWS IAM console.",
        "private-key-block": "Remove the private key from the repository. Add the file to .gitignore. Rotate the key pair. Use a secrets vault for key storage. Note: the key remains in git history — use git filter-repo or BFG Repo-Cleaner to purge it.",
        "gcp-service-account": "Remove the service account JSON from source code. Use workload identity federation or store in a secrets manager. Rotate the key in the GCP console.",
        "gcp-api-key": "Review the API key restrictions in the Google Cloud console. If unrestricted, add application and API restrictions immediately. Move to environment variables.",
        "stripe-secret-key": "Remove the key from source code. Use environment variables. Rotate the key in the Stripe dashboard. If this is a live key, check for unauthorized transactions.",
        "azure-storage-key": "Remove the connection string from source code. Use Azure Key Vault or managed identity. Rotate the storage account key.",
        "azure-ad-secret": "Remove the client secret from source code. Rotate it in Azure AD. Use managed identity or certificate-based authentication instead.",
        "db-root-password": "Remove hardcoded password. Use environment variables or a secrets manager. Rotate the password. Consider using IAM-based database authentication.",

        # High
        "github-pat-classic": "Remove the token from source code. Rotate it at github.com/settings/tokens. Use GitHub Actions secrets or environment variables.",
        "github-pat-fine": "Remove the token from source code. Rotate it at github.com/settings/tokens. Use GitHub Actions secrets or environment variables.",
        "github-oauth": "Remove the token from source code. Revoke and regenerate the OAuth token.",
        "gitlab-pat": "Remove the token from source code. Rotate it in GitLab user settings. Use CI/CD variables for automation.",
        "gitlab-runner": "Remove the runner token from source code. Re-register the runner with a new token.",
        "slack-bot-token": "Remove the token from source code. Rotate it in the Slack app settings. Use environment variables.",
        "slack-webhook": "Remove the webhook URL from source code. Regenerate it in Slack app settings if exposed.",
        "sendgrid-key": "Remove the API key from source code. Rotate it in the SendGrid dashboard. Use environment variables.",
        "twilio-key": "Remove the API key from source code. Rotate it in the Twilio console.",
        "db-connection-string": "Remove credentials from the connection string. Use environment variables or a secrets manager for database credentials.",
        "password-assignment": "Remove hardcoded password. Use environment variables or a secrets manager.",
        "heroku-key": "Remove the API key from source code. Regenerate it via the Heroku CLI or dashboard.",
        "mailgun-key": "Remove the API key from source code. Rotate it in the Mailgun dashboard.",
        "npm-token": "Remove the token from source code. Rotate it via npm token revoke and npm token create.",
        "rubygems-token": "Remove the token from source code. Rotate it at rubygems.org/profile/api_keys.",
        "openai-key": "Remove the API key from source code. Rotate it at platform.openai.com/api-keys. Use environment variables.",

        # Medium — secrets
        "jwt-signing-secret": "Verify this is a real signing secret (not a placeholder). If real, move to environment variables and rotate immediately.",
        "generic-api-key": "Verify this is a real API key. If confirmed, move to environment variables and rotate with the service provider.",
        "generic-secret": "Verify this is a real secret. If confirmed, move to environment variables or a secrets manager.",
        "base64-secret": "Verify the decoded value is sensitive. If confirmed, move to environment variables.",
        "private-key-var": "Verify this contains actual key material. If real, move to a secrets vault and rotate.",
        "encryption-key": "Move encryption keys to a secrets manager or key management service. Never hardcode cryptographic keys.",
        "high-entropy": "Verify whether this high-entropy string is a real secret. If confirmed, move to environment variables.",

        # Medium — vulnerabilities
        "sql-injection-concat": "Use parameterized queries or prepared statements instead of string concatenation in SQL. Example: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
        "sql-injection-build": "Use parameterized queries instead of building SQL strings with concatenation.",
        "xss-innerhtml": "Use textContent instead of innerHTML for untrusted data. If HTML is required, sanitize with a library like DOMPurify.",
        "xss-react-dangerous": "Sanitize HTML content before passing to dangerouslySetInnerHTML. Use DOMPurify or a similar sanitization library.",
        "insecure-deserialize": "Avoid deserializing untrusted data. For Python YAML, use yaml.safe_load(). For pickle, consider using JSON instead. Validate and sanitize input before deserialization.",
        "weak-crypto": "Replace MD5/SHA1 with SHA-256 or SHA-3 for integrity checks. For password hashing, use bcrypt, scrypt, or Argon2.",
        "hardcoded-ip": "Move IP addresses to configuration files or environment variables. Use DNS names where possible.",
        "insecure-http": "Use HTTPS instead of HTTP for all non-local endpoints.",
        "command-injection": "Avoid passing user input to shell commands. Use subprocess with a list argument (not shell=True). Validate and sanitize all inputs.",
        "ssrf-dynamic-url": "Validate and allowlist URLs before making HTTP requests. Block requests to internal/private IP ranges.",

        # Dangerous file types
        "dangerous-file-tfstate": "Add *.tfstate to .gitignore. Remove from git history with git filter-repo. Configure a remote state backend (S3, GCS, Terraform Cloud).",
        "dangerous-file-tfstate-backup": "Add *.tfstate.backup to .gitignore. Remove from git history. Configure a remote state backend.",
        "dangerous-file-tf-apply-output": "Add terraform apply output files to .gitignore. Remove from git history. Share infrastructure details via secure channels only.",
        "dangerous-file-tf-plan-output": "Add terraform plan output files to .gitignore. Remove from git history.",
        "dangerous-file-pem": "Add *.pem to .gitignore. Remove from git history with git filter-repo. Rotate any exposed key material immediately.",
        "dangerous-file-key": "Add *.key to .gitignore. Remove from git history. Rotate any exposed key material immediately.",
        "dangerous-file-p12": "Add *.p12 to .gitignore. Remove from git history. Rotate certificates and keys. Consider using a certificate authority for short-lived certs.",
        "dangerous-file-pfx": "Add *.pfx to .gitignore. Remove from git history. Rotate certificates and keys.",
        "dangerous-file-jks": "Add *.jks to .gitignore. Remove from git history. Rotate keystores and re-issue certificates.",
        "dangerous-file-credentials-json": "Add credentials.json to .gitignore. Remove from git history. Use workload identity federation or IAM roles instead of exported key files.",
        "dangerous-file-service-account": "Add service-account*.json to .gitignore. Remove from git history. Rotate the service account key in GCP console. Use workload identity federation.",
        "dangerous-file-terraform-cache": "Add .terraform/ to .gitignore. Remove from git history. This directory is generated by terraform init.",
        "dangerous-file-sqlite": "Add *.sqlite to .gitignore. Remove from git history. Use migration scripts or fixtures instead of database files.",
        "dangerous-file-db": "Add *.db to .gitignore. Remove from git history. Use migration scripts or fixtures instead of database files.",
        "dangerous-file-secret-name": "Verify file contents. If it contains real secrets, add to .gitignore and remove from git history. If it's a template, rename with .example or .template extension.",

        # Additional SaaS & Cloud tokens
        "digitalocean-pat": "Revoke the token in the DigitalOcean API settings. Use environment variables or a secrets manager.",
        "hashicorp-vault-token": "Revoke the token via 'vault token revoke'. Use short-lived tokens with appropriate policies.",
        "terraform-cloud-token": "Revoke the token in Terraform Cloud user settings. Use team or organization tokens with scoped permissions.",
        "docker-hub-pat": "Revoke the token in Docker Hub security settings. Use environment variables for CI/CD authentication.",
        "grafana-cloud-token": "Revoke the token in Grafana Cloud API keys settings. Use service accounts with minimal permissions.",
        "grafana-service-account": "Revoke the service account token in Grafana admin settings. Create a new token with appropriate scope.",
        "shopify-private-app": "Rotate the token in Shopify admin. Use Shopify CLI authentication or environment variables.",
        "shopify-access-token": "Rotate the token in Shopify partner dashboard. Store in environment variables.",
        "shopify-shared-secret": "Rotate the shared secret in Shopify admin. Store in environment variables.",
        "anthropic-api-key": "Revoke the key at console.anthropic.com. Use environment variables (ANTHROPIC_API_KEY).",
        "linear-api-key": "Revoke the key in Linear API settings. Use environment variables.",
        "planetscale-token": "Revoke the token in PlanetScale dashboard. Use environment variables for database connections.",
        "figma-pat": "Revoke the token in Figma account settings. Use environment variables.",
        "digitalocean-oauth": "Revoke the OAuth token in DigitalOcean API settings. Use environment variables.",
        "datadog-api-key": "Revoke the key in Datadog organization settings. Use environment variables (DD_API_KEY).",
        "discord-bot-token": "Reset the bot token in Discord Developer Portal. Use environment variables.",

        # Low
        "debug-enabled": "Ensure debug mode is disabled in production configurations.",
        "cors-wildcard": "Replace wildcard CORS origin (*) with specific allowed origins in production.",
        "ssl-verify-disabled": "Enable SSL/TLS verification in production. Only disable for local development with self-signed certificates.",
        "security-todo": "Address the security concern described in this TODO comment.",
    }

    return remediations.get(pattern_id, "")


# ─── Main ──────────────────────────────────────────────────────────────────

def main() -> None:
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <findings_file> <format> <output_file>", file=sys.stderr)
        print("  format: markdown, sarif, or json", file=sys.stderr)
        sys.exit(1)

    findings_file = sys.argv[1]
    output_format = sys.argv[2].lower()
    output_file = sys.argv[3]

    if output_format not in ("markdown", "sarif", "json"):
        print(f"ERROR: Unknown format '{output_format}'. Use markdown, sarif, or json.", file=sys.stderr)
        sys.exit(1)

    if not Path(findings_file).is_file():
        print(f"ERROR: Findings file not found: {findings_file}", file=sys.stderr)
        sys.exit(1)

    findings = load_findings(findings_file)
    print(f"Loaded {len(findings)} findings", file=sys.stderr)

    if output_format == "markdown":
        content = generate_markdown(findings)
    elif output_format == "sarif":
        sarif = generate_sarif(findings)
        content = json.dumps(sarif, indent=2, ensure_ascii=False)
    elif output_format == "json":
        report = generate_json(findings)
        content = json.dumps(report, indent=2, ensure_ascii=False)

    if output_file in ("-", "/dev/stdout"):
        sys.stdout.write(content + "\n")
    else:
        Path(output_file).write_text(content + "\n", encoding="utf-8")
        print(f"Report written to {output_file}", file=sys.stderr)


if __name__ == "__main__":
    main()
