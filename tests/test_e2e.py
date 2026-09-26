#!/usr/bin/env python3
"""End-to-end regression tests for the bundled scanners and report generator."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills" / "security-audit"
PY_SCANNER = SKILL / "scripts" / "scan-secrets.py"
BASH_SCANNER = SKILL / "scripts" / "scan-secrets.sh"
PATTERNS = SKILL / "scripts" / "patterns.dat"
REPORTER = SKILL / "scripts" / "generate-report.py"


def run(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(args), cwd=cwd, text=True, capture_output=True, check=False,
    )


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


class ScannerTests(unittest.TestCase):
    def scan_directory(self, target: Path, *, entropy: bool = False) -> tuple[subprocess.CompletedProcess[str], list[dict]]:
        output = target / "findings.jsonl"
        args = [
            sys.executable, str(PY_SCANNER),
            "--target", str(target),
            "--patterns", str(PATTERNS),
            "--output", str(output),
            "--no-dangerous-files",
        ]
        if not entropy:
            args.append("--no-entropy")
        result = run(*args)
        findings = read_jsonl(output) if output.exists() else []
        return result, findings

    def test_python_scan_redacts_filters_and_applies_threshold(self) -> None:
        aws_key = "AKIA" + "ABCDEFGHIJKLMNOP"
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / "app.js").write_text(f'const accessKey = "{aws_key}";\n')
            (target / "ignored.js").write_text('DEBUG = true\n')
            output = target / "findings.jsonl"

            result = run(
                sys.executable, str(PY_SCANNER),
                "--target", str(target),
                "--patterns", str(PATTERNS),
                "--output", str(output),
                "--exclude-files", "ignored.js",
                "--severity-min", "critical",
                "--no-entropy",
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            findings = read_jsonl(output)
            self.assertEqual([item["pattern_id"] for item in findings], ["aws-access-key"])
            self.assertNotIn(aws_key, output.read_text())
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)

    def test_bash_fallback_redacts_vendor_secret(self) -> None:
        github_token = "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234"
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / "app.js").write_text(f'const token = "{github_token}";\n')
            output = target / "findings.jsonl"

            result = run(
                "bash", str(BASH_SCANNER), str(target), str(PATTERNS), str(output),
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("github-pat-classic", output.read_text())
            self.assertNotIn(github_token, output.read_text())

    def test_incremental_scan_rejects_unknown_base(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            run("git", "init", "-q", cwd=target)
            run("git", "config", "user.email", "test@example.invalid", cwd=target)
            run("git", "config", "user.name", "Security Audit Tests", cwd=target)
            (target / "safe.py").write_text("answer = 42\n")
            run("git", "add", "safe.py", cwd=target)
            run("git", "commit", "-qm", "base", cwd=target)

            result = run(
                sys.executable, str(PY_SCANNER),
                "--target", str(target),
                "--patterns", str(PATTERNS),
                "--output", str(target / "findings.jsonl"),
                "--base-branch", "does-not-exist",
            )

            self.assertEqual(result.returncode, 2)
            self.assertIn("cannot compare against base branch", result.stderr)
            self.assertNotIn("falling back to full scan", result.stderr.lower())

    def test_fail_on_threshold_writes_findings_then_exits_three(self) -> None:
        aws_key = "AKIA" + "ABCDEFGHIJKLMNOP"
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / "app.js").write_text(f'const accessKey = "{aws_key}";\n')
            output = target / "findings.jsonl"

            result = run(
                sys.executable, str(PY_SCANNER),
                "--target", str(target),
                "--patterns", str(PATTERNS),
                "--output", str(output),
                "--fail-on", "high",
                "--no-entropy",
            )

            self.assertEqual(result.returncode, 3)
            self.assertTrue(output.is_file())
            self.assertIn("aws-access-key", output.read_text())
            self.assertIn("CI severity gate failed", result.stderr)

    def test_incremental_scan_includes_uncommitted_and_untracked_files(self) -> None:
        aws_key = "AKIA" + "ABCDEFGHIJKLMNOP"
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            run("git", "init", "-q", cwd=target)
            run("git", "config", "user.email", "test@example.invalid", cwd=target)
            run("git", "config", "user.name", "Security Audit Tests", cwd=target)
            (target / "safe.py").write_text("answer = 42\n")
            run("git", "add", "safe.py", cwd=target)
            run("git", "commit", "-qm", "base", cwd=target)
            run("git", "branch", "audit-base", cwd=target)
            (target / "safe.py").write_text("answer = 43\n")
            (target / "untracked.js").write_text(f'const accessKey = "{aws_key}";\n')
            output = target / "findings.jsonl"

            result = run(
                sys.executable, str(PY_SCANNER),
                "--target", str(target),
                "--patterns", str(PATTERNS),
                "--output", str(output),
                "--base-branch", "audit-base",
                "--no-entropy",
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            findings = read_jsonl(output)
            self.assertIn("aws-access-key", [item["pattern_id"] for item in findings])
            self.assertNotIn(aws_key, output.read_text())

    def test_incremental_dangerous_files_are_limited_to_changed_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            run("git", "init", "-q", cwd=target)
            run("git", "config", "user.email", "test@example.invalid", cwd=target)
            run("git", "config", "user.name", "Security Audit Tests", cwd=target)
            (target / "old.pem").write_text("placeholder certificate\n")
            run("git", "add", "old.pem", cwd=target)
            run("git", "commit", "-qm", "base", cwd=target)
            run("git", "branch", "audit-base", cwd=target)
            (target / "new.key").write_text("placeholder key\n")
            run("git", "add", "new.key", cwd=target)
            run("git", "commit", "-qm", "add changed key", cwd=target)
            output = target / "findings.jsonl"

            result = run(
                sys.executable, str(PY_SCANNER),
                "--target", str(target),
                "--patterns", str(PATTERNS),
                "--output", str(output),
                "--base-branch", "audit-base",
                "--no-entropy",
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            dangerous = [item for item in read_jsonl(output) if item["line"] == 0]
            self.assertEqual([item["file"] for item in dangerous], ["new.key"])

    def test_source_filename_containing_secret_is_not_a_dangerous_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            run("git", "init", "-q", cwd=target)
            run("git", "config", "user.email", "test@example.invalid", cwd=target)
            run("git", "config", "user.name", "Security Audit Tests", cwd=target)
            (target / "scan-secrets.py").write_text("def scan():\n    return []\n")
            (target / "secret_scanning.yml").write_text("paths-ignore: []\n")
            run("git", "add", "scan-secrets.py", "secret_scanning.yml", cwd=target)
            run("git", "commit", "-qm", "add scanner", cwd=target)
            output = target / "findings.jsonl"

            result = run(
                sys.executable, str(PY_SCANNER),
                "--target", str(target),
                "--patterns", str(PATTERNS),
                "--output", str(output),
                "--no-entropy",
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            dangerous = [item for item in read_jsonl(output) if item["line"] == 0]
            self.assertEqual(dangerous, [])

    def test_scan_does_not_follow_symlinks_outside_target(self) -> None:
        aws_key = "AKIA" + "ABCDEFGHIJKLMNOP"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "repo"
            target.mkdir()
            outside = root / "outside.js"
            outside.write_text(f'const accessKey = "{aws_key}";\n')
            (target / "linked.js").symlink_to(outside)
            output = target / "findings.jsonl"

            result = run(
                sys.executable, str(PY_SCANNER),
                "--target", str(target),
                "--patterns", str(PATTERNS),
                "--output", str(output),
                "--no-entropy",
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(read_jsonl(output), [])
            self.assertNotIn(aws_key, output.read_text())

    def test_firebase_client_key_is_low_severity_not_critical(self) -> None:
        firebase_key = "AIza" + "A" * 35
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / "google-services.json").write_text(
                json.dumps({"client": [{"api_key": [{"current_key": firebase_key}]}]})
            )

            result, findings = self.scan_directory(target, entropy=True)

            self.assertEqual(result.returncode, 0, result.stderr)
            gcp = [item for item in findings if item["pattern_id"] == "gcp-api-key"]
            self.assertEqual(len(gcp), 1)
            self.assertEqual(gcp[0]["severity"], "LOW")
            self.assertEqual(gcp[0]["confidence"], "High")
            self.assertIn("Firebase client configuration", gcp[0]["context"])

    def test_non_firebase_gcp_key_remains_critical(self) -> None:
        gcp_key = "AIza" + "B" * 35
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / "backend.py").write_text(f'credential = "{gcp_key}"\n')

            result, findings = self.scan_directory(target)

            self.assertEqual(result.returncode, 0, result.stderr)
            gcp = [item for item in findings if item["pattern_id"] == "gcp-api-key"]
            self.assertEqual(len(gcp), 1)
            self.assertEqual(gcp[0]["severity"], "CRITICAL")

    def test_firebase_context_in_file_content_downgrades_client_key(self) -> None:
        firebase_key = "AIza" + "C" * 35
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / "seed.mjs").write_text(
                f'const firebaseApiKey = "{firebase_key}";\n'
                "await fetch('https://firestore.googleapis.com/v1/projects/demo/databases');\n"
            )

            result, findings = self.scan_directory(target)

            self.assertEqual(result.returncode, 0, result.stderr)
            gcp = [item for item in findings if item["pattern_id"] == "gcp-api-key"]
            self.assertEqual(len(gcp), 1)
            self.assertEqual(gcp[0]["severity"], "LOW")

    def test_unrelated_firebase_mention_does_not_downgrade_gcp_key(self) -> None:
        gcp_key = "AIza" + "D" * 35
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / "backend.py").write_text(
                "# This service also sends Firebase notifications.\n"
                f'google_maps_api_key = "{gcp_key}"\n'
            )

            result, findings = self.scan_directory(target)

            self.assertEqual(result.returncode, 0, result.stderr)
            gcp = [item for item in findings if item["pattern_id"] == "gcp-api-key"]
            self.assertEqual(len(gcp), 1)
            self.assertEqual(gcp[0]["severity"], "CRITICAL")

    def test_firebase_key_utility_filename_is_client_context(self) -> None:
        firebase_key = "AIza" + "E" * 35
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / "firebase-key-posture.mjs").write_text(
                f'const configuredKey = "{firebase_key}";\n'
            )

            result, findings = self.scan_directory(target)

            self.assertEqual(result.returncode, 0, result.stderr)
            gcp = [item for item in findings if item["pattern_id"] == "gcp-api-key"]
            self.assertEqual(len(gcp), 1)
            self.assertEqual(gcp[0]["severity"], "LOW")

    def test_second_google_key_in_firebase_file_is_not_automatically_downgraded(self) -> None:
        firebase_key = "AIza" + "F" * 35
        maps_key = "AIza" + "G" * 35
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / "client.js").write_text(
                "const firebaseConfig = {\n"
                f'  apiKey: "{firebase_key}"\n'
                "};\n"
                f'const mapsCredential = "{maps_key}";\n'
                "initializeApp(firebaseConfig);\n"
            )

            result, findings = self.scan_directory(target)

            self.assertEqual(result.returncode, 0, result.stderr)
            gcp = [item for item in findings if item["pattern_id"] == "gcp-api-key"]
            self.assertEqual([item["severity"] for item in gcp], ["LOW", "CRITICAL"])

    def test_private_key_requires_complete_pem_block(self) -> None:
        begin = "-----BEGIN " + "PRIVATE KEY-----"
        end = "-----END " + "PRIVATE KEY-----"
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / "parser.js").write_text(f'const marker = "{begin}";\n')
            (target / "actual.pem.txt").write_text(
                begin + "\n" + ("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=" * 3) + "\n" + end + "\n"
            )

            result, findings = self.scan_directory(target)

            self.assertEqual(result.returncode, 0, result.stderr)
            pem = [item for item in findings if item["pattern_id"] == "private-key-block"]
            self.assertEqual(len(pem), 1)
            self.assertTrue(pem[0]["file"].endswith("actual.pem.txt"))
            self.assertEqual(pem[0]["confidence"], "High")

    def test_ssrf_requires_direct_user_control_signal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / "safe.js").write_text(
                "const response = await fetch(`${API_BASE}/v1/users/${id}`);\n"
            )
            (target / "unsafe.js").write_text(
                "const response = await fetch(req.query.url);\n"
            )

            result, findings = self.scan_directory(target)

            self.assertEqual(result.returncode, 0, result.stderr)
            ssrf = [item for item in findings if item["pattern_id"] == "ssrf-dynamic-url"]
            self.assertEqual(len(ssrf), 1)
            self.assertTrue(ssrf[0]["file"].endswith("unsafe.js"))
            self.assertEqual(ssrf[0]["confidence"], "Medium")

    def test_weak_crypto_ignores_checksums_but_flags_security_use(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / "main.tf").write_text('name = "asset-${md5(file("bundle.js"))}"\n')
            (target / "auth.py").write_text("password_digest = hashlib.md5(password).hexdigest()\n")
            (target / "build.log").write_text("MD5(file) build cache hit\n")

            result, findings = self.scan_directory(target)

            self.assertEqual(result.returncode, 0, result.stderr)
            weak = [item for item in findings if item["pattern_id"] == "weak-crypto"]
            self.assertEqual(len(weak), 1)
            self.assertTrue(weak[0]["file"].endswith("auth.py"))

    def test_test_password_is_downgraded_and_documentation_vulns_are_suppressed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / "tests").mkdir()
            (target / "docs").mkdir()
            (target / "tests" / "auth.test.js").write_text('password = "CorrectHorse1!";\n')
            (target / "docs" / "example.md").write_text("fetch(`${USER_URL}/resource`)\n")

            result, findings = self.scan_directory(target)

            self.assertEqual(result.returncode, 0, result.stderr)
            passwords = [item for item in findings if item["pattern_id"] == "password-assignment"]
            self.assertEqual(len(passwords), 1)
            self.assertEqual(passwords[0]["severity"], "LOW")
            self.assertEqual(passwords[0]["confidence"], "Low")
            self.assertFalse(any(item["pattern_id"] == "ssrf-dynamic-url" for item in findings))

    def test_eval_pattern_does_not_match_retrieval_identifiers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / "graph.ts").write_text(
                "function routeAfterRetrieval(state) { return state; }\n"
                "const result = eval(userInput);\n"
            )

            result, findings = self.scan_directory(target)

            self.assertEqual(result.returncode, 0, result.stderr)
            unsafe = [item for item in findings if item["pattern_id"] == "insecure-deserialize"]
            self.assertEqual(len(unsafe), 1)
            self.assertEqual(unsafe[0]["line"], 2)

    def test_scan_fails_loudly_when_no_patterns_load(self) -> None:
        """A pattern file the loader cannot parse must abort, not report a clean scan.

        Passing a path that yields zero usable patterns (for example one of the
        Markdown files in references/, which are documentation rather than
        pattern data) previously scanned every file against nothing, printed
        "Findings: 0" and exited 0 - a silent false negative.
        """
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            (target / "leak.py").write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
            bad_patterns = target / "not-patterns.md"
            bad_patterns.write_text("# Heading\n\n- **Pattern**: `something`\n")
            output = target / "findings.jsonl"

            result = run(
                sys.executable, str(PY_SCANNER),
                "--target", str(target),
                "--patterns", str(bad_patterns),
                "--output", str(output),
            )

            self.assertNotEqual(result.returncode, 0, "expected a non-zero exit")
            self.assertIn("No usable patterns", result.stderr)
            # It must not have produced a findings file implying a clean result.
            if output.exists():
                self.assertEqual(read_jsonl(output), [])


class ReportTests(unittest.TestCase):
    def test_report_deduplicates_weaker_secret_heuristics(self) -> None:
        findings = [
            {
                "file": "app.js", "line": 3, "match": "AKIA...MNOP",
                "pattern_id": "aws-access-key", "pattern_name": "AWS Access Key ID",
                "severity": "CRITICAL",
            },
            {
                "file": "app.js", "line": 3, "match": "AKIA...MNOP",
                "pattern_id": "high-entropy", "pattern_name": "High-Entropy String",
                "severity": "MEDIUM",
            },
        ]
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            source = tmp / "findings.jsonl"
            source.write_text("\n".join(json.dumps(item) for item in findings) + "\n")
            report = tmp / "report.json"

            result = run(
                sys.executable, str(REPORTER), str(source), "json", str(report),
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(report.read_text())
            self.assertEqual(payload["summary"]["total"], 1)
            self.assertEqual(payload["findings"][0]["pattern_id"], "aws-access-key")

    def test_clean_markdown_keeps_metadata_and_caveat(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            source = tmp / "empty.jsonl"
            source.write_text("")
            report = tmp / "report.md"

            result = run(
                sys.executable, str(REPORTER), str(source), "markdown", str(report),
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            content = report.read_text()
            self.assertIn("No security findings detected by this lightweight pattern scan", content)
            self.assertIn("not proof", content)
            self.assertIn("## Scan Metadata", content)

    def test_sarif_is_valid_and_has_stable_fingerprint(self) -> None:
        finding = {
            "file": "src/app.py", "line": 7, "match": "ghp_...1234",
            "pattern_id": "github-pat-classic", "pattern_name": "GitHub PAT",
            "severity": "HIGH",
        }
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            source = tmp / "findings.jsonl"
            source.write_text(json.dumps(finding) + "\n")
            report = tmp / "report.sarif"
            result = run(
                sys.executable, str(REPORTER), str(source), "sarif", str(report),
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(report.read_text())
            self.assertEqual(payload["version"], "2.1.0")
            self.assertIn("partialFingerprints", payload["runs"][0]["results"][0])

    def test_firebase_low_severity_report_has_firebase_specific_remediation(self) -> None:
        finding = {
            "file": "google-services.json", "line": 4, "match": "AIza...AAAA",
            "pattern_id": "gcp-api-key", "pattern_name": "GCP API Key",
            "severity": "LOW", "confidence": "High",
            "context": "Firebase client configuration key; public by design.",
        }
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            source = tmp / "findings.jsonl"
            source.write_text(json.dumps(finding) + "\n")
            report = tmp / "report.md"

            result = run(
                sys.executable, str(REPORTER), str(source), "markdown", str(report),
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            content = report.read_text()
            self.assertIn("Firebase client API key", content)
            self.assertIn("Security Rules", content)
            self.assertNotIn("Move to environment variables", content)
            self.assertEqual(report.stat().st_mode & 0o777, 0o600)

    def test_sarif_separates_contextual_severity_and_fingerprints(self) -> None:
        findings = [
            {
                "file": "config.js", "line": 2, "match": "AIza...AAAA",
                "pattern_id": "gcp-api-key", "pattern_name": "GCP API Key",
                "severity": "CRITICAL",
            },
            {
                "file": "config.js", "line": 8, "match": "AIza...AAAA",
                "pattern_id": "gcp-api-key", "pattern_name": "GCP API Key",
                "severity": "LOW",
            },
        ]
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            source = tmp / "findings.jsonl"
            source.write_text("\n".join(json.dumps(item) for item in findings) + "\n")
            report = tmp / "report.sarif"

            result = run(
                sys.executable, str(REPORTER), str(source), "sarif", str(report),
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(report.read_text())
            rules = payload["runs"][0]["tool"]["driver"]["rules"]
            results = payload["runs"][0]["results"]
            self.assertEqual(len(rules), 2)
            self.assertEqual(
                {rule["properties"]["security-severity"] for rule in rules},
                {"9.5", "2.5"},
            )
            fingerprints = {
                result["partialFingerprints"]["primaryLocationLineHash"]
                for result in results
            }
            self.assertEqual(len(fingerprints), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
