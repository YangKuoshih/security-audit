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


if __name__ == "__main__":
    unittest.main(verbosity=2)
