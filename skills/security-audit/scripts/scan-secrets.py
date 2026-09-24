#!/usr/bin/env python3
"""
scan-secrets.py — Pattern-based secret and vulnerability scanner

Part of the security-audit skill. This is the preferred scanner; it includes
entropy detection and the full filtering option set.

Usage:
    python3 scan-secrets.py --target <dir> --patterns <file> --output <file> [options]

Options:
    --target <dir>         Directory or file to scan
    --patterns <file>      Tab-delimited patterns file (patterns.dat)
    --output <file>        Output file path (use - for stdout)
    --base-branch <branch> Incremental mode: only scan files changed vs branch
    --exclude-dirs <dirs>  Comma-separated extra directories to exclude
    --entropy              Enable high-entropy string detection (default: on)
    --no-entropy           Disable high-entropy string detection

Output: JSON Lines format, one finding per line.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import math
import os
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

TOOL_VERSION = "0.2.0"
SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
DEFAULT_MAX_FILE_BYTES = 5 * 1024 * 1024

# ─── Configuration ──────────────────────────────────────────────────────────

DEFAULT_EXCLUDE_DIRS = {
    "node_modules", ".git", "venv", ".venv", "dist", "build", "__pycache__",
    ".next", "vendor", "target", ".tox", ".eggs", ".mypy_cache", ".pytest_cache",
    ".gradle", ".idea", ".vscode", "coverage", ".nyc_output",
}

BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp3", ".mp4", ".avi", ".mov", ".wav", ".flac",
    ".pdf", ".zip", ".gz", ".tar", ".bz2", ".7z", ".rar",
    ".jar", ".war", ".ear", ".class", ".pyc", ".pyo",
    ".so", ".dylib", ".dll", ".exe", ".bin",
    ".dat", ".db", ".sqlite", ".sqlite3",
    ".lock", ".map",
}

# Generated files that are large and never contain real secrets (skip by basename)
SKIP_FILENAMES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "composer.lock", "Gemfile.lock", "Pipfile.lock", "poetry.lock",
    "Cargo.lock", "go.sum", "flake.lock",
    "npm-shrinkwrap.json",
}

# Entropy detection settings
ENTROPY_MIN_LENGTH = 20       # Minimum string length to evaluate
ENTROPY_VARIABLE_NAMES = re.compile(
    r"(?i)(key|secret|token|password|passwd|pwd|credential|auth|api[_-]?key|"
    r"private[_-]?key|access[_-]?key|signing[_-]?key|encryption[_-]?key)",
)

# Regex to extract quoted string values from assignments
STRING_VALUE_PATTERN = re.compile(
    r"""(?i)(?:key|secret|token|password|passwd|pwd|credential|auth|api[_-]?key)"""
    r"""\s*[:=]\s*['"]([^'"]{20,})['"]"""
)

# Charset-aware entropy thresholds
HEX_CHARS = set("0123456789abcdefABCDEF")
BASE64_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
ENTROPY_THRESHOLDS = {
    "hex": 3.5,      # max theoretical: 4.0 bits
    "base64": 4.2,   # max theoretical: ~6.0 bits
    "generic": 4.5,  # full character set
}

# False positive filters for entropy detection
UUID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I
)
URL_PATH_PATTERN = re.compile(r"^(https?://|/[a-z])", re.I)
SEMVER_PATTERN = re.compile(r"^\d+\.\d+\.\d+")


def detect_charset(value: str) -> str:
    """Detect the character set of a string value."""
    chars = set(value)
    if chars <= HEX_CHARS:
        return "hex"
    if chars <= BASE64_CHARS:
        return "base64"
    return "generic"


def is_false_positive_entropy(value: str) -> bool:
    """Filter out high-entropy strings that aren't secrets."""
    if UUID_PATTERN.match(value):
        return True
    if URL_PATH_PATTERN.match(value):
        return True
    if SEMVER_PATTERN.match(value):
        return True
    return False


# ─── Shannon Entropy ────────────────────────────────────────────────────────

def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string in bits per character."""
    if not data:
        return 0.0
    counter = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counter.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)
    return entropy


def is_placeholder(value: str) -> bool:
    """Check if a string value looks like a placeholder, not a real secret."""
    lower = value.lower()
    placeholders = [
        "example", "test", "dummy", "fake", "sample", "placeholder",
        "changeme", "your-key-here", "insert_key", "replace-me",
        "todo", "fixme", "xxx",
    ]
    for p in placeholders:
        if p in lower:
            return True

    # All same character
    if len(set(value.replace("-", "").replace("_", ""))) <= 2:
        return True

    # AWS documentation example keys (split to avoid self-detection by scanner)
    _AWS_EXAMPLE_PREFIX = "AKIAIOSFODNN7"
    _AWS_EXAMPLE_SECRET_PREFIX = "wJalrXUtnFEMI/K7MDENG"
    if value.startswith(_AWS_EXAMPLE_PREFIX) or value.startswith(_AWS_EXAMPLE_SECRET_PREFIX):
        return True

    return False


# ─── File Discovery ─────────────────────────────────────────────────────────

def is_binary_file(filepath: str) -> bool:
    """Check if a file is binary by extension, name, or by reading first bytes."""
    name = Path(filepath).name
    if name in SKIP_FILENAMES:
        return True

    ext = Path(filepath).suffix.lower()
    if ext in BINARY_EXTENSIONS:
        return True

    # Only probe file contents for unknown extensions — skip the I/O when
    # the extension is a known text type (covers the vast majority of files)
    if ext in _KNOWN_TEXT_EXTENSIONS:
        return False

    # Check for null bytes in first 512 bytes
    try:
        with open(filepath, "rb") as f:
            chunk = f.read(512)
            if b"\x00" in chunk:
                return True
    except (OSError, PermissionError):
        return True

    return False


_KNOWN_TEXT_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
    ".java", ".kt", ".kts", ".scala", ".groovy", ".gradle",
    ".go", ".rs", ".rb", ".php", ".c", ".h", ".cpp", ".hpp", ".cs",
    ".swift", ".m", ".mm", ".r", ".R", ".pl", ".pm", ".lua",
    ".sh", ".bash", ".zsh", ".fish", ".bat", ".cmd", ".ps1",
    ".html", ".htm", ".css", ".scss", ".sass", ".less",
    ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
    ".xml", ".xsl", ".xsd", ".plist", ".properties",
    ".md", ".rst", ".txt", ".csv", ".tsv", ".log",
    ".sql", ".graphql", ".gql", ".proto",
    ".tf", ".tfvars", ".hcl",
    ".dockerfile", ".env", ".env.example", ".gitignore",
    ".editorconfig", ".eslintrc", ".prettierrc",
    ".vue", ".svelte", ".astro",
}


def get_file_list(
    target: str,
    base_branch: str | None,
    exclude_dirs: set[str],
    exclude_files: list[str] | None = None,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
) -> list[str]:
    """Build list of files to scan."""

    requested_path = Path(target)
    if requested_path.is_symlink():
        raise RuntimeError("refusing to scan a symlink target")
    target_path = requested_path.resolve()

    # Single file mode
    if target_path.is_file():
        return [str(target_path)]

    files: list[str] = []

    # Check if git is available
    git_available = False
    try:
        result = subprocess.run(
            ["git", "-C", str(target_path), "rev-parse", "--is-inside-work-tree"],
            capture_output=True, text=True, timeout=10,
        )
        git_available = result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    if base_branch and not git_available:
        raise RuntimeError("incremental mode requires a git repository")

    if base_branch and git_available:
        # Incremental mode
        print(f"Mode: incremental (base: {base_branch})", file=sys.stderr)
        try:
            changed_paths: set[str] = set()
            commands = [
                ["diff", "--name-only", "--diff-filter=ACMR", f"{base_branch}...HEAD"],
                ["diff", "--name-only", "--diff-filter=ACMR", "HEAD"],
                ["ls-files", "--others", "--exclude-standard"],
            ]
            for command in commands:
                result = subprocess.run(
                    ["git", "-C", str(target_path), *command],
                    capture_output=True, text=True, timeout=30,
                )
                if result.returncode != 0:
                    detail = result.stderr.strip() or f"git {command[0]} failed"
                    raise RuntimeError(
                        f"cannot compare against base branch {base_branch!r}: {detail}"
                    )
                changed_paths.update(result.stdout.strip().splitlines())
            for line in sorted(changed_paths):
                fullpath = target_path / line
                if fullpath.is_file() and not fullpath.is_symlink():
                    files.append(str(fullpath))
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            raise RuntimeError(f"incremental git diff failed: {exc}") from exc

    if not files and git_available and not base_branch:
        # Full scan with git ls-files
        print("Mode: full scan (git)", file=sys.stderr)
        try:
            result = subprocess.run(
                ["git", "-C", str(target_path), "ls-files",
                 "--cached", "--others", "--exclude-standard"],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode != 0:
                detail = result.stderr.strip() or "git ls-files failed"
                raise RuntimeError(detail)
            for line in result.stdout.strip().splitlines():
                fullpath = target_path / line
                if fullpath.is_file() and not fullpath.is_symlink():
                    files.append(str(fullpath))
        except (FileNotFoundError, subprocess.TimeoutExpired):
            git_available = False

    if not files and not git_available:
        # Fallback: walk directory
        print("Mode: full scan (walk)", file=sys.stderr)
        for root, dirs, filenames in os.walk(str(target_path)):
            # Prune excluded directories in-place
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            for fname in filenames:
                files.append(os.path.join(root, fname))

    # Filter files
    filtered = []
    exclude_files = exclude_files or []
    for filepath in files:
        # Check excluded directories (for git-based lists that don't prune)
        parts = Path(filepath).parts
        if any(part in exclude_dirs for part in parts):
            continue
        path = Path(filepath)
        if path.is_symlink():
            continue
        try:
            if path.stat().st_size > max_file_bytes:
                continue
        except OSError:
            continue

        try:
            relative = Path(filepath).resolve().relative_to(target_path).as_posix()
        except ValueError:
            relative = Path(filepath).name
        if any(
            fnmatch.fnmatch(relative, pattern) or fnmatch.fnmatch(Path(relative).name, pattern)
            for pattern in exclude_files
        ):
            continue

        # Skip binary files
        if is_binary_file(filepath):
            continue

        filtered.append(filepath)

    return filtered


# ─── Pattern Loading ────────────────────────────────────────────────────────

class Pattern:
    __slots__ = ("severity", "pattern_id", "name", "regex", "compiled")

    def __init__(self, severity: str, pattern_id: str, name: str, regex: str, compiled: re.Pattern):
        self.severity = severity
        self.pattern_id = pattern_id
        self.name = name
        self.regex = regex
        self.compiled = compiled  # precompiled for performance across many files


def load_patterns(patterns_files: list[str]) -> list[Pattern]:
    """Load patterns, allowing later files to override an existing pattern ID."""
    patterns_by_id: dict[str, Pattern] = {}
    for patterns_file in patterns_files:
        with open(patterns_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.rstrip("\n\r")
                if not line or line.startswith("#"):
                    continue

                parts = line.split("\t", 3)
                if len(parts) != 4:
                    print(f"WARNING: Skipping malformed pattern line: {line!r}", file=sys.stderr)
                    continue

                severity, pattern_id, name, regex = parts
                try:
                    compiled = re.compile(regex)
                except re.error as e:
                    print(f"WARNING: Invalid regex for {pattern_id}: {e}", file=sys.stderr)
                    continue

                severity = severity.upper()
                if severity not in SEVERITY_RANK:
                    print(f"WARNING: Invalid severity for {pattern_id}: {severity}", file=sys.stderr)
                    continue
                patterns_by_id[pattern_id] = Pattern(severity, pattern_id, name, regex, compiled)

    return list(patterns_by_id.values())


# ─── Redaction ──────────────────────────────────────────────────────────────

def redact(match: str) -> str:
    """Redact a matched string, showing only first/last few characters."""
    length = len(match)
    if length <= 8:
        return "****"
    elif length <= 16:
        return f"{match[:2]}...{match[-2:]}"
    else:
        return f"{match[:4]}...{match[-4:]}"


# ─── Scanning ──────────────────────────────────────────────────────────────

def scan_file(
    filepath: str,
    patterns: list[Pattern],
    enable_entropy: bool,
) -> list[dict]:
    """Scan a single file against all patterns and optionally for high-entropy strings.

    Iterates lines once, testing all patterns per line (better cache locality
    than the inverse — each line is in CPU cache when tested against every pattern).
    Entropy detection runs in the same pass to avoid a second file read.
    """
    findings = []

    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except (OSError, PermissionError):
        return findings

    for line_num, line in enumerate(lines, start=1):
        # Skip blank / whitespace-only lines early
        if not line.strip():
            continue

        # Pattern-based scanning — all patterns tested on this line
        for pattern in patterns:
            match = pattern.compiled.search(line)
            if match:
                findings.append({
                    "file": filepath,
                    "line": line_num,
                    "match": redact(match.group(0)),
                    "pattern_id": pattern.pattern_id,
                    "pattern_name": pattern.name,
                    "severity": pattern.severity,
                })

        # Entropy-based detection (same pass, no second file read)
        if enable_entropy and ENTROPY_VARIABLE_NAMES.search(line):
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

    return findings


# ─── Output ─────────────────────────────────────────────────────────────────

def make_relative(filepath: str, target: str) -> str:
    """Make a filepath relative to the target directory."""
    try:
        return str(Path(filepath).relative_to(Path(target).resolve()))
    except ValueError:
        return filepath


# ─── Dangerous File Type Scanning ─────────────────────────────────────────


def scan_dangerous_files(target: str, allowed_files: set[str] | None = None) -> list[dict]:
    """Scan for dangerous file types tracked by git.

    Single-pass: iterates tracked files once, matching all patterns per file
    (mirrors the bash scanner's case-statement approach).
    """
    findings = []
    target_path = Path(target).resolve()

    # Only works in a git repo
    try:
        result = subprocess.run(
            ["git", "-C", str(target_path), "rev-parse", "--is-inside-work-tree"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            return findings
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return findings

    # Get tracked files only (--cached = staged/committed, no --others)
    try:
        result = subprocess.run(
            ["git", "-C", str(target_path), "ls-files", "--cached"],
            capture_output=True, text=True, timeout=30,
        )
        tracked_files = result.stdout.strip().splitlines()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return findings

    if not tracked_files:
        return findings

    # Extension → (pattern_id, pattern_name, severity)
    _EXT_MAP = {
        ".tfstate": ("dangerous-file-tfstate", "Terraform State Committed", "HIGH"),
        ".pem": ("dangerous-file-pem", "Private Key File Committed", "CRITICAL"),
        ".key": ("dangerous-file-key", "Private Key File Committed", "CRITICAL"),
        ".p12": ("dangerous-file-p12", "Certificate Bundle Committed", "CRITICAL"),
        ".pfx": ("dangerous-file-pfx", "Certificate Bundle Committed", "CRITICAL"),
        ".jks": ("dangerous-file-jks", "Java Keystore Committed", "HIGH"),
        ".sqlite": ("dangerous-file-sqlite", "Database File Committed", "MEDIUM"),
        ".db": ("dangerous-file-db", "Database File Committed", "MEDIUM"),
    }
    _SECRET_EXCLUDED_EXT = {".example", ".sample", ".template", ".md"}
    _SECRET_SAFE_NAMES = {
        "secret_scanning.yml", "secret_scanning.yaml", ".secrets.baseline",
        ".secretlintrc", ".secretlintrc.json",
    }
    _SECRET_LIKELY_EXT = {
        "", ".env", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg",
        ".conf", ".properties", ".txt", ".xml",
    }

    def _emit(filepath: str, pid: str, pname: str, sev: str) -> None:
        findings.append({
            "file": str(target_path / filepath),
            "line": 0,
            "match": "(entire file)",
            "pattern_id": pid,
            "pattern_name": pname,
            "severity": sev,
        })

    for filepath in tracked_files:
        if not filepath:
            continue
        if allowed_files is not None and filepath not in allowed_files:
            continue

        basename = Path(filepath).name
        lower_base = basename.lower()
        lower_path = filepath.lower()
        matched = False

        # .tfstate.backup must be checked before .tfstate (longer suffix wins)
        if lower_base.endswith(".tfstate.backup"):
            _emit(filepath, "dangerous-file-tfstate-backup", "Terraform State Backup Committed", "HIGH")
            continue

        # Extension-based patterns
        ext = Path(lower_base).suffix
        if ext in _EXT_MAP:
            pid, pname, sev = _EXT_MAP[ext]
            _emit(filepath, pid, pname, sev)
            matched = True

        # Name-based: credentials.json
        if not matched and lower_base == "credentials.json":
            _emit(filepath, "dangerous-file-credentials-json", "Credentials File Committed", "HIGH")
            matched = True

        # Name-based: service-account*.json
        if not matched and lower_base.startswith("service-account") and lower_base.endswith(".json"):
            _emit(filepath, "dangerous-file-service-account", "Service Account Key Committed", "HIGH")
            matched = True

        # Wildcard-name: terraform output files
        if not matched:
            if "terraform-apply-output" in lower_base:
                _emit(filepath, "dangerous-file-tf-apply-output", "Terraform Apply Output Committed", "MEDIUM")
                matched = True
            elif "terraform-plan-output" in lower_base:
                _emit(filepath, "dangerous-file-tf-plan-output", "Terraform Plan Output Committed", "MEDIUM")
                matched = True

        # .terraform/ directory
        if not matched and (".terraform/" in lower_path or lower_path.startswith(".terraform/")):
            _emit(filepath, "dangerous-file-terraform-cache", "Terraform Provider Cache Committed", "MEDIUM")
            matched = True

        # *secret* in filename (excluding safe extensions)
        if not matched and "secret" in lower_base and lower_base not in _SECRET_SAFE_NAMES:
            ext = Path(lower_base).suffix
            if ext not in _SECRET_EXCLUDED_EXT and ext in _SECRET_LIKELY_EXT:
                _emit(filepath, "dangerous-file-secret-name", "Possible Secrets File Committed", "MEDIUM")

    return findings


def write_findings(
    findings: list[dict],
    output_path: str,
    target: str,
) -> None:
    """Write findings as JSON Lines."""
    out = sys.stdout if output_path in ("-", "/dev/stdout") else open(output_path, "w", encoding="utf-8")
    if out is not sys.stdout:
        os.chmod(output_path, 0o600)

    try:
        for finding in findings:
            finding = finding.copy()
            finding["file"] = make_relative(finding["file"], target)
            out.write(json.dumps(finding, ensure_ascii=False) + "\n")
    finally:
        if out is not sys.stdout:
            out.close()


# ─── Main ───────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Pattern-based secret and vulnerability scanner",
    )
    parser.add_argument("--target", required=True, help="Directory or file to scan")
    parser.add_argument("--patterns", required=True, help="Tab-delimited patterns file")
    parser.add_argument("--extra-patterns", action="append", default=[],
                        help="Additional patterns file; repeatable, later IDs override earlier ones")
    parser.add_argument("--output", required=True, help="Output file (use - for stdout)")
    parser.add_argument("--base-branch", default=None, help="Base branch for incremental scan")
    parser.add_argument("--exclude-dirs", default="", help="Comma-separated extra exclude dirs")
    parser.add_argument("--exclude-files", default="",
                        help="Comma-separated glob patterns to exclude")
    parser.add_argument("--severity-min", default="low",
                        choices=("low", "medium", "high", "critical"),
                        help="Minimum severity to emit (default: low)")
    parser.add_argument("--no-dangerous-files", action="store_true",
                        help="Disable tracked dangerous-file detection")
    parser.add_argument("--max-file-bytes", type=int, default=DEFAULT_MAX_FILE_BYTES,
                        help="Skip files larger than this many bytes (default: 5242880)")
    parser.add_argument("--entropy", dest="entropy", action="store_true", default=True,
                        help="Enable entropy detection (default)")
    parser.add_argument("--no-entropy", dest="entropy", action="store_false",
                        help="Disable entropy detection")
    args = parser.parse_args()

    print(f"security-audit scanner v{TOOL_VERSION} (Python)", file=sys.stderr)
    print(f"Target: {args.target}", file=sys.stderr)
    print(f"Patterns: {args.patterns}", file=sys.stderr)
    print(f"Entropy detection: {'on' if args.entropy else 'off'}", file=sys.stderr)

    # Build exclude dirs set
    exclude_dirs = set(DEFAULT_EXCLUDE_DIRS)
    if args.exclude_dirs:
        for d in args.exclude_dirs.split(","):
            d = d.strip()
            if d:
                exclude_dirs.add(d)

    # Validate inputs
    if not os.path.exists(args.target):
        print(f"ERROR: Target not found: {args.target}", file=sys.stderr)
        sys.exit(1)
    if not os.path.isfile(args.patterns):
        print(f"ERROR: Patterns file not found: {args.patterns}", file=sys.stderr)
        sys.exit(1)
    for extra_patterns in args.extra_patterns:
        if not os.path.isfile(extra_patterns):
            print(f"ERROR: Extra patterns file not found: {extra_patterns}", file=sys.stderr)
            sys.exit(1)
    if args.max_file_bytes <= 0:
        print("ERROR: --max-file-bytes must be greater than zero", file=sys.stderr)
        sys.exit(1)

    # Load patterns
    patterns = load_patterns([args.patterns, *args.extra_patterns])
    print(f"Patterns loaded: {len(patterns)}", file=sys.stderr)

    # Build file list
    exclude_files = [item.strip() for item in args.exclude_files.split(",") if item.strip()]
    try:
        files = get_file_list(
            args.target, args.base_branch, exclude_dirs, exclude_files, args.max_file_bytes,
        )
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(2)
    print(f"Files to scan: {len(files)}", file=sys.stderr)

    # Scan all files
    all_findings: list[dict] = []
    for filepath in files:
        file_findings = scan_file(filepath, patterns, args.entropy)
        all_findings.extend(file_findings)

    # Scan for dangerous file types (between pattern scan and output)
    incremental_files = None
    if args.base_branch:
        target_path = Path(args.target).resolve()
        incremental_files = {
            Path(filepath).resolve().relative_to(target_path).as_posix()
            for filepath in files
        }
    dangerous_findings = (
        [] if args.no_dangerous_files
        else scan_dangerous_files(args.target, incremental_files)
    )
    print(f"Dangerous file types found: {len(dangerous_findings)}", file=sys.stderr)
    all_findings.extend(dangerous_findings)

    minimum_rank = SEVERITY_RANK[args.severity_min.upper()]
    all_findings = [
        finding for finding in all_findings
        if SEVERITY_RANK.get(finding.get("severity", "MEDIUM").upper(), 1) >= minimum_rank
    ]

    # Write output
    write_findings(all_findings, args.output, args.target)

    # Summary
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in all_findings:
        sev = f["severity"]
        if sev in severity_counts:
            severity_counts[sev] += 1

    print(
        f"Scan complete. Findings: {len(all_findings)} "
        f"({severity_counts['CRITICAL']} Critical, {severity_counts['HIGH']} High, "
        f"{severity_counts['MEDIUM']} Medium, {severity_counts['LOW']} Low)",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
