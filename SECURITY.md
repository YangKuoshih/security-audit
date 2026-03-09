# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability in this project, **do not** open a public issue.

Instead, please report it privately:
- Email: [Create a private security advisory](https://github.com/YangKuoshih/security-audit/security/advisories/new)
- Include: description, reproduction steps, and potential impact

We will acknowledge receipt within 48 hours and provide a timeline for a fix.

## Scope

This project is a security scanning tool. The following are in scope for security reports:

- **Pattern bypass** — a real secret format that evades all detection patterns
- **False negative** — a known vulnerability pattern that the scanner misses
- **Script injection** — a way to execute arbitrary code through crafted pattern files or input
- **ReDoS** — a regex pattern that causes catastrophic backtracking on crafted input
- **Information leakage** — the scanner or report generator exposing full secret values instead of redacting them

The following are **not** in scope:

- Findings in `tests/fixtures/` — these contain intentionally fake secrets for testing
- The scanner detecting its own pattern definitions — this is expected behavior

## Security Considerations for Contributors

### Pattern Contributions

When contributing new regex patterns to `patterns.dat` or `references/`:

- **No catastrophic backtracking**: Avoid nested quantifiers like `(a+)+`, `(a*)*`, or `(a|b)*a`. These cause exponential time complexity on crafted input (ReDoS).
- **Bounded repetition**: Use `{min,max}` instead of unbounded `*` or `+` where possible.
- **Test your patterns**: Run against large files (10,000+ lines) to verify performance.

### Script Contributions

- Pattern files (`patterns.dat`) are read as data only — patterns are passed to `grep` as regex arguments, never executed as shell commands.
- The scanner scripts never use `eval`, `source`, or any construct that executes pattern content as code.
- All file paths are quoted to prevent word splitting and glob expansion.

### Test Fixture Rules

- Test fixtures must use **clearly fake values** that cannot be mistaken for real credentials.
- Fixture values should be designed to avoid triggering GitHub push protection.
- Every fixture file must include a warning comment at the top stating it contains fake data.
- Never commit real credentials, even temporarily, even in test fixtures.

## Dependencies

This project has **zero runtime dependencies**. The scanners use only:
- Bash built-ins + `grep` (bash scanner)
- Python 3 standard library only (Python scanner)

This eliminates supply chain attack vectors through dependency compromise.
