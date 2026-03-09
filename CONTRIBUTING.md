# Contributing to security-audit

Contributions are welcome, especially new detection patterns. Here's how to contribute effectively.

## Getting Started

```bash
git clone https://github.com/YangKuoshih/security-audit.git
cd security-audit

# Run the test suite to verify everything works
bash tests/test-e2e.sh
```

## Adding a New Secret Pattern

1. **Add the pattern documentation** to `skills/security-audit/references/secret-patterns.md`:
   - Pattern name, regex, severity, description
   - Source/validation (which tool or vendor doc confirms this format)
   - Example match (redacted)

2. **Add the compiled pattern** to `skills/security-audit/scripts/patterns.dat`:
   - Format: `SEVERITY<TAB>pattern-id<TAB>Pattern Name<TAB>regex`
   - Use actual tab characters, not spaces

3. **Add a test fixture** to `tests/fixtures/sample-repo/`:
   - Use clearly fake values that match the pattern format
   - Values must NOT trigger GitHub push protection
   - Include a warning comment in the fixture file

4. **Add remediation guidance** to `skills/security-audit/scripts/generate-report.py`:
   - Add an entry to the `remediations` dict in `get_remediation()`

5. **Run the test suite**:
   ```bash
   bash tests/test-e2e.sh
   ```

## Adding a New Vulnerability Pattern

Same process as secret patterns, but add to `vulnerability-patterns.md` instead. Include:
- OWASP Top 10 mapping
- Languages where the pattern is relevant
- False positive guidance for the LLM

## Pattern Quality Rules

- **Validate against real tools**: Check your regex against GitLeaks, detect-secrets, or the vendor's documentation
- **No ReDoS**: Avoid nested quantifiers (`(a+)+`, `(a*)*`). Use bounded repetition `{min,max}` where possible
- **Test on large files**: Patterns must not cause excessive scanning time
- **Minimize false positives**: Prefer specific vendor prefixes over generic catches

## Test Fixture Rules

- Use **obviously fake values** (zeroed out, sequential characters, "fake" in the value)
- Never use values that could be mistaken for real credentials
- Always include a warning comment at the top of fixture files
- Verify fixtures don't trigger GitHub push protection before submitting

## Code Changes

- Scripts use only bash built-ins + grep (bash scanner) and Python 3 standard library (Python scanner)
- Do not add external dependencies
- All file paths must be quoted to prevent injection
- Never use `eval`, `source`, or execute pattern content as code

## Pull Request Process

1. Fork the repo and create a branch
2. Make your changes
3. Run `bash tests/test-e2e.sh` — all 58 tests must pass
4. Submit a PR with a clear description of what you added and why

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
