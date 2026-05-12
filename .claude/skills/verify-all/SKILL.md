---
name: verify-all
description: Run all quality checks — tests, lint, format, security scan.
allowed-tools: Read, Edit, Write, Bash, Glob, Grep
user-invocable: true
---

Run the complete verification pipeline for this project.

1. **Tests**: Run the full test suite. Fix any failures.
2. **Lint**: Run the linter. Fix all violations.
3. **Format**: Run the formatter. Fix any formatting issues.
4. **Security**: Grep for common security anti-patterns:
   - eval(), exec(), shell=True, os.system(), subprocess.call(..., shell=True)
   - Hardcoded secrets: password\s*=\s*["'], api_key\s*=\s*["']
   - SQL injection: f"SELECT, f"INSERT, f"UPDATE, f"DELETE
5. **State**: Update .codelicious/STATE.md with current test count and status.

Report a summary of each check: pass/fail, issues found, fixes applied.
