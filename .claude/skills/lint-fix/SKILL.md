---
name: lint-fix
description: Run the project linter and formatter, fix all violations.
allowed-tools: Read, Edit, Bash, Glob
user-invocable: true
---

Run the linter and formatter for this project and fix all issues.

Steps:
1. Detect the linter from project config:
   - Python: ruff check . --fix && ruff format .
   - JavaScript/TypeScript: npx eslint --fix . && npx prettier --write .
   - Rust: cargo clippy --fix && cargo fmt
   - Go: golangci-lint run --fix && gofmt -w .
2. Run the appropriate commands.
3. If auto-fix doesn't resolve everything, read the remaining errors and fix
   them manually.
4. Re-run the linter to confirm zero violations.
5. Report: violations found, auto-fixed, manually fixed, remaining.
