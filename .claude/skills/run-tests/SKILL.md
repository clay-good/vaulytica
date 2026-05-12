---
name: run-tests
description: Run the full test suite, diagnose any failures, fix them, and re-run until green.
allowed-tools: Read, Edit, Write, Bash, Glob, Grep
user-invocable: true
---

Run the full test suite for this project.

Steps:
1. Read .codelicious/STATE.md to find the test command.
2. Run the test command.
3. If all tests pass, report the count and exit.
4. If tests fail:
   - Read the failing test file and the source file it tests.
   - Determine root cause (code bug vs test bug).
   - Fix the issue.
   - Re-run the full test suite.
   - Repeat until all tests pass or you've attempted 5 fix cycles.
5. Report: total tests, passed, failed, fixes applied.
