---
name: update-state
description: Update .codelicious/STATE.md with accurate current status.
allowed-tools: Read, Write, Bash, Glob, Grep
user-invocable: true
---

Update .codelicious/STATE.md to accurately reflect the current state of
the project.

Steps:
1. Run the test suite and record the count.
2. Run the linter and check for violations.
3. Count source and test files.
4. Read the current STATE.md.
5. Update the test count, file counts, and task statuses to match reality.
6. Ensure all completed work is recorded.
7. Write the updated STATE.md.
