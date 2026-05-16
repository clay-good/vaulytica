# tests/v4 — v4 test suite

This directory mirrors the v4 source layout. Each v4 sub-domain
(`src/engine/rules/v4/<sub-domain>/`) gets a corresponding test
subdirectory here once the implementation lands per spec-v4.md Part VI
(Steps 45–59).

```
tests/v4/
  extract/                        # Step 42 — document classifier tests
  engine/
    rules/
      governance/                 # Step 45
      equity/                     # Step 46
      m-and-a/                    # Step 47
      real-estate/                # Step 48
      employment/                 # Step 49
      settlement/                 # Step 50
      ip-licensing/               # Step 51
      privacy-extended/           # Step 52
      healthcare/                 # Step 53
      insurance/                  # Step 54
      banking/                    # Step 55
      construction/               # Step 56
      trust-estate/               # Step 57
      compliance-policy/          # Step 58
      regulatory-prose/           # Step 59
  bundle/                         # Steps 41 + 43 + 44 — multi-doc tests
```

Convention mirrors the v3 test suite at [`tests/v3/`](../v3/README.md):
each ruleset gets a registry test (id pattern + uniqueness +
`applies_to_playbooks` scope), one compliant fixture per playbook,
one or more failure-mode tests per critical rule, and a determinism
guard.

Golden-output fixtures for v4 land at `tests/golden/v4/`, following
the same harness pattern as [`tests/golden/v3/`](../golden/v3/README.md).
