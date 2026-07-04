# Tasks

- [ ] 1. Failing tests first: `--format json,md` without `--out` must exit
  non-zero (today: summary line + exit 0); empty `--format` must exit
  non-zero.
- [ ] 2. Add upfront validation in `tools/cli/run.ts`: multi-format/multi-input
  without `--out` → usage error; empty/unknown/duplicate format values →
  usage error listing the valid set.
- [ ] 3. Remove the render-and-drop branch; assert by construction that every
  render call has a delivery target.
- [ ] 4. Add the delivery-completeness contract test (real CLI spawn, sweep of
  combinations).
- [ ] 5. Update usage text and `docs/ci-integration.md`.
- [ ] 6. Full gate green.
