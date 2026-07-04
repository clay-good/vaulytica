# Tasks

- [x] 1. Failing tests first: `--format json,md` without `--out` must exit
  non-zero (today: summary line + exit 0); empty `--format` must exit
  non-zero. *(Pinned in `tests/integration/cli-output-completeness.test.ts`
  and verified through the real CLI: exit 1 with "multiple formats/inputs
  require --out <dir>".)*
- [x] 2. Add upfront validation in `tools/cli/run.ts`: multi-format/multi-input
  without `--out` → usage error; empty/unknown/duplicate format values →
  usage error listing the valid set.
- [x] 3. Remove the render-and-drop branch; assert by construction that every
  render call has a delivery target. *(The render loop's else-branch is now
  unconditionally stdout — reachable only in the validated single-input ×
  single-format case.)*
- [x] 4. Add the delivery-completeness contract test (real CLI spawn, sweep of
  combinations). *(Sweep runs in-process through the exported `runAnalyze` —
  the exact dispatch target — matching the established stream-contract test
  pattern (a tsx spawn per combination would add ~2-4s each); the headline
  case was additionally exercised through a real CLI spawn. Covers: multi-
  format and multi-input without `--out` fail with nothing on stdout; the
  same combinations with `--out` write every artifact; single×single still
  streams; empty/unknown/duplicate `--format` values error listing the
  valid set.)*
- [x] 5. Update usage text and `docs/ci-integration.md`. *(USAGE gains the
  output-delivery contract; ci-integration.md's multi-format example already
  used `--out`.)*
- [x] 6. Full gate green. *(typecheck, lint, format:check, 3,707 tests / 263
  files, build.)*
