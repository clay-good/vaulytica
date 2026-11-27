# answer-undetectable-required-clauses

## Why

This change began as a different one. `pin-the-docx-report` and
`guard-harness-extraction-parity` both closed with the same note: *`tools/cli/artifacts.ts` calls
`extractAll` with no classifier where the accuracy pipeline passes one. Same shape, different
field, and `extracted.classified` feeds routing — it needs its own measurement first.*

**That defect does not exist, and the measurement is why I know.** The CLI's analysis and routing
go through `runIngested`, which passes the classifier. The thirteen bare `extractAll` calls in
`tools/` are post-analysis report re-extracts, each feeding a builder that provably never reads
`extracted.classified` (`critical-dates.ts`, `definitions.ts`, `v3/inputs.ts` — zero references),
and several already carry a comment saying so. The stated cost was a hypothesis and it was wrong:
the third time this lineage that a predicted blast radius did not survive a probe.

Simulating the divergence anyway — emptying the patterns at the `runIngested` level, a path no
shipped surface takes — moved 1 of 363 specimens and 5 findings. Reachable by nothing.

**What the probe did find is a confident wrong answer at the top severity.**
`required_clauses[].category` is a free string (`z.string().min(1)`). The DKB ships 103 TF-IDF
vocab categories; the product passes `vocab: { vocab: {} }`, so only the ~21 PATTERN categories can
ever appear in `extracted.classified`. A category outside those 21 is read as *absent*. An
executive agreement with a Change of Control section and a Base Salary section, reviewed against a
playbook requiring both, produced:

```
[critical] Required clause missing: change-of-control
[warning]  Required clause missing: base-salary
unevaluable: 0
```

Both false, about the user's own standard, on a document that complies — and with no doubt
recorded. The dead vocab itself is *deliberate*, documented in
`required-clauses-live.test.ts`, and wiring it was measured over the 363-specimen corpus: it
labels 6,258 paragraphs instead of 645 and moves **no route and no finding**. So the vocab is not
the bug. Reading "undetectable" as "absent" is.

The invariant already exists. `required-clauses-live.test.ts` enforces "a `required_clauses` entry
must name a category the classifier can emit" across the 286 shipped playbooks, where violating it
only costs match weight. It was never enforced on the user's own playbook, which is the one place
it manufactures an accusation.

## What changes

| | |
| --- | --- |
| `detectableCategories(data)` | one helper, derived from the same patterns + vocab `classifyClauses` reads, so the live set cannot drift from the artifact |
| `runCustomPlaybook` | takes `detectable` as a **required** argument; an undetectable category goes to `unevaluable`, not to a finding |
| `custom-run.ts` | supplies it from the DKB the run loaded |
| two integration harnesses | supply it the same way, rather than assuming a set |

`detectable` is required and not optional on purpose. An optional parameter lets every caller keep
the bug by saying nothing — which is exactly how `jurisdiction_id` stayed empty for the product's
whole history.

## Impact

- `unevaluable` is inside `result_hash`, so a custom-playbook run naming an undetectable category
  hashes differently than before. No catalog run moves: shipped playbooks use the other
  `required_clauses` field (`string[]`, consumed by the matcher), which this does not touch.
- The user loses nothing they had: they could not detect `change-of-control` before either. They
  gain an honest answer naming the categories they can require.
- Still open, deliberately: whether to wire the DKB vocab at all. Measured inert on this corpus
  (0 routes, 0 findings), but it would label half of every document, which changes
  `required_clauses` satisfaction from "too strict" to possibly "too loose". That is an accuracy
  question needing labeled data, not a wiring question.
