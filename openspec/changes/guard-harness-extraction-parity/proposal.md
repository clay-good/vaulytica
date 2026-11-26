# guard-harness-extraction-parity

## Why

Three times in one session a test harness built `extracted` differently from the product, and each
time something else found it:

| harness | how it was found |
| --- | --- |
| `src/engine/_test-fixtures.ts` — the shared rule-test context builder | a static sweep, by luck |
| `tests/golden/artifact-digests.test.ts` | by inspection, while adding a digest |
| `tests/integration/cli-docx-report.test.ts` — a **parity** test | went red in the gate |

Nothing was looking for the class. That is a bad detection story for a defect that has recurred
three times, and the next instance will look different again.

## What the sweep found

Not every harness should be held to the product's extraction options — `tests/` holds ~90
`extractAll` calls and most are unit fixtures asserting things jurisdictions have nothing to do
with. Three reasons mark the ones where the omission changes what the harness *proves*:

| reason | files | result of fixing |
| --- | --- | --- |
| **committed output** — a pin built from inputs the product never produces enshrines an artifact no user receives | 4 golden pipelines | **inert**: 820 golden tests passed unchanged |
| **renders a report artifact** — where a missing option becomes a wrong cell | 7 harnesses | inert: 30 tests passed unchanged |
| **asserts on `jurisdiction_id`** — an assertion over a field the harness never populates | 1 | 🥇 **a live vacuity** |

🥇 **The live one.** `extraction-format-invariance.test.ts` projects
`[clause_kind, jurisdiction_id ?? ""]` to assert the id survives a format transform. The harness
built `extracted` without the lookup, so **every value in that projection was the empty string**: it
compared `""` to `""` on every document and every transform, and the `clause_kind` half was doing
all the work. **An assertion over a field the harness never populates does not fail — it quietly
stops being a test.** Wired, the invariance holds, so the finding is a dead assertion rather than a
behavioural bug. A `resolvedIds` floor now makes the vacuity itself detectable.

The other two reasons were latent, not live, and this proposal says so rather than claiming eleven
bugs. They would have bitten the next artifact added to those goldens.

## What changes

- 13 harness call sites wired across 11 files.
- `_extract-all-sites.ts`: **one** scanner, shared with the product guard — balanced-delimiter
  scanning that sees every call shape, and skips a string literal (so it can read itself), a
  comment, the declaration, and a member call **but not a spread**.
- A harness sweep over `tests/` + `tools/`, selecting by the three reasons above.
- `resolvedIds` floor in `extraction-format-invariance`.

## Proof

Each reason was proved to bite by unwiring a real site:

- committed output → `tests/golden/v4/_pipeline.ts`, `v3/_pipeline.ts`, `_pipeline-helpers.ts`
- renders a report → `html-report-content-parity.test.ts`
- asserts on the field → `extraction-format-invariance.test.ts`

🚨 **That exercise found a hole in the rule.** The first version attached *committed output* to the
file holding the `VAULYTICA_REGEN_GOLDEN` gate — but the gate sits in `golden.test.ts` while the
extraction happens in its `_pipeline.ts` helper, so unwiring the helper left the sweep **green**.
The reason now propagates one level through local imports. Proving a guard by failing is not
ceremony: it is the only step that tests the guard's own reach.

The sweep also found a file the hand survey missed — `critical-dates-no-wallclock.test.ts` — because
the survey's render pattern was narrower than the shared one.

## Impact

- The three vacuity assertions (class size, each reason selecting something, real wired sites
  found) are what stop this passing by matching nothing.
- `tests/` is still not swept wholesale, deliberately: a guard that flags 40 files nobody will fix
  becomes an exceptions table.
- Still open, unchanged: `tools/cli/artifacts.ts` calls `extractAll` with no classifier where the
  accuracy pipeline passes one. Same shape, different field, and `extracted.classified` feeds
  routing — it needs its own measurement first.
