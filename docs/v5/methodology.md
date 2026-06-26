# Accuracy methodology (spec-v5 §23)

> **Status:** the measurement *method and machinery* are built and unit-tested
> (Steps 67, 69, 71, 83). The *numbers* await a human-gated corpus (Step 68)
> and attorney annotation (Step 70). This page describes exactly what the
> harness measures, how, and what the numbers will and will not claim — so it
> is ready the moment real data lands.

## The claim v5 backs

> On a corpus of real legal documents we did not write, Vaulytica's findings
> agree with a credentialed reviewer's gold annotations with measured
> precision and recall, reproducibly, with a per-rule breakdown.

*Deterministic* is not *correct*. A rule that fires identically every time can
be reproducibly wrong. v5 measures correctness against real documents instead
of the synthetic fixtures that were authored to make the rules fire.

## What the harness does

`npm run accuracy` ([`tools/accuracy/run.ts`](../../tools/accuracy/run.ts)):

1. **Loads** the ground-truth corpus ([`corpus/`](../../corpus/)) — redacted
   real documents, provenance records, and gold annotations — validated
   against the zod schemas on load.
2. **Runs the real engine** over each (document × annotated playbook) in the
   regression split, through the exact `ingest → extract → classify → engine`
   path the browser uses ([`tools/accuracy/pipeline.ts`](../../tools/accuracy/pipeline.ts)
   composes the same `src/` functions as `src/ui/pipeline.ts`; the full
   1,065-rule catalog, all playbooks, the real `matchPlaybook`/candidate
   selection). A measured number reflects shipped behavior, not a test-only
   shortcut.
3. **Grades** the fired-rule set against gold (spec-v5 §8): TP / FP / FN / TN
   per rule, with gold silence on a fired rule scored as a false alarm
   (closed-world over graded documents).
4. **Aggregates** precision, recall, and F1 — micro (pooled counts) and macro
   (mean over rules) — overall and per rule, plus the worst-offenders and
   unmeasured-rule sections.
5. **Stamps and hashes** the scoreboard `(corpus_version, dkb_version,
   engine_version)` and computes `SHA-256(canonical(scoreboard))` with the
   same wall-clock-excluded discipline as the engine's `result_hash` — two
   engineers on the same inputs get a byte-identical scoreboard.

## Metric definitions

| Metric | Formula | Reads as |
|---|---|---|
| Precision | TP / (TP + FP) | "when Vaulytica flags it, how often is it right?" (the trust metric) |
| Recall | TP / (TP + FN) | "of the real defects, how many did we catch?" (the value metric) |
| F1 | harmonic mean of P and R | the single headline per rule |

Micro and macro are both reported: macro so a high-volume rule cannot mask a
broken rare one; micro so the overall number reflects real document mix. A
metric whose denominator is zero is reported as `—` (undefined), never as 0.

## Inter-annotator agreement (κ)

Each document is independently double-annotated; Cohen's κ corrects raw
agreement for chance. A rule graded only on documents where the annotators
disagreed (κ below the confidence threshold, 0.6 by default) is flagged
`low_confidence` and excluded from the headline — reported as `unmeasured`,
with the exclusion count published.

## What the numbers will *not* claim

- **No model.** The corpus measures the deterministic engine; it never trains
  anything, and no corpus-derived statistic ships to the browser as decision
  logic. The classifier feature table remains a hand-authored, inspectable
  table.
- **No runtime privacy change.** Corpus, annotations, and scoreboard live in
  `corpus/`, `tools/accuracy/`, and `docs/`; none is imported by `src/` (a
  guard test asserts it) and none ships in the deployed bundle. The user's
  document still never leaves the tab.
- **Thin coverage is flagged, not faked.** A family below its §4 minimum
  document count ships with an explicit flag rather than a fabricated number.
  Bootstrap placeholder documents (maintainer-authored, to exercise the
  harness) are excluded from every headline number and surfaced as such.

## Legal soundness, not just agreement

Measurement answers *does the rule match a credentialed human's annotation?*
It does **not** answer *is the rule's legal premise sound?* — two annotators
could share a misconception. The [legal-basis ledger](../legal-basis/README.md)
(spec-v5 Part III) is the orthogonal check: a per-rule record of the authority
the rule rests on, pinned to a DKB node, plus a licensed attorney's `verdict`
and confidence `tier` (`established` / `prevailing-practice` / `opinion`). The
`tier` is surfaced on the finding so a statutory flag reads differently from a
drafting preference. The ledger machinery and the optional `tier` field are
built (Step 75) and the ledger is **honestly empty** until attorney review
(Steps 76/77) signs the first entry — the same posture this scoreboard takes
until a real corpus lands. A finding is fully defensible only when it is both
*measured* (here) and *legally reviewed* (the ledger).

## Reproducing the scoreboard

```
npm run accuracy        # writes tools/accuracy/SCOREBOARD.md + scoreboard.json
```

The current scoreboard reports `status: empty` and publishes no precision /
recall number, because there are zero real annotated documents yet — by
design. That honesty is the entire point of v5: we publish a number only when
it is real.
