# Annotation protocol (spec-v5 §5, Step 69)

> **Status:** protocol + tooling shipped; annotation itself is human-gated
> (spec-v5 Step 70) and pending a credentialed annotator.
> **Schema:** [`tools/accuracy/schema.ts`](../../tools/accuracy/schema.ts) (`GoldAnnotationSchema`).
> **κ tooling:** [`tools/accuracy/kappa.ts`](../../tools/accuracy/kappa.ts).

A document without a gold annotation is unusable for measurement. The
annotation is a human's ground-truth statement of what the engine *should*
produce on a real document — the thing the engine is graded against.

## The unit

For each **(document × applicable playbook)** pair, the annotator records the
**expected finding set**: which rule IDs *should fire* (a true defect or
required-clause absence is present) and which *should not fire*. By the
closed-world convention (spec-v5 §8), any rule the engine fires that the
annotation does not mark `should_fire` is scored as a false positive — so the
annotation must be complete for the playbook's surface, not just a sample.

Free-form `uncovered_defects` capture real problems no current rule covers.
These are tracked to prioritize new rules; they are **never** scored against
the engine (you cannot dock recall for a rule that does not exist).

## The five rules of the protocol

1. **Annotators are credentialed.** Annotation is a legal judgment, not data
   entry. Annotators are licensed attorneys, or supervised senior law students
   with a documented attorney review. The annotator ID and date are recorded.
2. **Author ≠ annotator.** A rule is not annotated as ground truth by the
   person who wrote the rule — the same separation the legal-basis review
   (spec-v5 §13) requires.
3. **Double-annotation + adjudication.** Each (document × playbook) is
   annotated independently by two annotators. Disagreements are surfaced and
   resolved by a third senior adjudicator. **Cohen's κ is computed and
   published** — if the humans cannot agree, the engine cannot be graded
   against a coin flip, and that rule's metric is flagged `low_confidence`
   (κ < 0.6 by default; re-decided against the first measured κ in Step 70).
4. **Blind to engine output.** Annotators do not see Vaulytica's findings
   before annotating. Annotating against the tool's output launders the tool's
   errors into the ground truth.
5. **Version-stamped.** Each annotation records the DKB version it was made
   against; the corpus version stamps the release. Every published number is
   reproducible to `(corpus_version, dkb_version, engine_commit)`.

## The gold-standard JSON (one file per document × playbook)

```jsonc
{
  "corpus_doc_id": "edgar-10k-ex10-2021-acme-msa-redacted",
  "playbook_id": "msa-general",
  "annotator_a": "att-014",
  "annotator_b": "att-022",
  "adjudicator": null,          // set once an A/B disagreement is resolved
  "kappa_input": true,           // feeds the inter-annotator κ
  "dkb_version_at_annotation": "v0.0.1-starter",
  "expected_findings": [
    { "rule_id": "MSA-006", "verdict": "should_fire",
      "evidence_hint": "no liability cap in §11", "severity_expected": "critical" },
    { "rule_id": "MSA-024", "verdict": "should_not_fire",
      "note": "governing law and venue both NY — consistent" }
  ],
  "uncovered_defects": [
    { "description": "one-sided audit right with no notice period", "no_rule_yet": true }
  ]
}
```

`should_fire` / `should_not_fire` are the gradable verdicts. The file lives at
`corpus/annotations/<corpus_doc_id>__<playbook_id>.json` and is validated by
`GoldAnnotationSchema` on load — a malformed annotation fails the harness
rather than silently mis-grading.

## How κ is computed

`cohensKappa(pairs)` takes the two annotators' independent verdicts on the
same set of (document × playbook × rule) items and returns κ corrected for
chance agreement, with the Landis & Koch interpretive band. A rule whose
grading documents are all below the confidence threshold is reported as
`unmeasured` and excluded from the headline precision/recall — and that
exclusion count is itself published (spec-v5 §11), so "we shipped 1,000 rules
but measured 600" can never hide.
