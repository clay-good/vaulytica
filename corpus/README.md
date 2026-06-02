# Vaulytica ground-truth corpus (spec-v5 Part I)

The real-document corpus the accuracy harness grades against. This is the
foundation of the v5 "Ground Truth" claim: *on real contracts we did not
write, here is the engine's measured precision and recall.* It is **not** the
synthetic unit fixtures (`tests/fixtures/contracts/`), which stay where they
are as the regression layer — the two sets are kept disjoint and a guard test
([`tests/integration/accuracy-corpus-guard.test.ts`](../tests/integration/accuracy-corpus-guard.test.ts))
asserts it.

## Status: seed (scaffolding only)

`v0.0.0-seed` carries **zero real documents**. Sourcing real, license-clean,
attorney-annotated documents is human-gated work (spec-v5 Steps 68, 70) that
code cannot do. The harness, schemas, redaction tool, metric math, and κ
computation are all built and unit-tested; the moment a real `(document,
provenance, annotation)` triple lands here, `npm run accuracy` produces a real
number. Until then the scoreboard reports the honest empty state.

## Layout

```
corpus/
  CORPUS_VERSION              # the versioned artifact stamp (spec-v5 §7)
  manifest.json              # corpus_doc_id → split (regression | development)
  CHANGELOG.md               # no silent edits: every add/remove/re-annotate logged
  documents/<id>.txt          # redacted document text (real source never committed)
  provenance/<id>.json        # source, license, retrieval date, redaction log
  annotations/<id>__<pb>.json # gold annotation per (document × playbook)
```

## Storage decision (spec-v5 §7 / Open-Q #1)

Redacted text + JSON annotations live **in-repo** as plain files. Rationale:
the redacted derivatives are small (text-only, party detail masked), keeping
clone-time low and review trivial — a reviewer can read a diff. If the corpus
later outgrows a comfortable repo size, the migration path is a Git-LFS
pointer for `documents/` only; the provenance and annotation JSON stay in-repo
because they are the auditable trust artifacts. The **original unredacted
source is never committed** — only the redacted derivative and the provenance
record (which links back to the public source, e.g. an EDGAR accession).

## Adding a document

1. Obtain a license-clean source (EDGAR Ex-10 exhibit, CC0 template bank, or a
   donated+consented document — see spec-v5 §4 priority order).
2. Redact identities with `tools/accuracy/redact.ts`; keep clause headings,
   defined terms, and governing-law phrasing intact.
3. Write `provenance/<id>.json` (validated by `ProvenanceSchema`) with the
   source ref, license, retrieval date, redaction log, and the redacted text's
   SHA-256.
4. Have two credentialed annotators independently annotate, then adjudicate
   (spec-v5 §5); commit `annotations/<id>__<playbook>.json` per playbook.
5. Assign the doc to `regression` or `development` in `manifest.json` and bump
   `CORPUS_VERSION`; log the change in `CHANGELOG.md`.

A document below its family's §4 minimum ships with a `corpus_thin` flag on
its accuracy claim rather than a fabricated number. A maintainer-authored
placeholder used only to exercise the harness is marked `"bootstrap": true` in
its provenance and is excluded from every headline number.
