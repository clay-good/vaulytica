# Corpus changelog

Every add, removal, or re-annotation bumps `CORPUS_VERSION` and is logged here
(spec-v5 §7 — no silent edits). Scores across corpus versions are never
compared without noting the version change.

## v0.0.0-seed (2026-06-01)

- Initial scaffolding. Zero real documents. Establishes the layout, the split
  manifest, and the provenance/annotation schemas. Real-document sourcing
  (Step 68) and attorney annotation (Step 70) are human-gated and pending.

## v0.0.0-seed — routing scaffolding (2026-10-11)

- Added `routing/labels.json` (25 titles) and the empty `routing/records/`.
  No exhibits sampled; `CORPUS_VERSION` is unchanged because no document was
  added.
- `routing/labels.json`: "registration rights agreement" is a title the catalog
  has no type for, and is labelled so (it had been mapped to the venture
  investor-rights type, which no document with that title routes to). The
  table is now checked against the router in `tools/accuracy/routing.test.ts`.
