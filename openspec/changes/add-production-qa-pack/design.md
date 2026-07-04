# add-production-qa-pack — design notes

## The privilege log as a bundle member, not a document

`ConsistencyDocument` and `DocKind` (`src/engine/consistency/types.ts:18-30`) model
*analyzed documents* — tree + extracted facts. A privilege log is neither: it is
structured data *about* the bundle. Forcing it through document ingest would
pollute the doc pipeline (no clauses, no outline) and the cross-doc pairing
semantics. Instead:

- `planBundle` learns one new member class: `data_members` (v1: exactly one
  `.csv`, parsed by `src/ingest/privilege-log.ts` into a typed
  `PrivilegeLog { rows[], header_map, warnings[] }`).
- Header mapping is deterministic and conservative: recognized synonyms map
  (`BegBates`/`Beg Bates`/`BEGDOC` → `bates_start`); unrecognized columns are
  carried as-is and never guessed. A file that doesn't parse as a log is a
  *rejected member with a reason*, mirroring `rejectionForFilename`.
- PROD reconciliation rules receive `(bundleDocs, privilegeLog)` — a new rule
  shape parallel to, not inside, the `requires: DocKind[]` pairing of CC/CROSS
  rules, so the 20 existing cross-doc checks are untouched.

## Bates identity, v1 honesty

Filename-derived only: `^(?<prefix>[A-Z][A-Z0-9._-]*?)[-_]?(?<num>\d{4,12})` per
member, with the whole bundle's prefix/padding distribution computed before any
finding fires (a single odd file is the finding; two populations of prefixes is
a different finding). In-page stamp verification requires per-page text runs the
`DocumentTree` flattens away (`src/ingest/types.ts:46` has no page concept) —
same plumbing gap the filing pack notes for page-accurate TOA checks. One shared
follow-up change should add optional per-page offsets to PDF ingest; both packs
consume it; neither blocks on it.

## Hash boundaries

- Bundles without a csv member: `planBundle` output, member hashes, and the
  bundle report are byte-identical to today (pinned by regression test).
- The production-QA report is a new artifact with its own namespaced
  `production_qa_hash` (pattern: `delivery_hash`, `critical_dates_hash`),
  covering the reconciliation model — log rows, extracted Bates ranges,
  findings — none of which touches per-document `result_hash`es.
