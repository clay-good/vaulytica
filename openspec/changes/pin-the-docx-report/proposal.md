# pin-the-docx-report

## Why

`wire-jurisdiction-id-resolution` shipped with the DOCX jurisdiction column fixed and this note in
its Impact section: *the DOCX report is not digest-pinned, so its prose and tables can change
without any test noticing.* That is this change — and chasing it found two things worse than the
missing pin.

**1. The CLI never got the fix.** The reach guard written to prove the lookup was wired swept
`src/` only. `tools/cli/artifacts.ts` builds its own `extracted` with a bare `extractAll` and hands
it to `buildDocxReport`, so **the CLI's report still printed `—` in every id cell** — the surface
agents and scripts use. Fourteen call sites across four `tools/` files were unwired, plus
`src/report/abstract.ts`. The guard was green the whole time.

**2. The guard could not see the defect it was written for.** Its scan required an options object
(`extractAll(…, { … })`), so a call with no options at all matched nothing. Proved by failing:
unwiring the CLI site left the guard **green**. Same shape as `export-reach`'s regex that matched
`export function build*` and so could not see `export async function buildDocxReport` — the full
attorney-facing report — for the CLI's entire existence.

## What changes

| | |
| --- | --- |
| `tools/` + `src/report/abstract.ts` | 15 `extractAll` call sites now pass the resolver |
| the reach guard | sweeps `src/` **and** `tools/`; scans with balanced delimiters, so every call shape is visible; skips the declaration and prose |
| `_docx-part.ts` | the document-part extraction and the one `nanoid` exception, shared |
| `artifact-digests.json` | a committed `docx_document_xml` digest per fixture |

## The stated reason was half true

`artifact-digests.test.ts` declared the DOCX absent because the `docx` library mints hyperlink
relationship ids with `nanoid()`, so *"a digest here would fail everywhere and teach nobody
anything."* The fact was true; the conclusion was not. `report-reproducibility.test.ts` had
**already** solved it — normalizing the ids and comparing `word/document.xml`.

What that test compares is render A against render B of the *same code*. It proves DETERMINISM and
pins no CONTENT: rename a column header and both renders change together, and it stays green. So
the artifact was covered in the one respect that could not catch a wrong column, and uncovered in
the respect that could.

Pinning the normalized part needed no new capability — only the recognition that *"the bytes are
not comparable"* and *"the content is not pinnable"* are different claims.

## Proof

- Unwiring the lookup in the digest harness moves both `docx_document_xml` digests → the pin
  captures the ids, so the dash would now fail.
- Renaming the `"Normalized id"` column moves both digests → the pin catches prose.
- In each case **only** that key moved; the other seven digests and `result_hash` held.
- Regenerating added the two new keys and changed nothing else, so passing the resolver into the
  harness is inert for every other artifact.
- Unwiring the CLI call site now fails the reach guard, naming `tools/cli/artifacts.ts`.

## Impact

- ⚠️ What is still NOT pinned: the zip container. Per-entry archive metadata and
  `docProps/core.xml`'s creation stamp sit outside the document part, so a change in how the
  archive is assembled would not show here.
- `tests/` is deliberately not swept — 91 `extractAll` calls, nearly all unit fixtures that assert
  nothing about jurisdictions. The exception is a harness whose output is COMMITTED; both of those
  pass the resolver, and the digest set is what fails if that changes.
- `tools/cli/artifacts.ts` also calls `extractAll` with no classifier, where the accuracy pipeline
  passes one. Noted, not changed: `extracted.classified` is a separate surface with its own
  blast radius.
