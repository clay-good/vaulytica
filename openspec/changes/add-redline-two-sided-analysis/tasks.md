# Tasks

- [~] 1. Fixtures: a DOCX redline with insertions, deletions, a move, a formatting-only change, and a table-cell change — **BUILT in 9.1010.0**; plus Word's Accept-All and Reject-All exports of it, committed, for the round-trip test — still needs Word (see the note at the end).
- [x] 2. `src/ingest/docx-revisions.ts`: the linear OOXML rewrite producing the rejected `document.xml`; property test that accepted(rewrite) and rejected(rewrite) each contain no revision elements; bounded matching per `container.ts`.
- [x] 3. `ingestDocxBuffer(buf, { revisions })` and the `ingestDocx` wrapper with the `#rejected` / `#accepted` name suffix; the default path byte-identical (corpus goldens unchanged).
- [x] 4. `tools/cli/api.ts` `compareRedline(path, opts)` over `compareFiles` with `pinType`; `compare --redline`; the no-tracked-changes refusal; `MAX_COUNT` notice carried.
- [x] 5. Attribution: `collectRevisions` with spans; overlap join; `revision_authors` on the comparison's introduced/resolved entries; author column in `compare-docx.ts`; Markdown summary column.
- [x] 6. Browser: the comparison affordance on a result whose ingest notice reports tracked changes; the Word deliverable; hashes identical to the CLI on the same bytes (cross-surface parity test extended).
- [x] 7. MCP `compare_documents` `redline_path`; Action `redline` input; `ci-integration.md` example "gate a counterparty redline on a pull request".
- [x] 8. Format-invariance relation for the rejected reading (same five transforms); reach and honesty-caveat tests extended.
- [x] 9. Docs: `reference.md` ingest table row for redlines updated to say both readings are available; the "About this input" notice links to the comparison.
- [x] 10. Full gate green.

## Progress

- 9.965.0 shipped slice A: tasks 2–4, and the MCP half of task 7 (`redline_path`).
  - The fixture is built in code (`redlineDocx()` in `src/delivery/_fixtures.ts`): an insertion, deletions, a move and a paragraph-mark insertion. Word's Accept-All and Reject-All exports of it (task 1's round-trip) need Word and are not committed yet.
  - The rewrite is `indexOf`-based. A malformed part stays linear: an unclosed element ends the scan rather than being searched for again.
  - The CLI refuses a file with no tracked changes, and a file that is not a DOCX.
- 9.966.0 shipped task 5. Attribution is by text containment: a finding names the authors of the insertions (introduced) or deletions (resolved) its quoted paragraph contains. An absence finding names no one. Changes under 12 characters are not used. The comparison DOCX lists authors per finding rather than in a table column, because the report renders findings as blocks, not a table.
- 9.967.0 finished task 7 (the Action `redline` input and the `ci-integration.md` example). Toward task 8, it added a different relation from the one the task names: every run of eight specimens is marked deleted or inserted, and the rejected or accepted reading must then report the plain DOCX's findings. A mutation of the rewrite fails all eight. The five format transforms over a redline are still open.
- 9.973.0 shipped tasks 6 and 9. A DOCX with tracked changes shows "Compare both sides of this redline" beside "Compare a revised version…"; it runs `runRedlineComparison` (the CLI's `compareRedline`: the same `#rejected` / `#accepted` names, the accepted reading held to the rejected reading's type) and renders the comparison page the two-file compare renders. The Word report and the JSON carry `revision_authors`. `prepareDocument` gained an optional reading (`revisions`, a pinned `playbook_id`), as `runIngested` takes them. The cross-surface test checks both runs' hashes, the comparison hash and the attribution against the CLI; an e2e drives the tab and reads the author from the downloaded JSON. The accepted reading's notice now names both ways to compare. The page itself does not show authors; they are in the downloads.
- Task 8 finished (test only, no release): `redline-format-invariance.test.ts`. CRLF and hard-wrap have no DOCX analog (a Word paragraph has no line ending, and a wrapped line is not a paragraph), so the five are the ways a Word redline varies without its words changing: curly quotes, a repeated page legend, an empty paragraph after each paragraph, every run split in two, formatting on every run. Each, applied before marking every run deleted, leaves the rejected reading's findings unchanged on five specimens. The fixture helpers moved to `tests/integration/_redline-docx.ts`, shared with `redline-reading-invariance`. The honesty-caveat surfaces already include the comparison renderers, so no reach entry was added.
- Open: task 1's Word round-trip (needs Word), and with it task 10.

## Progress — 9.1005.0 (task 10)

The full gate is green at 9.1005.0. Task 1's remaining half — Word's own
Accept-All and Reject-All exports of the committed redline, for the round-trip
test — still needs a copy of Word to produce them; the synthesized fixture and
the property test that neither reading contains a revision element are built
(task 2).

## Why task 1's round-trip half is blocked — verified 9.1008.0

The fixture needs Word's OWN Accept-All and Reject-All exports of the committed
redline, because the test exists to check this product's rewrite against what
Word actually produces. Synthesizing those exports here would make the test
compare the rewrite with itself.

Checked on this machine: no `soffice`, no `libreoffice`, no `pandoc`. There is
no headless tool available that accepts or rejects tracked changes with
authority, so the two exports have to come from someone with Word (or
LibreOffice) in front of them.

Built and standing meanwhile (task 2): the linear OOXML rewrite, and the
property test that neither reading — accepted or rejected — contains any
revision element.

## Progress — 9.1010.0 (the five-kind fixture, which needed no copy of Word)

Task 1 is two halves and I had been treating it as one. The Word exports
genuinely need Word. **The fixture does not**, and it was missing: the only
builder, `markEveryRun`, wraps every run in `w:ins` or `w:del`, so the three
kinds where the rewrite must do something other than keep or drop a run were
never exercised by any fixture.

`fiveKindRedlineXml()` builds the five as OOXML directly — `docx` the library
has no API for a tracked move or a `w:rPrChange` — and
`redline-revision-kinds.test.ts` holds both readings to:

- the insertion present only when accepted, the deletion only when rejected;
- 🥇 **a moved clause present EXACTLY ONCE in each reading, at different
  positions.** This is the one worth having. `w:moveFrom` wraps the words at
  their origin and `w:moveTo` the same words at their destination, so a rewrite
  that drops neither half DUPLICATES the clause and one that drops both LOSES
  it. Counting revision elements — which is what the existing property test
  does — sees neither. The test pins the origin in the payment clause when
  rejected and the destination in the remedies clause when accepted, and
  asserts each reading does *not* contain the other arrangement;
- a formatting-only change leaving the text identical on both sides, since
  `w:rPrChange` carries no text and must therefore move no words;
- a revision nested in `w:tc` applied like any other — the case a run-level
  rewrite is likeliest to miss, because the element sits inside table markup;
- no `w:ins`, `w:del`, `w:moveFrom`, `w:moveTo` or `w:rPrChange` surviving into
  either reading.

The fixture is also guarded against itself: a derivation that stopped emitting
one of the five kinds would make the assertions vacuous, so the first case
asserts all five markers are present and that the move's two halves carry the
same words.

**Still needs Word** (or LibreOffice): its own Accept-All and Reject-All
exports, committed, for the round-trip. That test exists to compare this
product's rewrite with what Word actually produces, so a fixture built here
would only compare the rewrite with itself. Verified on this machine: no
`soffice`, no `libreoffice`, no `pandoc`.

## Final determination on the Word exports — 9.1015.0

This is the one item in the repository that needs a person with Word, and the
reason is not an unchecked assumption. It was tested three ways:

1. **No tool on this machine can do it.** No `soffice`, no `libreoffice`, no
   `pandoc`.
2. **Nothing in the dependency tree can either.** `docx` writes DOCX but has no
   accept/reject-revisions API; `mammoth` reads DOCX to HTML and drops
   revisions entirely. Those are the only two Word-format libraries present.
3. **The artifact's purpose makes it unsynthesizable by me.** It exists to be an
   INDEPENDENT oracle — to catch cases where Word's actual behaviour diverges
   from ECMA-376 or from this product's reading of it. If I could predict the
   divergence I would not need the export; writing the expected side myself
   would compare the rewrite with itself, which is the one thing the test is
   designed to rule out.

What stands in for it meanwhile is not nothing:
`redline-revision-kinds.test.ts` holds both readings of a redline carrying all
five revision kinds to the behaviour ECMA-376 defines, including the move case
where a rewrite that drops neither half DUPLICATES a clause and one that drops
both LOSES it — which counting revision elements cannot see. That covers the
rewrite against the STANDARD. Only Word-versus-standard divergence is
uncovered.

**What a person needs to do:** open the committed redline in Word, Accept All
and save as one file, Reject All and save as another, commit both beside the
fixture, and the round-trip assertion becomes a byte comparison. Nothing else
on this change is waiting.
