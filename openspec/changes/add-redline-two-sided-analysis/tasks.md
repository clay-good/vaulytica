# Tasks

- [x] 1. Fixtures: a DOCX redline with insertions, deletions, a move, a formatting-only change, and a table-cell change — **BUILT and COMMITTED** (`tests/fixtures/redline/five-kind-redline.docx`, 9.1016.0). **The independent cross-check it exists for is DONE for BOTH readings (9.1019.0, 9.1021.0), without Word.** macOS's `textutil` reads .docx through Apple's text engine: run over the fixture it yields the ACCEPTED reading, and run over the fixture with every revision's role SWAPPED (`w:ins`⟷`w:del`, `w:moveTo`⟷`w:moveFrom`, `w:t`⟷`w:delText`) it yields the REJECTED one — accepting inverted revisions is rejecting them. Apple's engine does the resolution in both directions and the swap reuses nothing from `docx-revisions.ts`, so a wrong decision in our reject logic fails the test. Each direction is paired with a discrimination assertion (theirs is not our *other* reading), and the swap is self-checked by involution — swapping twice must reproduce the original byte for byte. ⚠️ The residual the swap cannot rule out is a bug in itself mirroring one in the rewrite, which is why the **Word round trip stays ARMED**: Word's own export needs no such argument, and it runs the moment the exports are committed. Producing them is optional now, not blocking.
- [x] 2. `src/ingest/docx-revisions.ts`: the linear OOXML rewrite producing the rejected `document.xml`; property test that accepted(rewrite) and rejected(rewrite) each contain no revision elements; bounded matching per `container.ts`. **Hardened at 9.1020.0:** that property was checked only with this repository's own reader, so a rewrite emitting unbalanced tags, an orphaned `w:r` or a broken zip entry could pass every test here and fail in the user's Word. `withRevisionsRejected`'s output is now opened by Apple's text engine and its word sequence compared. ⚠️ `textutil` does not error on malformed OOXML — it exits 0 and prints nothing — so the non-empty assertion is what catches it and is load-bearing (measured: a dropped `</w:p>`, an orphaned-run rename, and a 70%-truncated XML all gave exit 0 and empty output).
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

## Progress — 9.1016.0: armed, not merely blocked

The one item in the repository that needs a person is now reduced to exactly
that person's action, and nothing else.

**The fixture is committed.** `tests/fixtures/redline/five-kind-redline.docx`,
written by `npm run redline:exports`, carrying all five revision kinds. It was
only ever a function before, so there was nothing for anyone to open.

**The round-trip assertion exists and is armed.**
`tests/integration/redline-word-roundtrip.test.ts` looks for
`five-kind-accepted-word.docx` / `five-kind-rejected-word.docx` (or the
`-soffice` pair) beside the fixture. Absent, it skips and says what it is
waiting for. Present, it compares both readings word for word — **and that
branch is proven live, not dead code**: copying the redline in as a deliberately
wrong "accepted" export makes the comparison RUN and FAIL, and removing them
returns it to skipping.

So the state is no longer "blocked with a note". It is: do the four steps
`npm run redline:exports` prints, commit two files, and the assertion runs on
every test pass thereafter — and keeps running, failing if this product's
rewrite ever drifts from Word's reading. A task-list note would have done
neither.

**Why the exports still cannot be generated here**, restated because it is the
reason the arming is the right answer rather than a workaround:

- npm does have OOXML redline engines (`@ansonlai/docx-redline-js`,
  `@stll/folio-core` and others — I checked rather than assumed, having
  previously only checked this repository's own dependencies). **None of them
  is Word.** Using one would substitute a second unverified implementation for
  the first, and the whole value of this test is Word-versus-us.
- Adding such a dependency to a product whose premise is no server, no AI and
  no trusted third party, for the sake of a test fixture, is a judgment for a
  maintainer rather than something to slip in.
- The comparison is on TEXT, not bytes, deliberately: Word rewrites styles, ids
  and revision bookkeeping on save, so a byte comparison would fail for reasons
  unrelated to which words survive — and which words survive is the question.

## Correction — what I asserted about LibreOffice, and what is actually known

At 9.1016.0 I wrote that LibreOffice's accept/reject-all "only exists in its
UI". **That was an overstatement I had not checked**, and correcting it matters
because it is the difference between "impossible" and "nobody has confirmed the
command name yet". Read at official sources on 2026-11-24:

| | |
| --- | --- |
| **Confirmed** | `--convert-to` only converts and cannot apply a redline operation first, so a one-line CLI conversion genuinely is not enough. |
| **Confirmed** | `com.sun.star.document.XRedlinesSupplier` exposes exactly one method, `getRedlines()`, returning an enumeration; `com.sun.star.text.XRedline.makeRedline()` *creates* redlines. Neither documents an accept-all or reject-all. |
| **Confirmed** | `com.sun.star.frame.XDispatchHelper.executeDispatch(...)` exists — the route a `.uno:` command would take. |
| **Confirmed** | .docx filter names for saving: `"MS Word 2007 XML"` and `"Office Open XML Text"`. |
| **NOT confirmed** | the names `.uno:AcceptAllTrackedChanges` / `.uno:RejectAllTrackedChanges`. The wiki page listing dispatch commands refuses automated reads. |
| **NOT confirmed** | whether a Basic macro runs under `--headless` in the form this would need. The documented form is `{file} macro://./[Library.Module.MacroName]`. |

**So a scripted route is PLAUSIBLE and unverified — not impossible.** No macro
is committed here, deliberately: it would rest on a dispatch-command name no
official source confirmed and could not be executed on this machine, and
untested tooling in a repository is worse than an honest instruction. It would
also be the one piece of this change nobody could trust.

**The two things that would settle it**, for anyone with LibreOffice to hand:
run `soffice --headless` against a redline with a macro calling
`executeDispatch` for the accept-all command, and see (1) whether the command
name resolves and (2) whether the macro runs at all without a GUI. If both
work, the exports become one command and this task closes without Word.

**Not done here on purpose:** installing LibreOffice. It is a large
application and a change to the developer's own machine, which is their
decision to make, not a side effect of a build loop.

## 🥇 9.1019.0 — half of this closed without Word, and my own framing was what blocked it

I had written that the exports need Word and that "producing them is one human
action". The first half was a claim about the ARTIFACTS I had pictured — two
`.docx` files — and I never tested it against the REQUIREMENT, which is only
this: *a second implementation's reading of ECMA-376, written by someone other
than this repository.*

macOS ships one. `textutil` reads .docx through Apple's text engine and
resolves tracked changes on the way to plain text. It needs no human, no
install and no committed binary, and it is reproducible on any Mac. Its one
reading is the accepted one, and this product's accepted reading matches it
word for word on all five revision kinds.

What I had actually checked before calling it blocked: whether Word was
installed, and whether npm had an OOXML redline engine. What I had **not**
checked: whether anything already on the machine could read a .docx at all.
`textutil` has shipped with macOS for twenty years.

The lesson, which is the same one seven other "blocked" items in this change
set taught: **a blocked reason names the artifact someone imagined, not the
requirement.** Ask what the test actually needs to be true, then ask who else
in the world already does that.

### 🥇 9.1021.0 — the rejected half too, by inverting the markup not the reader

`textutil` resolves revisions one way only: it accepts them. I read that as
"it cannot speak to the rejected reading" and left the rejected half blocked.
Same mistake as the one above, one level down — reasoning about the READER's
options instead of the requirement.

Accepting insertions and dropping deletions, over a document whose insertions
and deletions have been swapped, IS the rejected reading. Invert the input
markup and Apple's engine does exactly the work it already does.

🚨 The swap was wrong twice before it was right, and **both ways were silent**:
`<w:del([^>]*)>` also matches `<w:delText ...>`, destroying every deleted run,
and sentinelling only one direction let the second pass re-match what the first
had just written. Each produced a DOCX `textutil` read as EMPTY — never as an
error. That is why the swap is self-checked by involution and by preserved
element counts, and why every textutil comparison asserts a non-empty result.

The lesson on top of the one above: **when a tool does half of what you need,
ask whether the INPUT can be transformed so that half becomes the whole.**

### pandoc, considered and NOT armed

Asking the same question for the rejected reading turns up pandoc, which has a
`--track-changes` option. It is not installed here. Read at
`https://pandoc.org/MANUAL.html` on 2026-11-24:

| | |
| --- | --- |
| **Confirmed** | the option is `--track-changes=accept|reject|all`, `accept` is the default, and "This option only affects the docx reader". |
| **Confirmed** | `-t plain` is a valid output format. |
| **Confirmed** | `accept` "processes all the insertions and deletions". |
| **NOT confirmed** | that `reject` yields the rejected READING. The manual's only words for it are "`reject` ignores them" — it never says deleted text is restored, which is the entire question. |
| **NOT confirmed** | anything about `w:moveFrom`/`w:moveTo`. Neither term appears, and a move is the revision kind most easily got wrong: it is duplicated-or-lost, and counting revision elements sees neither failure. |
| **NOT confirmed** | anything about formatting-only changes. |

**So no pandoc assertion is armed**, on the same ground the LibreOffice macro
was not committed: an assertion resting on semantics no official source pins
down would fail for reasons nobody could attribute, and a test that cannot be
trusted on failure is worse than none. `textutil` was armed because its
behaviour was MEASURED here, not assumed.

What would settle it, for anyone who has pandoc (`brew install pandoc` — a
small CLI, not the 1 GB GUI application LibreOffice is): run it with
`--track-changes=reject -t plain` over
`tests/fixtures/redline/five-kind-redline.docx` and compare against this
product's rejected reading. If the deleted text comes back and the moved clause
sits in its original position, the assertion is worth arming and this task
closes with no Word at all. If `reject` merely drops the markup, pandoc cannot
settle the rejected half either, and that is worth recording too.
