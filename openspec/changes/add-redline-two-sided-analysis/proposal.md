# add-redline-two-sided-analysis

## Why

A counterparty's redline is two documents in one file: the draft as it stood (every tracked change rejected) and the draft they want (every change accepted). Today the DOCX ingest reads only the second, says so in the "About this input" notice, and stops. The reviewer who wants the finding delta the redline implies must save two copies in Word, one with all changes rejected and one with all accepted, and run `compare`. Almost nobody does, so the question a redline exists to answer, *what did their markup fix, break, and quietly remove*, goes unanswered by the one tool built to answer it deterministically.

Everything needed exists. `compareFiles` already produces resolved / introduced / unchanged findings, the clause redline, and posture movement for two inputs. `docx-notices.ts` already inflates `word/document.xml` and counts `w:ins`, `w:del`, and `w:moveFrom`/`w:moveTo`. The missing piece is a second text projection of the same bytes: the all-rejected reading. With it, one dropped file yields the two runs `compare` needs. The container read already recovers each revision's author (`RevisionFact`), though not its position; adding the span lets each introduced finding name whose change introduced it.

## What Changes

- **Two readings of one DOCX.** `ingestDocxBuffer` (and the `File` wrapper `ingestDocx`) gains a `revisions: "accepted" | "rejected"` option. The rejected reading keeps `w:delText` as ordinary text, drops `w:ins` runs, and treats `w:moveFrom` as present and `w:moveTo` as absent. Default stays `accepted`, so no existing hash moves. Each reading's `source_file.name` is suffixed (`contract.docx#rejected`, `contract.docx#accepted`) because the name is inside `result_hash` and the two runs must not collide.
- **A redline comparison.** `compare --redline contract.docx` (and the browser's "Compare both sides of this redline" affordance on any DOCX whose notice reports tracked changes) runs the existing `compareFiles` over the two readings with the type pinned to the rejected reading's family, and renders the existing comparison artifacts. The MCP `compare_documents` tool accepts `redline_path` as a third input form.
- **Attribution.** Each introduced or resolved finding carries `revision_authors`: the distinct `w:author` values of the revisions whose span overlaps the finding's span in the accepted reading. The Word comparison report's delta table gains an "Author" column. No new hash: attribution is render-side, computed from a span-bearing revision collector (design) that extends what `countRevisions` reads today; it does not require the delivery scan to have run.
- **Honesty.** A DOCX with no tracked changes is refused with a message that says so and points to `compare` for two files. A redline with more than `MAX_COUNT` revisions is compared, with the notice that counting stopped. Nothing is said about whether a change is acceptable; the output is the same finding delta the two-file compare gives.

## Impact

- Affected specs: `version-comparison` (new capability spec; the delta is in this change). Ingest behaviour changes are described here rather than as an `ingest-fidelity` delta because the default reading is unchanged
- Affected code: `src/ingest/docx.ts` and `docx-notices.ts` (the rejected projection, written over the OOXML the notices module already inflates, then handed to mammoth as a rewritten `document.xml`), `tools/cli/compare.ts`, `tools/cli/api.ts` (`compareRedline`), `tools/mcp/tools.ts`, `src/ui/main.ts`, `src/report/compare-docx.ts` (author column), the Action's `base`/`revised` inputs gain `redline`
- Risk: none to existing hashes (the default reading is unchanged). The rejected projection is a new text path and gets the same format-invariance relation the accepted one has.
