# add-word-comment-export

## Why

Today the deliverable is a *separate* Word memo; `src/report/docx.ts:301` is explicit that no redline is ever generated. So an attorney must cross-reference every finding back into their own draft by hand — the highest-friction step in the whole workflow. Market research is unambiguous: the tools attorneys actually adopt live inside their own document (Word-native review is table stakes across Spellbook, Definely, Litera). Vaulytica already holds the original DOCX container bytes in the tab (the v9 pre-disclosure surface reads them); annotating a *copy* of that container with anchored comments keeps every existing invariant — comments are review metadata, not drafted contract language, so the lint-not-draft line holds.

## What Changes

- New export: "Reviewed copy (.docx)" — a byte-copy of the *uploaded* DOCX with one Word comment (`word/comments.xml` + anchor ranges) per finding, anchored at the finding's excerpt location, authored as `Vaulytica <version>`, containing the rule id, severity, explanation, citation, and recommendation.
- Anchoring is deterministic: excerpt offsets map to the flattened-text positions the engine already records; a finding whose anchor cannot be located lands in a document-start "unanchored findings" comment — never dropped, never guessed.
- The document body is byte-identical to the upload (a test asserts only comment-related parts differ); the export never touches PDFs (DOCX-only, greyed out otherwise) and never fires for paste input.
- Available in the tab and from the CLI (`--format docx-comments`).

## Impact

- Affected specs: `report-exports` (new capability spec)
- Affected code: new `src/report/docx-comments.ts` (container-level writer over fflate, reusing the v9 container reader), export wiring in `src/ui/` + `tools/cli/run.ts`; tests including a body-unchanged byte assertion
- Risk: none to existing exports — purely additive surface; determinism holds (same inputs → identical annotated container, no timestamps inside comment XML beyond a fixed epoch value).
