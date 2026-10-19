# add-executed-copy-conformity

## Why

The last document in a deal is the one nobody reads: the signed PDF that comes back from the counterparty or the e-signature platform. The malpractice record says it should be read. In one New York case the client signed a revision described as fixing a typo; the revision also carried a change worth $4,000,000 against the client, and the claim survived. In another, a lender relied on the wrong version of a subordination agreement supplied by its own firm. Eric Goldman's signing protocol begins with confirming the execution copy *is* the final draft because drafts get swapped at the eleventh hour. The check is mechanical: does the executed copy's text match the final draft's text, outside the blanks that execution is supposed to fill?

`compare` already diffs two documents clause by clause. What it lacks is the frame for this question: the differences that execution legitimately introduces (dates filled in, `/s/` and names on signature lines, initials, a "FINAL" watermark becoming "EXECUTED", page furniture from a scanner) must be set aside, and what remains must be reported as a plain list with a verdict that is honest about OCR. The browser already runs OCR on image-only PDFs, so the common case, a scanned signature packet against a Word final, works in the tab today without any server.

## What Changes

- **`compare --executed final.docx signed.pdf`** (browser: "Check the signed copy against the final"), a mode of the existing comparison that:
  - normalizes both texts with the existing clause-diff normalization plus an **execution allowance**: signature-block lines (`By:`, `Name:`, `Title:`, `Date:`, `/s/`, witness and notary blocks), filled date blanks where the draft had `____` or `[●]`, initials lines, and page furniture already classified by `page-furniture.ts`;
  - reports every remaining difference as a clause-level redline, and a **conformity line**: *identical outside the execution allowance* · *N differences outside the allowance* · *could not determine (OCR confidence below threshold on M pages)*;
  - lists the allowance items it set aside, so a reviewer can see what was filled in and by whom the block says.
- **A closing-set mode** over two folders: `compare --executed-set ./final ./signed` pairs files by normalized title (the matcher's title, not the filename), reports unpaired files on either side, and renders one table: document · conformity · differences · pages OCR'd. Hashes: `conformity_hash` over the canonical table, namespaced apart from every `result_hash`.
- **Honesty.** A signed PDF that needed OCR carries the OCR notice and its low-confidence words; a difference inside a low-confidence span is reported as *unverified*, never as a change and never silently dropped. The CLI runs no OCR, so an image-only PDF is refused headless with the message that the browser can do it.

## Impact

- Affected specs: `version-comparison`
- Affected code: `src/report/clause-diff.ts` (an `allowance` filter), new `src/report/conformity.ts`, `tools/cli/compare.ts`, `tools/cli/api.ts`, `src/ui/main.ts`, DOCX/Markdown/JSON renderers for the conformity table
- Risk: none to existing hashes; the comparison `result_hash` is untouched and the conformity table carries its own
