# Design — execution allowance

## What execution may change

| Allowed difference | How it is recognized | Not allowed |
|---|---|---|
| signature lines filled | a paragraph within a signature block (the extractor's block window) whose draft form is a label with a blank and whose executed form is the label with text, or a `/s/` line | a new signatory the draft did not list (reported, because STRUCT-017 would) |
| dates filled | the draft paragraph has `____`, `[●]`, `[date]`, `[__]`, or a bare `, 20` and the executed paragraph has a parseable date in that position | a date that differs where the draft already had one |
| initials | a paragraph of ≤ 4 tokens matching initials patterns at a page edge | — |
| exhibit cover pages | pages whose text is only an exhibit label | an exhibit missing on one side (reported) |
| scanner furniture | running headers, "Page N of M", Bates stamps, already classified by `page-furniture.ts`; a fax-header pattern is added there | — |
| watermark words | `DRAFT`, `FINAL`, `EXECUTION VERSION`, `EXECUTED`, `CONFORMED COPY`, alone in a paragraph | — |

Everything else is a difference. The allowance never applies to a paragraph outside the recognized shapes, so a changed number in §4.2 is a difference even if a date was also filled in that paragraph.

## The verdict's three values

The verdict is a classification of the diff, not a legal conclusion. "Identical outside the execution allowance" means the normalized texts match after the allowed paragraphs are set aside. It does not mean the document was validly executed, that the signatories had authority, or that the copy is the one filed. The report says this in the same sentence as the verdict.

## OCR

Executed copies are usually scans. In the browser, `ocr.ts` already produces text with per-word confidence. A difference whose executed-side span contains any word below the existing low-confidence threshold is reported under *unverified*, with the words, and the verdict becomes *could not determine* if any unverified difference exists. The user is told which pages to read by eye. Headless, the CLI refuses an image-only PDF for this mode with a message naming the browser, consistent with the MCP server's "no text layer" behaviour.

## Pairing a closing set

Files are paired by the matcher's normalized title (the same `titleCorpus` routing uses), not by filename, because signed copies arrive as `Scan_0041.pdf`. Ties and unpaired files are listed; nothing is guessed. The table's rows are sorted by title; `conformity_hash` is SHA-256 over the canonical rows.
