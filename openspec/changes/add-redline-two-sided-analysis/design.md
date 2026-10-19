# Design — the rejected reading

## Where the projection lives

mammoth resolves tracked changes while converting. The simplest correct route is to rewrite `word/document.xml` *before* mammoth sees it, so mammoth's own structure handling (headings, lists, tables, numbering) applies to both readings identically:

| Element | Accepted reading (today) | Rejected reading |
|---|---|---|
| `w:ins` | keep children | remove element and children |
| `w:del` | remove element | unwrap; rename each `w:delText` to `w:t` |
| `w:moveTo` | keep | remove |
| `w:moveFrom` | remove | unwrap (its `w:delText` becomes `w:t`) |
| `w:rPrChange`, `w:pPrChange`, `w:numberingChange` | drop the record | drop the record (formatting history is not text) |
| `w:cellIns` / `w:cellDel` / `w:cellMerge` | table-level; accept | reject (keep deleted cells, drop inserted) |

The rewrite is a linear pass over the XML string with the same bounded, non-backtracking matching `container.ts` uses for `w:del` (its comment on matching the closing tag whole applies here). The output is handed to mammoth as a modified zip in memory; the original bytes are untouched, so the delivery scan and `docx-comments` still see the file the user dropped.

## Pinning and naming

- The rejected reading is `base`, the accepted reading is `revised`; `pinType: true`, so the revision is analyzed under the base reading's family even if the markup is heavy enough to re-route it.
- `source_file.name` becomes `<name>#rejected` and `<name>#accepted`. `verify` already handles the name as part of the hash; the receipt names both.
- `result_hash` for the accepted reading is **not** equal to `analyze contract.docx`'s hash, because the name differs. The comparison report says so in one line, so a reader does not report a determinism defect.

## Attribution

`countRevisions` becomes `collectRevisions`, returning for each revision its kind, author, and the character span its text occupies in the *accepted* reading (insertions) or would occupy in the *rejected* reading (deletions). A finding's span in the accepted run overlapping an insertion's span yields that insertion's author; a resolved finding's span in the rejected run overlapping a deletion's span yields the deleter. Multiple authors are listed sorted. Span computation reuses the run-boundary walk `docx-comments.ts` already performs to anchor comments.

## What this is not

Not a redline generator, not an acceptance recommendation, not a merge. The tool reads two states the file already holds and reports the same deterministic delta it reports for two files.
