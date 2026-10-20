# simplify-result-downloads

## Why

Measured on vaulytica.com at 9.965.0 with a pasted NDA: the result shows sixteen download buttons, including Markdown, CSV, HTML, SARIF, JSON and two certificate formats. Two calendar files sit side by side ("Deadlines (.ics)" and "Critical dates (.ics)") with nothing saying how they differ, and "Reviewed copy (.docx)" is shown greyed out because pasted text has no Word file to annotate. Each one is useful to someone. Shown together, they turn "take this with me" into a choice among sixteen files. Once the page itself answers the question (`add-results-page`), a download is only about where the user's work goes next, and for most users that is Word, a calendar, or nowhere.

## What Changes

One **Download** section at the bottom of the page, collapsed by default. Opened, it shows at most three named files, each with a one-line reason:

| Button                               | When shown                     | One line under it                                                          |
| ------------------------------------ | ------------------------------ | -------------------------------------------------------------------------- |
| **Your draft with comments (.docx)** | DOCX upload                    | "Each item above as a Word comment on its clause. Your text is unchanged." |
| **Report (.docx)**                   | Always                         | "The full report in Word, for the file or a colleague."                    |
| **Dates for your calendar (.ics)**   | When the document states dates | "Renewal, notice and cure dates."                                          |

- For a PDF or pasted text, the draft-with-comments button does not appear, and the Report is listed first. A disabled button with a tooltip is not shown.
- **Other formats** is a second fold below the three. It groups every remaining export under two plain headings: _Spreadsheets_ (fix list, obligations, closing checklist, definitions, negotiation posture) and _Records and data_ (verification certificate, JSON, HTML, Markdown, SARIF). No format is removed, and the CLI, Action and MCP formats are unchanged.
- **One calendar file.** The tab offers a single .ics. The build first measures how `deadlines.ics` and `critical-dates.ics` overlap on the corpus, then ships the register's file where it exists and the deadlines file otherwise. Both stay available under Other formats and from the CLI.
- **Filenames** follow one pattern: `<document name> - review.docx`, `<document name> - with comments.docx`, `<document name> - dates.ics`.
- After a download, the page says in one line where the file went ("Saved Mutual NDA - review.docx"). Clicking the same button twice saves the same file again: same bytes, same name.

## Impact

- Affected specs: `report-exports`
- Affected code: the `complete` template and export wiring in `src/ui/states.ts`, filename helpers in `src/ui/pipeline.ts`, and tests
- Hashes: none. Every file is byte-identical to today's except its name.
