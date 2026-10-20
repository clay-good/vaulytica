# report-exports — delta

## ADDED Requirements

### Requirement: The tab offers at most three downloads up front

The single-document result SHALL show one collapsed Download section holding at most three named files: the draft with comments (DOCX uploads only), the Word report, and one calendar file (only when at least one date was computed). Every other export SHALL stay reachable under "Other formats," and no export SHALL be removed from the tab, the CLI, the Action or the MCP server.

#### Scenario: A PDF upload

- **WHEN** the input is a PDF
- **THEN** the Download section lists the Word report first, does not show the draft-with-comments button, and Other formats still holds every other export

#### Scenario: No surprise files

- **WHEN** analysis finishes
- **THEN** no file is saved until the user clicks a download button

### Requirement: Renaming does not change contents

Download filenames SHALL follow `<document name> - review.docx`, `<document name> - with comments.docx` and `<document name> - dates.ics`, and every file's bytes SHALL equal what the same export produced before this change.

#### Scenario: Same click, same file

- **WHEN** the user clicks Report twice
- **THEN** both saved files are byte-identical with the same name
