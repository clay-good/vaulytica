# results-page — delta

## ADDED Requirements

### Requirement: The result is a page that says what to raise and why

After a single document is analyzed, the tab SHALL show a headline stating how many things to raise and a to-do list holding every actionable finding (`isActionable`) and every critical or warning delivery item, in report order. Severity SHALL be labeled "Fix before signing," "Worth raising," or "Optional." No file SHALL download without a user click.

#### Scenario: The legend NDA

- **WHEN** `tests/fixtures/specimens/legend-nda.txt` is pasted
- **THEN** the headline reads "6 things to raise before you sign," the list holds those six rows, and "Also noted (2)" is collapsed below

#### Scenario: Nothing to raise

- **WHEN** a document produces no actionable finding and no critical or warning delivery item
- **THEN** the headline carries the existing clean-result statement and never says "clean," "safe," or "compliant"

### Requirement: A row opens to why and what to ask for

Each to-do row SHALL open in place to show the evidence, the explanation, the rule's recommendation verbatim as "Suggested change," the source citations with the rule id, a Copy action, and the per-finding report link. The page SHALL NOT generate or alter contract text.

#### Scenario: A quoted finding

- **WHEN** a finding pinned a span (start offset before end offset, non-empty text)
- **THEN** the row shows that text in quotation marks, with its section heading when one exists

#### Scenario: An absence finding

- **WHEN** a finding's excerpt is a placeholder at offsets 0–0, such as "(clause absent from the document)"
- **THEN** the row shows the placeholder under "Not in the document" and never in quotation marks

### Requirement: Key terms show only what the text says

The page SHALL show the abstract's parties, effective date, governing law, forum, liability cap, renewal and assignment, each with its section when known. A term with no value SHALL read "Not found in the text," never an inferred or "standard" value. Name-only signature-block entries SHALL NOT be shown as parties.

#### Scenario: An NDA with no cap

- **WHEN** the abstract has no liability cap
- **THEN** the Liability cap row reads "Not found in the text"

### Requirement: Nothing is lost, only folded

Every panel and control the result showed before this change SHALL still be reachable: the input, classification and rule-error notices at the top, and everything else in a fold. The page SHALL print with every row open.

#### Scenario: Pasted text

- **WHEN** the input is pasted text
- **THEN** the "Read as plain text" notice appears above the headline
