# proofreading — new capability

## ADDED Requirements

### Requirement: Unpaired punctuation is reported per paragraph

The engine SHALL report, as `PROOF-001`, a paragraph in which parentheses, square or curly brackets, double quotation marks, or curly single quotation marks do not balance after leading enumerators are stripped, naming the unmatched mark.

#### Scenario: Open parenthesis

- **WHEN** a paragraph reads "the Services (as defined in Exhibit A shall be performed"
- **THEN** `PROOF-001` fires naming the unmatched `(`

#### Scenario: Enumerator is not a mark

- **WHEN** a list item begins "(a) the Services"
- **THEN** `PROOF-001` does not fire for the enumerator

### Requirement: A stated weekday matches its date

The engine SHALL report, as `PROOF-002`, a date written with a weekday that does not fall on that weekday under the proleptic Gregorian calendar, and at info a date lacking a year in a document whose other dates carry years.

#### Scenario: Wrong weekday

- **WHEN** the document says "Monday, March 3, 2026"
- **THEN** `PROOF-002` fires stating that March 3, 2026 is a Tuesday

### Requirement: Repeated words, drifted party names, mismatched cross-reference titles, broken enumerations, and non-conforming standard phrases are reported

The engine SHALL report `PROOF-003` through `PROOF-007` as described in the proposal, each quoting only text the document contains and recommending nothing the tool authored.

#### Scenario: Cross-reference title

- **WHEN** the text cites "Section 7 (Confidentiality)" and the heading of Section 7 is "Indemnification"
- **THEN** `PROOF-005` fires quoting both

#### Scenario: Enumeration gap

- **WHEN** a clause enumerates "(a)", "(b)", "(d)"
- **THEN** `PROOF-006` fires naming the missing "(c)"

#### Scenario: The document's own majority form

- **WHEN** "including, without limitation" appears six times and "including without limitations" once
- **THEN** `PROOF-007` fires on the single occurrence and names the majority form as the reference

### Requirement: Clean documents stay clean

Every rule in the pack SHALL produce zero findings on each of the authored clean documents and clean deal rooms in the tree, and its corpus firing count SHALL be committed by equality.

#### Scenario: Clean-document sweep

- **WHEN** the fifteen clean documents and two clean deal rooms are analyzed
- **THEN** no `PROOF-*` finding appears
