# results-page — delta

## ADDED Requirements

### Requirement: Multi-document and comparison results use the same page

The bundle, version-comparison and round-comparison results SHALL each show a headline, to-do rows that open to their evidence, folded detail, and the shared Download section, and SHALL NOT download any file without a click.

#### Scenario: A deal folder

- **WHEN** an MSA and a DPA with different governing law are dropped together
- **THEN** the first row is the governing-law conflict, quoting both clauses and naming both files, followed by one row per document with its own count

#### Scenario: A revised draft

- **WHEN** a revision adds one critical finding and resolves two
- **THEN** the headline reads "The revision added 1, resolved 2, left K open," and the added row is listed first

### Requirement: One count everywhere

A document's "things to raise" count SHALL be computed by `isActionable` and SHALL be identical on its own page, its bundle row, and any comparison that includes it.

#### Scenario: Same document, three views

- **WHEN** one NDA is analyzed alone, inside a bundle, and compared against itself
- **THEN** its count is the same in all three, and the comparison against itself reports 0 added and 0 resolved
