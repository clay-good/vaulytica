# redaction-integrity — new capability

## ADDED Requirements

### Requirement: A liftable PDF redaction is reported without reproducing what it hides

The delivery scan SHALL report, as `HANDOFF-006`, every filled single-color rectangle (content-stream path or `Square`/`Redact` annotation) painted after, and overlapping by more than half, one or more text items on the same page. The finding SHALL carry the page number, the rectangle's box, the number of covered text items, and a masked shape of the covered text (letters as `x`, digits as `#`). No serialized form of the finding, in any export, SHALL contain the covered text.

#### Scenario: Black box over the text layer

- **WHEN** a PDF page draws an opaque black rectangle over the sentence containing an account number after that sentence's glyphs were painted
- **THEN** `HANDOFF-006` fires once for that rectangle, names the page, and shows a masked shape such as `xxxxxxx ######### xxxx`, and a grep of every export for the account number finds nothing

#### Scenario: A background panel is not a redaction

- **WHEN** a PDF paints a shaded rectangle and then paints a heading on top of it
- **THEN** `HANDOFF-006` does not fire, because the rectangle precedes the text in paint order

#### Scenario: Redaction marked but not applied

- **WHEN** a PDF carries a `/Redact` annotation and the text under it is still present
- **THEN** `HANDOFF-006` fires and its message says the redaction was marked but not applied

### Requirement: A visual-only Word redaction is reported

The delivery scan SHALL report, as `HANDOFF-007`, every DOCX run whose font color equals its highlight color or its run or paragraph shading fill, or whose font color is white with no shading. The finding SHALL carry the location and a masked length, never the text.

#### Scenario: Black highlight on black text

- **WHEN** a DOCX run carries `w:highlight w:val="black"` and default (auto) font color
- **THEN** `HANDOFF-007` fires for that run with a masked length

#### Scenario: Theme color that cannot be resolved

- **WHEN** a run's color is a theme color and the package has no `theme1.xml`
- **THEN** the scan reports that run as not inspectable for this check, with the reason, and issues no finding

### Requirement: A declared omission in an SEC exhibit has its first-page statement

When a document is an SEC-exhibit family or `--sec-exhibit` is asserted, and its text carries omission markers (`[***]`, `[REDACTED]`, `[OMITTED]`, or a line of asterisks), the scan SHALL report, as `HANDOFF-008`, when the first page lacks a statement containing the elements Item 601(b)(10)(iv) requires: that information was omitted or excluded, that it is not material, and that it is information the registrant treats as private or confidential (or, on older exhibits, that disclosure would cause competitive harm). The finding SHALL list which elements were found and SHALL NOT characterize whether the omission was proper.

#### Scenario: Markers without a legend

- **WHEN** an exhibit contains `[***]` twelve times and its first page has no omission statement
- **THEN** `HANDOFF-008` fires once, cites 17 C.F.R. § 229.601(b)(10)(iv), and says the statement was not found

#### Scenario: Complete legend

- **WHEN** the first page states that certain identified information has been excluded because it is both not material and is the type that the registrant treats as private or confidential
- **THEN** `HANDOFF-008` does not fire

### Requirement: The scan never issues a clean bill and says what it could not read

A document with no text layer, an image-only redaction, a page whose operator list exceeded the walk bound, or a container the reader could not parse SHALL be reported as not inspectable for these checks with a reason. The summary line for a document with no redaction findings SHALL say that no liftable redaction of the scanned shapes was found, and SHALL NOT say that redactions are safe or complete.

#### Scenario: Scanned PDF

- **WHEN** a PDF has no text layer
- **THEN** the delivery report says redaction checks could not be run because there is no text layer, and no `HANDOFF-006` finding appears

### Requirement: The new facts enter `delivery_hash` and nothing else

`RedactionFact[]` SHALL be part of `ContainerFacts` and covered by `delivery_hash`. A document with no redaction facts SHALL produce a byte-identical delivery report and an unchanged `result_hash`.

#### Scenario: Existing goldens

- **WHEN** the full specimen corpus and every existing delivery fixture is re-run
- **THEN** no existing golden changes except those fixtures added for this change

### Requirement: Every surface that carries the delivery scan carries these checks

The tab's "Clean to send?" card, the CLI `--delivery` summary and `--fail-on-delivery` gate, JSON `delivery`, the DOCX and HTML sections, SARIF container results, and the bundle per-document card SHALL carry `HANDOFF-006…008` with the same masking; MCP `analyze_document` SHALL gain `include: ["delivery"]` and carry them too.

#### Scenario: Reach test

- **WHEN** a new delivery reach test (modeled on `export-reach.test.ts`) enumerates the surfaces
- **THEN** each renders a fixture's `HANDOFF-006` finding, and the masking grep passes on every rendered artifact
