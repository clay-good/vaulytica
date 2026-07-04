# report-exports — delta

## ADDED Requirements

### Requirement: Findings export as anchored comments in a copy of the uploaded DOCX

For a DOCX input, the product SHALL offer an export that is a copy of the uploaded container with each finding attached as a Word comment anchored at the finding's excerpt location, carrying the rule id, severity, explanation, citation, and recommendation.

#### Scenario: Reviewing findings inside Word

- **WHEN** an attorney analyzes an uploaded DOCX and downloads the reviewed copy
- **THEN** opening it in Word shows their own document with a comment on each flagged clause naming the rule and recommendation

#### Scenario: Unanchorable finding

- **WHEN** a finding's excerpt cannot be located in the container
- **THEN** it appears in a single aggregate comment anchored at the document start, and the total across anchored plus aggregated equals the report's finding count

### Requirement: The annotated copy never alters the document body

The exported copy's body text SHALL be identical to the uploaded document's; the export MUST NOT write any tracked-change (`w:ins`/`w:del`) element or modify, insert, or reorder any text content.

#### Scenario: Byte-level body parity

- **WHEN** the annotated copy is unzipped alongside the original
- **THEN** every part is byte-identical except the comment part, anchor markup, relationships, and content types, and the body text content matches the original exactly

### Requirement: The annotated export is deterministic

Producing the annotated copy twice from the same inputs SHALL yield byte-identical files, with no wall-clock timestamps in the written parts.

#### Scenario: Repeat export

- **WHEN** the same document and engine version produce the export twice
- **THEN** the two files' bytes are identical
