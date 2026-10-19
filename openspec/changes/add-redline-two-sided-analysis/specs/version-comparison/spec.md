# version-comparison — delta

## ADDED Requirements

### Requirement: A tracked-changes DOCX can be compared against itself

The product SHALL compare the all-changes-rejected reading of a DOCX (base) against its all-changes-accepted reading (revised) using the existing comparison engine, with the revision analyzed under the base reading's document type, and render the existing comparison artifacts (finding delta, clause redline, posture movement when a ladder is supplied).

#### Scenario: One file, two readings

- **WHEN** `compare --redline nda-redline.docx` runs on a file whose tracked changes delete the liability cap and insert a unilateral amendment clause
- **THEN** the comparison reports the cap rule as introduced (the cap is gone in the accepted reading) and the dark-pattern rule as introduced, with the clause redline showing both edits

#### Scenario: No tracked changes

- **WHEN** the DOCX carries no `w:ins`, `w:del`, or move elements
- **THEN** the command exits 1 with a message that the file has no tracked changes and that two files are compared with `compare base revised`

### Requirement: The rejected reading is a faithful text projection

The rejected reading SHALL keep deleted text, drop inserted text, treat moved-from text as present and moved-to text as absent, and otherwise pass through the same structure handling as the accepted reading. The default reading SHALL remain the accepted one, and no existing `result_hash` SHALL change.

#### Scenario: Round trip

- **WHEN** a DOCX with tracked changes is read both ways and a clean DOCX of each state (produced by Word's Accept All / Reject All) is read normally
- **THEN** the rejected reading's text equals the Reject-All document's text, and the accepted reading's text equals the Accept-All document's text

### Requirement: Introduced and resolved findings name the revision author

Each introduced finding SHALL carry the sorted distinct `w:author` values of the insertions overlapping its span in the accepted reading; each resolved finding SHALL carry the authors of the deletions overlapping its span in the rejected reading. Attribution SHALL be render-side and enter no hash.

#### Scenario: Two reviewers

- **WHEN** one author's insertion adds an auto-renewal clause and another author's deletion removes the notice period
- **THEN** the introduced auto-renewal finding names the first author and the introduced short-notice finding names the second

### Requirement: The redline comparison reaches every comparison surface

The CLI `compare --redline`, the browser comparison flow, the Word comparison report, the Action's `redline` input, and the MCP `compare_documents` tool (via `redline_path`) SHALL offer it, each carrying the one-line note that the two readings' hashes are named `#rejected` and `#accepted` and differ from the plain analysis hash by name.

#### Scenario: MCP

- **WHEN** an agent calls `compare_documents` with `redline_path`
- **THEN** it receives the same drafting-loop fields (`fixed`, `introduced`, `remaining`, `no_longer_present`, `removed`) as for two paths
