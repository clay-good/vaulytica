# ingest-fidelity — delta

## ADDED Requirements

### Requirement: No ingest path discards document content

Every ingest path (DOCX, PDF, paste, bundle members) SHALL preserve all
extracted paragraph text into the flattened document tree that rules scan. A
synthetic root section MAY be dropped only when it contains no paragraphs.

#### Scenario: Contract with a plain-text preamble before the first heading

- **WHEN** a DOCX whose title, parties, and recitals are plain (non-heading)
  paragraphs followed by a styled Heading-1 is analyzed
- **THEN** the preamble paragraphs appear in the flattened tree, are scanned by
  every applicable rule, and count toward `word_count`

#### Scenario: PDF with pre-heading body text

- **WHEN** a PDF whose first detected heading is preceded by body-size text is
  analyzed
- **THEN** the pre-heading text survives into the tree identically to the DOCX
  behavior

#### Scenario: Document with an empty synthetic root

- **WHEN** a document opens directly with a styled heading (the root section
  holds zero paragraphs)
- **THEN** the empty root is dropped and the section tree is unchanged from
  today's behavior

### Requirement: Cross-path ingest parity is pinned

The test suite SHALL feed one preamble-bearing document through the DOCX, PDF,
and paste ingest paths and assert the full text survives each, so the paths
cannot silently diverge on content retention.

#### Scenario: A future ingest refactor drops content again

- **WHEN** any ingest path produces a flattened tree missing extracted
  paragraph text present in the source
- **THEN** the ingest-fidelity test fails naming the path and the lost text

### Requirement: Text conservation under restructuring

Section-tree post-processing (root dropping, heading promotion, numbered-heading
detection) SHALL never reduce the total extracted character count of paragraph
text.

#### Scenario: Property test over generated documents

- **WHEN** the property suite generates documents with random mixes of
  pre-heading content, promoted headings, and numbered headings
- **THEN** the character count of paragraph text before and after
  restructuring is identical in every case
