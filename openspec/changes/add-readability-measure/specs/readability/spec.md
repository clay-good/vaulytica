# readability — new capability

## ADDED Requirements

### Requirement: Every document carries a statutory-method Flesch score, render-side

The product SHALL compute a Flesch reading ease score using the NAIC model act's counting rules (1.015 and 84.6 factors, 206.835 constant; contractions and hyphenated words as one word; sentences ending at period, semicolon, or colon; headings and captions excluded), with word, sentence and syllable counts, the longest sentence, the exclusions applied, and the syllable counter's version, in a `readability` block that enters no hash.

#### Scenario: Determinism

- **WHEN** the same document is analyzed twice on two machines
- **THEN** the `readability` block is byte-identical and `result_hash` is unchanged from before this change

#### Scenario: Exclusions are stated

- **WHEN** a document has a table of contents and signature block
- **THEN** the block lists them as excluded from the count

### Requirement: An asserted state standard yields a cited finding, never a compliance verdict

With `--readability <state>`, the product SHALL compare the score to the state's threshold from the `readability_standards` table and report `READ-001` when below it, quoting the citation and both numbers, and `READ-002` when the standard requires a table of contents or index and the outline has none. The finding text SHALL say that sampling and statutory exclusions were not applied and that certification is the filer's.

#### Scenario: Florida policy scoring 41

- **WHEN** a policy scores 41 and `--readability fl` is asserted
- **THEN** `READ-001` fires citing Fla. Stat. § 627.4145 and its minimum of 45

#### Scenario: No assertion

- **WHEN** the same policy is analyzed without the flag
- **THEN** no `READ-*` finding fires

### Requirement: NY GOL § 5-702's captioning requirement is checked structurally

With `--readability ny-consumer`, a residential lease or consumer agreement whose outline has no captioned sections SHALL draw `READ-003` citing N.Y. Gen. Oblig. Law § 5-702(a), and the finding SHALL state that the clear-and-coherent-language requirement is not measured.

#### Scenario: Uncaptioned lease

- **WHEN** a residential lease ingests as one unheaded section with no captions
- **THEN** `READ-003` fires

### Requirement: The standards table is provenance-gated

Every row of `readability_standards` SHALL carry citation, URL, retrieved date, threshold and scope; the DKB build SHALL fail on a row missing any, and the chart compilation SHALL not be the source of record for any row.

#### Scenario: Secondary source only

- **WHEN** a row's URL points to the NAIC chart rather than the state's statute
- **THEN** the build fails naming the row
