# filing-compliance — delta

## ADDED Requirements

### Requirement: Filing rules run only under an explicitly selected court profile

The FILE rule pack SHALL evaluate only when the user has selected a court profile, and the profile's id, version, and cited authority SHALL be stamped into the hashed run; with no profile selected the pack MUST stay dormant and the report notes filing checks were not run.

#### Scenario: A brief analyzed without a profile

- **WHEN** an appellate brief matches the filing family but no `--court` profile is selected
- **THEN** no FILE finding fires and the report states filing-compliance checks require a court profile

#### Scenario: Profile provenance in the receipt

- **WHEN** a brief is analyzed with `--court frap-default`
- **THEN** the hashed run records the profile id and version, so the receipt proves which limits were applied

### Requirement: Type-volume findings are honest about what was measured

The type-volume rule SHALL compute both the total flattened-text word count and the count after subtracting every detected excludable block (per the profile's count-exclusion list, e.g. FRAP 32(f) items), MUST report a violation only when the post-exclusion lower bound exceeds the profile's limit, and MUST state that the filer's word-processing count governs for certification purposes.

#### Scenario: Clearly over the limit

- **WHEN** a principal brief's post-exclusion word count exceeds the profile's 13,000-word limit
- **THEN** FILE-001 fires with both counts, the limit, and the profile's cited authority (FRAP 32(a)(7)(B)(i))

#### Scenario: Over in total but under after exclusions

- **WHEN** the total count exceeds the limit but the post-exclusion count does not
- **THEN** no violation fires; an informational note reports both counts and the remaining margin

### Requirement: Page limits are checked only where pages are measurable

The page-limit rule SHALL evaluate only for inputs whose ingest carries a real `page_count` (PDF), and for DOCX inputs MUST report that page count is not measurable from the file rather than estimating.

#### Scenario: DOCX brief under a page-limit profile

- **WHEN** a DOCX brief is analyzed under a profile with a page limit
- **THEN** the report contains an explicit "page count unmeasurable for DOCX" note and no page-limit violation

### Requirement: Required filing blocks are presence-checked against the profile

For each block the selected profile requires (certificate of compliance, certificate of service, table of contents, table of authorities, caption, signature block), the pack SHALL report the block as found (with location) or not detected, citing the profile's authority for that block, and MUST NOT certify the filing as compliant when all blocks are found.

#### Scenario: Missing table of authorities

- **WHEN** a brief under `frap-default` contains no table-of-authorities heading
- **THEN** FILE-006 fires citing FRAP 28(a)(3)

#### Scenario: All blocks present

- **WHEN** every required block is detected
- **THEN** the report lists each as found and renders the pack's scope statement — never a compliance certification

### Requirement: Court profiles are versioned data with cited authority

Every court profile SHALL carry, for each limit and required block, the rule citation, source URL, and `retrieved_at` date, validated in CI against the profile schema; profile content changes SHALL be releases (new version), never silent edits.

#### Scenario: A profile entry without authority

- **WHEN** a profile file adds a word limit with no citation or `retrieved_at`
- **THEN** schema validation fails in CI naming the profile and field
