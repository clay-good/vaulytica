# filing-compliance — delta (citation lint)

## ADDED Requirements

### Requirement: Citations are parsed against a pinned public-domain grammar

The engine SHALL extract citations (full, `id.`, `supra`, short forms) deterministically against a DKB-pinned grammar derived from The Indigo Book, with every grammar node carrying its source and `retrieved_at`; the product MUST NOT describe the grammar using the "Bluebook" name.

#### Scenario: A well-formed case citation

- **WHEN** the body contains `Ryan LLC v. FTC, 746 F. Supp. 3d 369 (N.D. Tex. 2024)`
- **THEN** the extractor records one full case citation with volume, reporter, page, court, year, and position

#### Scenario: Unknown reporter abbreviation

- **WHEN** a citation uses a reporter abbreviation absent from the pinned grammar
- **THEN** CITE-001 fires naming the abbreviation and quoting the citation — phrased as "not in the pinned reporter table", never as "invalid"

### Requirement: Dangling short-form citations are flagged

The pack SHALL flag an `id.` with no preceding citation in scope and a `supra` or case short form whose full citation appears nowhere earlier in the document.

#### Scenario: Orphaned id.

- **WHEN** a section's first citation is `Id. at 12`
- **THEN** CITE-002 fires at that position

#### Scenario: Dangling supra

- **WHEN** the body contains `Smith, supra note 4` and no prior full citation of Smith exists
- **THEN** CITE-003 fires naming `Smith`

### Requirement: The table of authorities reconciles with the body both ways

When a table of authorities is present, the pack SHALL reconcile it against body citations in both directions — authorities cited in the body but missing from the table, and table entries never cited in the body — citing the active profile's table-of-authorities rule; reconciliation is by authority identity, and the report MUST state that page-reference accuracy was not checked.

#### Scenario: Authority missing from the table

- **WHEN** the body cites a case that appears nowhere in the table of authorities
- **THEN** CITE-004 fires listing the case under "cited but not in table", citing FRAP 28(a)(3) under the FRAP profile

#### Scenario: Table entry never cited

- **WHEN** the table lists an authority the body never cites
- **THEN** CITE-004 fires listing it under "in table but never cited"

### Requirement: The pack never claims to validate authorities

Every report on which the citation pack ran SHALL state that citation formats and internal consistency were mechanically checked and that the existence, accuracy, and current validity of cited authorities were NOT checked; the pack MUST NOT emit any finding or absence-of-findings phrased as confirmation that an authority is real or good law.

#### Scenario: A clean citation report

- **WHEN** the pack runs and finds zero defects
- **THEN** the report renders the scope statement and reports "no format or consistency defects from the checks listed" — never "citations verified"
