# privacy-notices — delta

## ADDED Requirements

### Requirement: Notice checks run only under asserted regimes

The PNOT pack SHALL evaluate only the content items of regimes the user asserts, SHALL stamp the asserted regimes into the hashed run, and with no regime asserted MUST stay dormant with a report note that regime selection is required.

#### Scenario: CCPA and GDPR asserted together

- **WHEN** a notice is analyzed with `--regime ccpa,gdpr`
- **THEN** both regimes' item lists are evaluated and the receipt records both assertions

#### Scenario: No regime asserted

- **WHEN** a privacy notice matches the notice playbook but no regime is asserted
- **THEN** no PNOT finding fires and the report explains why

### Requirement: Every enumerated content item is a cited presence check

For each asserted regime, the pack SHALL check the presence of every enumerated content item in the regime's pinned list (each item carrying its citation and `retrieved_at`), reporting each item as found (with location) or not detected; the CCPA list MUST include the § 1798.106 correction right and the "none" statements alternative for the sold/shared and disclosed category lists.

#### Scenario: Missing correction right

- **WHEN** a notice under the `ccpa` regime describes access and deletion rights but not correction
- **THEN** the corresponding PNOT finding fires citing Cal. Civ. Code §§ 1798.130(a)(5)(A), 1798.106

#### Scenario: "None" statement satisfies the sold-categories item

- **WHEN** a notice states the business has not sold or shared personal information in the preceding 12 months
- **THEN** the sold/shared-categories item reports found via the statutory "none" alternative

### Requirement: Texas mandated wording is compared exactly

Under the `tx` regime the pack SHALL compare the notice against the exact statutory texts Tex. Bus. & Com. Code § 541.102(b)–(c) mandates (whitespace-normalized), distinguishing absent from present-but-altered and quoting the altered region.

#### Scenario: Altered mandatory sentence

- **WHEN** a notice paraphrases the § 541.102(b) sale-of-sensitive-data notice instead of reproducing it
- **THEN** the finding reports present-but-altered and quotes where the text diverges

### Requirement: Coverage is reported without a compliance verdict

The report SHALL render a per-regime coverage table (each item found / not detected) and the pack's scope statement — content presence was checked against the pinned lists; adequacy, accuracy, and the business's actual practices were not — and MUST NOT render any overall "compliant" or "non-compliant" conclusion.

#### Scenario: All items found

- **WHEN** every asserted regime item is found
- **THEN** the table shows all items found and the report still carries the scope statement, with no compliance conclusion
