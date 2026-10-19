# version-comparison — delta

## ADDED Requirements

### Requirement: An executed copy can be checked against its final draft

The product SHALL compare a final draft against an executed copy, set aside differences inside the execution allowance (signature-block fills, filled date blanks, initials, exhibit cover pages, scanner furniture, watermark words), report every remaining difference as a clause-level redline, and state one of three verdicts: identical outside the allowance, N differences outside the allowance, or could not determine. The verdict sentence SHALL state that it concerns text conformity only, not valid execution.

#### Scenario: Clean execution

- **WHEN** the signed PDF differs from the final DOCX only in filled signature lines, filled dates, and a "DRAFT" watermark becoming "EXECUTED"
- **THEN** the verdict is identical outside the allowance, and the set-aside list shows each filled line

#### Scenario: A number changed

- **WHEN** the signed copy's §4.2 reads "$1,250,000" where the final reads "$1,500,000"
- **THEN** the verdict is one difference outside the allowance, and the redline shows the paragraph

#### Scenario: Scan with low-confidence words

- **WHEN** the executed PDF is image-only and OCR marks three words in §9 below the confidence threshold, and §9 is the only paragraph that differs
- **THEN** the verdict is could not determine, the difference is listed as unverified with the three words, and the report names page and section to read by eye

### Requirement: A closing set is paired by title and reported as one table

Given two folders, the product SHALL pair documents by normalized title, report unpaired documents on either side, and render one table (document · verdict · differences · pages OCR'd) carrying a `conformity_hash` namespaced apart from every `result_hash`.

#### Scenario: Unpaired file

- **WHEN** the signed folder holds a document whose title matches nothing in the final folder
- **THEN** the table lists it as unpaired and the exit code is non-zero under `--fail-on-nonconformity`

### Requirement: Headless honesty about OCR

The CLI SHALL refuse an image-only executed copy in this mode with a message that the browser performs OCR and the headless path does not.

#### Scenario: Scanned PDF on the CLI

- **WHEN** `compare --executed final.docx scan.pdf` runs and the PDF has no text layer
- **THEN** the command exits 1 naming the browser as the surface that can read it
