# mandated-text — new capability

## ADDED Requirements

### Requirement: Mandated passages are held in a provenance-gated DKB table

The DKB SHALL carry a `mandated_texts` table whose every row has the exact text, the authority, `source_url`, `retrieved_at`, the text's version date, optional superseded texts with date ranges, applicability (families or assertion gates), and an optional form requirement. The DKB build SHALL fail on a row lacking any provenance field.

#### Scenario: Build gate

- **WHEN** a row is added without `retrieved_at`
- **THEN** `dkb:build` exits non-zero naming the row

### Requirement: A passage that reproduces a mandated text inexactly is reported with a redline

For each applicable row, the engine SHALL locate the best-matching window in the document; when it matches above the similarity threshold but is not an exact whitespace-normalized match, a `TEXT-*` finding SHALL show a word-level redline of the document's text against the mandated text and cite the authority. An exact match SHALL produce no finding.

#### Scenario: Paraphrased Holder Rule notice

- **WHEN** a retail installment contract's notice reads "Any holder of this contract is subject to all claims and defenses the debtor could assert against the seller" and omits the recovery-cap sentence
- **THEN** the finding shows the omitted sentence as deleted in the redline, cites 16 C.F.R. § 433.2(a), and is severity warning

#### Scenario: Exact text

- **WHEN** the notice reproduces § 433.2(a) exactly
- **THEN** no `TEXT-*` finding fires for that row

### Requirement: A superseded version of a mandated text is named as such

When the document's passage matches a superseded text more closely than the current text, the finding SHALL say which version it matches, the amendment that changed it, and its effective date.

#### Scenario: Pre-2019 § 1542

- **WHEN** a 2026 settlement agreement quotes "A general release does not extend to claims which the creditor does not know or suspect to exist in his or her favor … must have materially affected his or her settlement with the debtor"
- **THEN** the finding says the quotation matches the text in force before January 1, 2019 (SB 1431, Stats. 2018, ch. 157) and shows the redline to the current text

### Requirement: A form requirement is checked only where the carrier exposes it

Where a row requires bold, capitals, or a minimum point size, the engine SHALL check the located passage's run properties in a DOCX (and font size in a PDF text layer), report "form not met" when the requirement is not satisfied, and report "form not checked" with the reason for pasted text or where the properties are absent. It SHALL never state that the document is unenforceable.

#### Scenario: Holder notice in regular 9-point type

- **WHEN** the DOCX passage is matched exactly but its runs are not bold and are 9 points
- **THEN** `TEXT-FORM-*` fires naming both shortfalls and quoting the "ten point, bold face, type" requirement

#### Scenario: Pasted text

- **WHEN** the same passage arrives as pasted text
- **THEN** the finding is "form not checked: pasted text carries no formatting"

### Requirement: Conspicuousness of disclaimers is reported, not judged

For a located warranty disclaimer or limitation of liability in a DOCX whose runs are neither capitals nor bold, the engine SHALL report that the clause is not set conspicuously by the U.C.C. § 1-201(b)(10) markers, cite it, and leave the legal effect unstated.

#### Scenario: Mixed-case disclaimer

- **WHEN** a sale-of-goods agreement's warranty disclaimer is in ordinary type
- **THEN** an info finding reports it with the citation and the sentence that conspicuousness is a question for the court
