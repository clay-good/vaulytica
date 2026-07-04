# estate-planning — delta

## ADDED Requirements

### Requirement: The deepening pack is dormant until explicitly asserted

Because the `last-will-and-testament` and `revocable-living-trust` playbooks
(and 60 EST rules) already ship, every rule this pack adds (EST-1xx/2xx/3xx)
SHALL run only when the user explicitly asserts the pack — a `--state` value
or the `--estate-checks` flag (tab toggle in the browser). With no assertion,
analysis of an existing will or trust document SHALL produce a byte-identical
`result_hash` to today's, and a regression test MUST pin this on a shipped
golden.

#### Scenario: Existing will document, no assertion

- **WHEN** a will that analyzes today under `last-will-and-testament` is
  re-analyzed after the pack lands, with no `--state` or `--estate-checks`
- **THEN** the report's `result_hash` is byte-identical to the pre-pack hash

#### Scenario: Pack asserted without a state

- **WHEN** a will is analyzed with `--estate-checks` and no `--state`
- **THEN** the jurisdiction-neutral recital, arithmetic, and presence rules
  run; overlay-specific findings do not fire

### Requirement: Execution-formality checks report recitals, never validity

The will-instrument rules SHALL check for the presence and internal consistency of execution recitals (attestation clause, witness signature blocks matching the recited count, self-proving affidavit, notary block, testator signature block) and MUST word every finding as an observation about the document's recitals — never as a determination that the instrument is or is not validly executed.

#### Scenario: Attestation recites two witnesses but one block exists

- **WHEN** a will's attestation clause recites two witnesses and the document contains one witness signature block
- **THEN** a finding reports the mismatch between the recital and the blocks

#### Scenario: Clean will

- **WHEN** all recital checks pass
- **THEN** the report renders the pack's scope statement ("recitals and consistency checked; valid execution not determined") and no clean-bill language

### Requirement: State overlays encode verified formalities, not folk rules

The state-formalities overlay SHALL carry per-state data with citations and `retrieved_at`, seeded with the verified corrections — Pennsylvania's zero-witness ordinary signed will (20 Pa. C.S. § 2502), Louisiana's notarial testament (two witnesses plus notary, La. Civ. Code arts. 1576–1577), the Colorado / North Dakota notarization alternative (C.R.S. § 15-11-502(1)(c)(II); N.D.C.C. § 30.1-08-02) — and MUST NOT assert any state requires more than two attesting witnesses; with the pack asserted but no state selected, only jurisdiction-neutral recital checks run.

#### Scenario: Pennsylvania will without witness blocks

- **WHEN** a signed will is analyzed with `--state pa` and no witness blocks are present
- **THEN** the finding is informational, citing 20 Pa. C.S. § 2502's ordinary-signed-will path, not a warning that witnesses are missing

#### Scenario: Pack asserted, no state selected

- **WHEN** a will is analyzed with `--estate-checks` but no state selection
- **THEN** overlay-specific findings do not fire and the report notes formalities vary by state

### Requirement: Residuary shares are arithmetically reconciled

The pack SHALL extract numeric shares (percentages and word fractions) from residuary and beneficiary clauses, compute the total per disposition, and warn when shares sum to more or less than 100%, citing UPC § 2-604(b) and § 2-101(a) for the intestacy consequence of unallocated residue; non-numeric share language (e.g., "in equal shares") MUST NOT fire the rule.

#### Scenario: Shares totaling 105%

- **WHEN** a residuary clause allocates 50%, 30%, and 25% to three beneficiaries
- **THEN** the finding lists each beneficiary and share and reports the 105% total

#### Scenario: Shares totaling 90%

- **WHEN** allocations total 90%
- **THEN** the finding reports the 10% unallocated remainder and cites the intestacy consequence

### Requirement: Fiduciary and contingency provisions are presence-checked

The pack SHALL report whether the instrument names an executor or trustee, a successor fiduciary, a guardian when the document references minor children, and a survivorship or simultaneous-death provision — as presence observations under the presence-only doctrine.

#### Scenario: Minor children referenced, no guardian nominated

- **WHEN** a will references the testator's minor children and contains no guardian nomination
- **THEN** a finding reports the absence as a drafting consideration
