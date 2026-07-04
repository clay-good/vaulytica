# legal-authority — delta

## ADDED Requirements

### Requirement: Cited authority reflects its real current status

Every rule explanation and DKB node that cites a statute, regulation, or case SHALL state that authority's operative status accurately as of the DKB's build date, and MUST NOT describe vacated or never-effective authority as pending, current, or operative.

#### Scenario: The vacated FTC non-compete rule

- **WHEN** a non-compete finding fires and its explanation references 16 C.F.R. Part 910
- **THEN** the text states the rule was set aside in *Ryan LLC v. FTC* and never took effect, and rests the enforceability point on state law

### Requirement: State-law overlays reflect enacted statutes as of the DKB build

The non-compete state overlay SHALL reflect statutes enacted and effective as of the DKB build date, and each overlay node MUST carry the `retrieved_at` date of its source.

#### Scenario: Wyoming after SF 107

- **WHEN** the overlay is consulted for a Wyoming-governed agreement in a DKB built after 2025-07-01
- **THEN** the overlay reflects SF 107 (non-competes void except the trade-secret, sale-of-business, and executive carve-outs), not pre-2025 law

#### Scenario: Florida after the CHOICE Act

- **WHEN** the overlay is consulted for a Florida-governed agreement in a DKB built after July 2025
- **THEN** the overlay reflects the CHOICE Act's expanded enforceability for covered high earners rather than describing Florida under pre-2025 law

### Requirement: Numeric rules never assume a missing unit against the drafter

A rule that compares a document-stated rate or amount against a legal threshold SHALL NOT infer a missing unit or period; when the unit is unstated the rule MUST either stay silent on the threshold or emit a clarification-level finding, never the threshold-violation finding.

#### Scenario: One-time flat late fee

- **WHEN** a contract states "a late fee of 5% of the overdue amount" with no period
- **THEN** no usury finding fires
- **AND** at most an info-level finding notes the fee's period/basis is unstated

#### Scenario: Explicit periodic rate

- **WHEN** a contract states "2% per month on past-due amounts"
- **THEN** the annualized comparison (24%/year) runs as today

### Requirement: Citation currency is tracked and surfaced

Every DKB statute node SHALL carry a `retrieved_at` date; a finding citing a node older than the configured currency horizon SHALL carry a visible "verify currency" label with the retrieval date, and CI MUST fail on unacknowledged nodes beyond the horizon.

#### Scenario: An 18-month-old statute node

- **WHEN** a finding cites a node retrieved 18 months ago under a 12-month horizon
- **THEN** the rendered finding carries "verify currency (retrieved 2025-01-07)" in every export format

#### Scenario: Unacknowledged staleness in CI

- **WHEN** the staleness gate runs and a statute node exceeds the horizon with no acknowledgment entry
- **THEN** the gate exits non-zero naming the node and its retrieval date

### Requirement: Marketing claims match measured scope

Public copy (README, site) SHALL describe the state-overlay coverage by its actual topics and MUST distinguish findings backed by pinned legal authority from findings backed by drafting-practice rationale.

#### Scenario: Reading the state-overlay claim

- **WHEN** a visitor reads the overlay feature description
- **THEN** it names the covered topics (non-compete enforceability, residential security deposits, usury caps) rather than implying general state-law coverage
