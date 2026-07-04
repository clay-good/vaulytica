# legal-authority — delta

## ADDED Requirements

### Requirement: Attorney review status is recorded in a validated ledger

The repo SHALL maintain a machine-validated ledger of attorney rule reviews in which each entry records the rule id, reviewer identity and bar jurisdiction, review date, and a tier from the fixed vocabulary (`established`, `prevailing-practice`, `opinion`); CI MUST reject entries referencing unknown rules or unknown tiers.

#### Scenario: Signing a rule

- **WHEN** a licensed reviewer adds a ledger entry for `RISK-001` with tier `established`
- **THEN** CI validates the entry and subsequent reports render the tier badge on `RISK-001` findings

#### Scenario: Invalid entry

- **WHEN** a ledger entry references a rule id that does not exist
- **THEN** the validation test fails naming the entry

### Requirement: Reports state review coverage honestly

Every report SHALL display, for its own findings, how many cite attorney-reviewed rules out of the total, and MUST NOT render any review badge for an unsigned rule.

#### Scenario: Mostly-unreviewed report

- **WHEN** a report contains 12 findings of which 2 cite signed rules
- **THEN** the report states "2 of 12 findings cite attorney-reviewed rules" and only those 2 carry tier badges

### Requirement: Every report carries a scope-of-review statement

Every report SHALL include a fixed, versioned scope statement enumerating what the analysis covered (clause completeness, the listed red-flag checks) and what it did not (commercial adequacy, tax, local counsel matters), adjacent to the standing disclaimer.

#### Scenario: Limited-scope framing

- **WHEN** any report is exported in any format
- **THEN** the scope-of-review statement appears with the disclaimer block
