# playbooks — delta

## ADDED Requirements

### Requirement: Positions support multi-rung ladders above a stable floor

A custom playbook SHALL allow ordered intermediate rungs, each defined by a predicate, between `ideal` and `acceptable`; the posture evaluation MUST continue to treat `acceptable` as the only floor, with `below-acceptable` the only sub-floor state.

#### Scenario: Three-rung cap position

- **WHEN** a position defines ideal (2× fees), an intermediate rung (1.5× fees), and acceptable (1× fees), and the draft meets 1.5×
- **THEN** the posture reports the intermediate rung as met
- **AND** the dimension's floor standing, `weakest_tier`, and every coherence command's output semantics are unchanged from a two-rung playbook at-or-above floor

### Requirement: One playbook expresses both party roles

A custom playbook MAY declare party roles with per-position variants; the evaluation SHALL use the variant for the role selected at run time and MUST fail validation-loudly when role-variant positions run without a selected role.

#### Scenario: Vendor and customer from one file

- **WHEN** the same playbook runs with role `vendor` and again with role `customer` on the same draft
- **THEN** each run evaluates that role's variant positions and stamps the selected role in the posture block

#### Scenario: Missing role selection

- **WHEN** a playbook with role variants runs without a role
- **THEN** the run fails with a validation error naming the positions that require a role

### Requirement: Thresholds vary by deal size deterministically

A named threshold MAY carry deal-size bands; the evaluation SHALL resolve the band from the document's extracted contract value or an explicit override, stamp the resolved band and its source into the report, and use the declared default band when no value is resolvable.

#### Scenario: Big-deal indemnity floor

- **WHEN** a threshold declares bands at `< $1,000,000` and `>= $1,000,000` and the document's extracted value is $2,500,000
- **THEN** the higher band's threshold applies and the posture block records the band and that it came from the extracted value

### Requirement: Reports quote the team's own approved fallback language

A position MAY carry team-authored approved language; when the dimension sits below floor, reports SHALL quote that language attributed to the playbook, and the product MUST NOT generate or modify contract language of its own.

#### Scenario: Below-floor cap with approved language

- **WHEN** the cap dimension is below floor and the playbook carries approved cap language
- **THEN** the negotiation sheet shows the team's language labeled as from their playbook, verbatim
