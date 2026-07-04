# playbook-tooling — delta

## ADDED Requirements

### Requirement: Playbook diff covers the whole schema

`diff` SHALL compare every field of the playbook document, including
`negotiation_positions`, and `--exit-code` SHALL exit non-zero whenever any
field differs.

#### Scenario: Walk-away floor drift

- **WHEN** two playbooks differ only in
  `negotiation_positions[0].acceptable.value`
- **THEN** `diff --exit-code` reports the position change and exits `1`

#### Scenario: Identical playbooks

- **WHEN** two byte-identical playbooks are diffed
- **THEN** output reports no differences and the exit code is `0`

### Requirement: Diff completeness is schema-derived

The test suite SHALL derive the set of playbook top-level fields from the
schema/type definition and fail when `diff` lacks a comparator for any field,
so newly added playbook fields cannot ship uncovered.

#### Scenario: A future playbook field lands without diff support

- **WHEN** a new top-level field is added to the playbook schema without a
  diff comparator
- **THEN** the completeness test fails naming the uncovered field

### Requirement: Position changes render in attorney terms

Diff output for `negotiation_positions` SHALL name the rule/topic and describe
the change at the rung level (which floor or fallback moved, from what to
what), matching the tone of the existing section renderers.

#### Scenario: Rendering a floor move

- **WHEN** a position's acceptable floor changes 6 → 4
- **THEN** the diff names the position and states the floor moved from 6 to 4
