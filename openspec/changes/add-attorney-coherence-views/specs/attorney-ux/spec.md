# attorney-ux — delta

## ADDED Requirements

### Requirement: One command answers the three attorney posture questions

The CLI SHALL provide a `posture-review` command that, given a round archive, renders three sections in deal language — position drift since prior rounds, the per-front-per-round exposure map with the blackout verdict, and the currently weakest front — by composing the existing report modules without recomputation.

#### Scenario: Reviewing a three-round negotiation

- **WHEN** `vaulytica posture-review r1.coherence.json r2.coherence.json r3.coherence.json` runs
- **THEN** the output presents Position drift, Exposure map, and Weakest front sections in plain deal language, each naming the underlying command for drill-down

#### Scenario: Machine output

- **WHEN** the command runs with `--format json`
- **THEN** stdout is a single JSON document nesting the three composed reports under `posture_review` with a namespaced hash

### Requirement: Composed views agree with their source commands

Each `posture-review` section SHALL be byte-consistent with the standalone command it composes for the same inputs, and the command MUST apply the same verification, cross-ladder refusal, and gate exit-code semantics as its siblings.

#### Scenario: No composition drift

- **WHEN** the same archive is run through `posture-review` and through the standalone matrix command
- **THEN** the matrix content in both outputs is identical, and `--fail-on-blackout-round` exits 2 in both or neither

### Requirement: User-facing copy speaks in attorney terms

Site, README, and in-tab copy for the posture features SHALL phrase capabilities as the questions they answer (position slippage, exposure across rounds, weakest front, document consistency) rather than internal vocabulary (volatility, relapse, tenure, settling).

#### Scenario: Reading the posture feature on the site

- **WHEN** a visitor reads the posture section of the site
- **THEN** every capability is described by the attorney question it answers, with no internal metric names in the copy
