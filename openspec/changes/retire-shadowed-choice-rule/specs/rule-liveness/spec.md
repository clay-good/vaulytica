# rule-liveness — delta

## ADDED Requirements

### Requirement: A rule whose tests all assert silence is not a rule

A catalog rule SHALL have at least one executed case in which it produces a finding. A rule whose
every test asserts `null` SHALL be retired rather than carried, because the execution log reports
it as having RUN and found nothing — which is the product's way of telling a reader the document
was checked on that point.

#### Scenario: A rule defers to a sibling and keeps no case of its own

- **WHEN** a rule returns null whenever a named sibling fires, and its remaining condition is a
  subset of that sibling's condition
- **THEN** the rule has no reachable case and is retired, not ledgered

#### Scenario: Retiring a rule changes the analysis

- **WHEN** a rule leaves the catalog
- **THEN** `execution_log` loses an entry and every `result_hash` moves, because two runs that
  evaluated different rule sets are different analyses
- **AND** the regeneration SHALL be verified semantically — volatile fields stripped and the
  remainder compared — rather than by reading the golden diff, since the goldens are single-line
  JSON and a one-line diff per file is the signature of any stamp change

### Requirement: Shadowing is tested, not inferred

Before a rule is declared unreachable because a sibling fires first, the claim SHALL be tested
against a document constructed to distinguish them. Two rules that read the same extracted field
may still differ in how much of it they read.

#### Scenario: A sibling reads only the first entry of a repeated clause

- **WHEN** one rule inspects the first entry of a repeated clause kind and another inspects all of
  them
- **THEN** a document whose first entry is consistent and whose later entry is not distinguishes
  them, and the second rule is live
