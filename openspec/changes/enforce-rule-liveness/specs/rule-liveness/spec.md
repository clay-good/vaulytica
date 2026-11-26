# rule-liveness — delta

## ADDED Requirements

### Requirement: Every shipped rule carries executed evidence that it can fire

The catalog SHALL contain no rule without runtime evidence that some input makes it emit a
finding. Evidence is produced by executing the rule, never by inspecting its source: a pattern
that looks reachable is not evidence, because the defect being guarded is precisely a rule whose
pattern reads correctly and matches nothing a real document contains.

Evidence is satisfied in either of two ways, and a rule satisfying neither SHALL fail the build.

#### Scenario: A rule fires on the specimen corpus

- **WHEN** the liveness sweep runs a rule against the committed specimens
- **AND** the rule emits a finding on at least one of them
- **THEN** the rule is live and requires no registry entry

#### Scenario: A rule needs a context the corpus cannot carry

- **WHEN** a rule fires only under an asserted gate, an opt-in pack option, or document
  formatting a plain-text specimen cannot express
- **THEN** a fixture registry entry SHALL supply a `RuleContext` for that rule
- **AND** the guard SHALL execute the rule against that context and assert it emits a finding

#### Scenario: A new rule is added with no firing evidence

- **WHEN** a rule is added to any catalog registry
- **AND** it neither fires on a specimen nor has a fixture registry entry
- **THEN** the liveness ratchet fails, naming the rule

### Requirement: The evidence registry cannot drift from the rules it describes

The registry SHALL be self-cleaning: it records executable contexts, not asserted reasons, so an
entry cannot remain valid once it stops demonstrating what it claims.

#### Scenario: An entry stops making its rule fire

- **WHEN** a registry entry's context no longer produces a finding for its rule
- **THEN** the ratchet fails for that entry, rather than treating the entry as an exemption

#### Scenario: An entry names a rule that is not in the catalog

- **WHEN** the registry names a rule id absent from every catalog registry
- **THEN** the ratchet fails, so a renamed or retired rule cannot leave a stale entry behind

#### Scenario: The registry is empty or unreached

- **WHEN** the registry contains no entries, or the sweep reads no specimens or no rules
- **THEN** the ratchet fails rather than passing vacuously

### Requirement: The catalog the ratchet reads is the catalog the product ships

The ratchet SHALL assemble its rule universe from the shipped registries, including the opt-in
packs, and SHALL fail when the assembled count drifts from the pinned expectation, so a new
registry cannot be added to the product and stay outside the guard.

#### Scenario: A new rule pack ships outside the swept universe

- **WHEN** a new rule registry is wired into the product but not into the ratchet's universe
- **THEN** the pinned catalog count no longer matches and the ratchet fails

### Requirement: Rules without evidence are ledgered, and the ledger can only shrink

A rule that has no firing evidence SHALL be recorded in a known-silent ledger that is asserted in
both directions: the set of rules with no evidence must EQUAL the ledger. The ledger carries ids
only — no reason field — because a recorded reason is what lets an entry outlive its truth.

#### Scenario: A ledgered rule starts firing

- **WHEN** a rule on the ledger fires on a specimen or a defect fixture
- **THEN** the ratchet fails until its ledger entry is deleted, so the ledger shrinks by default

#### Scenario: A rule goes silent

- **WHEN** a rule that was live stops firing on every committed input
- **THEN** the ratchet fails, because it is not on the ledger — growth cannot happen silently

#### Scenario: A ledgered rule is retired or renamed

- **WHEN** the ledger names an id absent from every catalog registry
- **THEN** the ratchet fails, so a stale entry cannot be left behind
