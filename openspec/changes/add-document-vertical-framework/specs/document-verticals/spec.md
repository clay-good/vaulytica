# document-verticals — delta

## ADDED Requirements

### Requirement: Unmatched documents are reported as unmatched

When document classification resolves to the generic fallback (no playbook match at or above threshold and no v4 sub-domain at or above its calibrated floor), the engine SHALL stamp a classification notice into the hashed run stating that no known document family matched and that contract-lint rules were applied, and every report surface MUST render that notice prominently.

#### Scenario: A litigation brief is analyzed today

- **WHEN** a document that is not a contract (e.g., an appellate brief) is analyzed and falls to `generic-fallback`
- **THEN** the report carries the classification notice before any finding
- **AND** the notice is inside the hashed `EngineRun`, so the receipt permanently records that the analysis ran unmatched

#### Scenario: A matched document carries no notice

- **WHEN** a document matches a playbook at or above threshold
- **THEN** no classification notice is stamped and the report is unchanged from today

### Requirement: Vertical rule packs are gated to their document families

Every rule added outside the v1/v2 launch set SHALL declare a non-empty `applies_to_playbooks`, and a guard test MUST fail the suite naming any rule that omits it.

#### Scenario: A new pack rule without a gate

- **WHEN** a rule file is added with no `applies_to_playbooks` and it is not part of `LAUNCH_RULES`
- **THEN** the guard test fails naming the rule id

### Requirement: Adding a pack cannot change existing hashes

The suite SHALL contain a property test proving that registering an additional gated vertical pack leaves the `result_hash` of every launch golden byte-identical when the active playbook is outside the pack's gate.

#### Scenario: Synthetic pack registered against launch fixtures

- **WHEN** the property test registers a synthetic pack (fake playbook id, one gated rule) and re-runs each launch golden fixture
- **THEN** every fixture's `result_hash` equals its stored golden exactly

### Requirement: Every pack declares and renders its scope of review

Each vertical pack SHALL declare a scope-of-review statement (what the pack checks; what it does not), and every report on which the pack ran MUST render that statement, following the presence-only doctrine: the pack never issues a clean bill of health for anything it merely scanned for.

#### Scenario: A pack runs and finds nothing

- **WHEN** a vertical pack runs against a matching document and produces zero findings
- **THEN** the report renders the pack's scope statement and reports "no findings from the checks listed" — never "compliant" or "clean"

### Requirement: Rule-ID namespaces are reserved per vertical

The vertical registry documentation SHALL maintain the namespace table, and new packs MUST use their reserved prefix (FILE for filing format, CITE for citation lint, DDL for deadline computation, PROD for production QA, PNOT for privacy notices; estate deepening extends the existing EST prefix) so finding ids remain collision-free across packs.

#### Scenario: Two packs claim one prefix

- **WHEN** a rule is added whose id prefix is already reserved by a different pack in `docs/verticals.md`
- **THEN** the registry guard test fails naming both packs
