# report-pinning — delta

## ADDED Requirements

### Requirement: A harness is held to the product's extraction options when it matters

A test harness SHALL build its extraction inputs the way the product does when its output is
committed, when it renders a report artifact, or when it asserts on a field the option populates. A
harness that fails this proves something about itself rather than about the product.

#### Scenario: A golden pipeline omits an option the product passes

- **WHEN** a harness whose output is committed builds extraction inputs without that option
- **THEN** the harness guard SHALL fail, naming the file and the reason it is swept

#### Scenario: The committed-output gate and the extraction are in different files

- **WHEN** the regeneration gate is in a test and the extraction is in a helper it imports
- **THEN** the helper SHALL inherit the committed-output reason, so the gate's location does not
  decide what is checked

#### Scenario: A harness asserts on a field it never populates

- **WHEN** a projection compares a field the harness leaves empty on both sides
- **THEN** the comparison passes without testing anything, and a floor on real values SHALL fail
  instead

#### Scenario: A unit fixture that asserts nothing about the field

- **WHEN** a test calls the extractor only to assert on unrelated output
- **THEN** it SHALL NOT be swept, so the guard does not accumulate exceptions nobody will act on

### Requirement: One scanner answers "is this call site wired"

Every guard asking whether a call supplies an option SHALL use one shared scan. Two scanners for one
question drift, and a scanner that misses a call shape reports no problems — which reads as success.

#### Scenario: A call written in an unanticipated shape

- **WHEN** a call appears with no options object, or as a spread
- **THEN** the shared scan SHALL still see it

#### Scenario: The scanner reads its own source

- **WHEN** the swept set includes the scanner or a guard that discusses the pattern in prose
- **THEN** a string literal and a comment SHALL NOT be counted as call sites
