# custom-playbooks — delta

## ADDED Requirements

### Requirement: A required clause the classifier cannot detect is unevaluable, not missing

A custom playbook's `required_clauses` entry names a clause category. The engine SHALL report a
missing clause only for a category the loaded classifier can actually emit. For any other category
it SHALL record the entry as unevaluable, with a reason naming the categories that can be required.

An undetectable category is indistinguishable from an absent clause in `extracted.classified`.
Treating the two as the same thing lets the engine assert, at `critical`, that a clause is missing
from a document that contains it — a wrong answer the run records no doubt about.

#### Scenario: A compliant document is required to carry an undetectable category

- **WHEN** a playbook requires a category outside the classifier's detectable set, and the document
  contains such a clause
- **THEN** the run SHALL report no finding for it, and SHALL list it in `unevaluable` with a reason
  naming the detectable categories

#### Scenario: A genuinely missing clause in a detectable category

- **WHEN** a playbook requires a detectable category and the document has no clause of it
- **THEN** the run SHALL report the missing-clause finding at the configured severity, unchanged

#### Scenario: The detectable set is read from the loaded artifact

- **WHEN** the shipped classifier's patterns or vocab change
- **THEN** the detectable set SHALL change with them, being derived from the same two inputs the
  classifier reads — never from a list written in source

#### Scenario: A caller that does not supply the detectable set

- **WHEN** code calls the custom-playbook interpreter
- **THEN** the detectable set SHALL be a required argument, so a caller cannot reintroduce the
  false-missing finding by omission
