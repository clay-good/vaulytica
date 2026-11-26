# jurisdiction-resolution — delta

## ADDED Requirements

### Requirement: The product populates `jurisdiction_id`

Every pipeline that extracts jurisdictions SHALL supply a jurisdiction lookup, so a
`JurisdictionReference` naming a jurisdiction the resolver knows carries a normalized id. An
optional extractor parameter that no caller supplies is not a feature; it is a field that reads as
"unknown" for every document the product has ever processed.

#### Scenario: A document names a US state as its governing law

- **WHEN** the product pipeline analyzes a document whose governing-law clause names a US state
- **THEN** the extracted governing-law reference SHALL carry a `us-XX` `jurisdiction_id`

#### Scenario: The lookup is removed from a pipeline call site

- **WHEN** an `extractAll` call in the product stops passing the lookup
- **THEN** a reach guard SHALL fail, naming the surface whose ids went empty

#### Scenario: A jurisdiction outside the resolver's coverage

- **WHEN** the clause names a jurisdiction the resolver does not cover, or states a formula instead
  of a jurisdiction
- **THEN** `jurisdiction_id` SHALL be absent rather than guessed, and the consumer SHALL fall back
  to the raw text

### Requirement: One resolver, not one per consumer

A single normalization SHALL own raw jurisdiction text to `us-XX` id. A consumer that needs the id
SHALL read the extracted field or call the shared resolver, and SHALL NOT carry its own copy of the
jurisdiction-name map.

#### Scenario: A second copy of the state map is introduced

- **WHEN** a module declares its own raw-text-to-`us-XX` mapping
- **THEN** the guard SHALL fail, because a field that is empty at runtime is what causes consumers
  to re-implement the resolver

### Requirement: Consumers that accept a DKB id actually accept one

A surface documented as accepting a DKB jurisdiction id SHALL match on that id against real
extracted output, not only against raw text.

#### Scenario: A custom playbook allows a jurisdiction by DKB id

- **WHEN** a `governing_law_in` condition lists `allowed: ["us-de"]`
- **AND** the document's governing law is Delaware
- **THEN** the condition SHALL evaluate compliant

#### Scenario: A report prints the jurisdiction id column

- **WHEN** the DOCX report renders the jurisdiction table for a document naming a US state
- **THEN** the id column SHALL show the resolved id rather than a placeholder dash
