# report-exports — delta

## ADDED Requirements

### Requirement: A dedicated definitions report enumerates the document's defined-term health

The product SHALL produce a definitions report listing, with locations: terms used but never defined; terms defined (with definition site); terms defined but never used; terms defined more than once; and terms used before their definition — ordered with undefined-but-used first.

#### Scenario: Working the definitions list

- **WHEN** an attorney opens the definitions report for a contract that uses "Net Revenue" without defining it and defines "Confidential Information" twice
- **THEN** "Net Revenue" appears first under used-but-undefined with each use location, and "Confidential Information" appears under duplicates with both definition locations

#### Scenario: Bundle-wide term drift

- **WHEN** a bundle defines a term one way in the MSA and differently in the SOW
- **THEN** the definitions report marks the term as redefined across documents, naming both documents and locations

### Requirement: The definitions report is deterministic and hash-fingerprinted

The definitions report SHALL be a pure projection of extracted facts, carry a `definitions_hash` namespaced apart from all existing hashes, and reproduce byte-identically for the same inputs.

#### Scenario: Repeat generation

- **WHEN** the same document produces the definitions report twice
- **THEN** the outputs are byte-identical with equal `definitions_hash`
