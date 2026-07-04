# determinism-hardening — delta

## ADDED Requirements

### Requirement: Canonical hashing never silently drops data

`stableStringify` SHALL serialize every reachable value of an acyclic input exactly once per occurrence, including repeated references to the same object, and MUST throw on a genuinely cyclic input rather than emit a truncated serialization.

#### Scenario: Shared sub-object in a hash input

- **WHEN** a hash input references the same object from two fields
- **THEN** both occurrences serialize fully and the fingerprint covers both

#### Scenario: Accidental cycle

- **WHEN** a hash input contains a reference cycle
- **THEN** `stableStringify` throws an error naming the key path, and no hash is produced

### Requirement: Decompression is bounded by produced bytes, not declared bytes

Archive extraction SHALL enforce a hard ceiling on bytes actually produced by inflation, per entry and cumulatively, aborting on breach regardless of the sizes declared in the archive's headers.

#### Scenario: Header under-declares the uncompressed size

- **WHEN** a crafted zip declares a small `originalSize` but its deflate stream expands past the produced-bytes ceiling
- **THEN** extraction aborts with the archive-too-large error at the ceiling, and no further bytes are inflated
