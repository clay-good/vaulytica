# report-exports — delta

## ADDED Requirements

### Requirement: Every report can produce a verification certificate

The product SHALL generate, on request, a one-page certificate (DOCX/PDF with a JSON companion) stating the engine version, DKB version, input SHA-256, `result_hash`, the deterministic no-generative-AI no-server nature of the analysis, and the exact command that reproduces the result.

#### Scenario: Attaching provenance to a filing

- **WHEN** an attorney generates a report and requests the certificate
- **THEN** they receive a one-page document identifying the tool, versions, input hash, result hash, and reproduction command, suitable for a client file or a court's AI-use certification

#### Scenario: Certificate scope stays honest

- **WHEN** the certificate is rendered in any format
- **THEN** its claims are limited to what this tool did for this input, it carries the standard disclaimer, and it states the attorney remains responsible for independent verification

### Requirement: The certificate is tamper-evident and reproducible

The certificate's JSON companion SHALL carry a `certificate_hash`, namespaced apart from all existing hashes, computed over the canonical certificate model, and the same report and input MUST reproduce a byte-identical certificate.

#### Scenario: Re-deriving a certificate

- **WHEN** the same report JSON and input file produce the certificate twice
- **THEN** both outputs are byte-identical and carry the same `certificate_hash`

#### Scenario: Edited certificate JSON

- **WHEN** any field of a saved certificate JSON is altered and it is re-verified
- **THEN** verification fails with a hash mismatch naming the certificate
