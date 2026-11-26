# report-pinning — delta

## ADDED Requirements

### Requirement: The DOCX report's content is pinned, not only its determinism

The committed artifact digests SHALL include the DOCX report. Rendering an artifact twice in one
process proves determinism and pins no content: both renders move together when the renderer
changes, so a wrong column header, a dropped table or a placeholder where a value belongs passes.

#### Scenario: A renderer's prose changes without a regeneration

- **WHEN** a column header, label or table in the DOCX report changes
- **THEN** the committed `docx_document_xml` digest SHALL no longer match, and the change SHALL
  require a deliberate regeneration

#### Scenario: The digested part comes back implausibly small

- **WHEN** the unzip returns no document part, or a normalization removes most of it
- **THEN** the digest helper SHALL throw rather than digest it, so a broken harness cannot produce
  one stable digest on every machine

#### Scenario: The library's random relationship ids

- **WHEN** the `docx` library mints a fresh `nanoid()` relationship id per hyperlink
- **THEN** that one exception SHALL be normalized in a single shared place, and every other byte of
  the document part SHALL still have to match

### Requirement: A pinned artifact is built the way the product builds it

A harness that renders an artifact whose digest is committed SHALL construct its inputs the way the
product does. A pin over inputs the product never produces enshrines something no user sees.

#### Scenario: The harness omits an extraction option the product passes

- **WHEN** a digest harness builds `extracted` without an option the product's pipelines supply
- **THEN** the pinned digest no longer describes the shipped artifact, and the omission SHALL fail
  the reach guard or move the digest

#### Scenario: The harness calls the renderer with fewer arguments than the product

- **WHEN** a digest harness invokes a report builder directly and omits arguments the product
  supplies
- **THEN** it renders a document no user receives, so the harness SHALL call the product's own
  renderer rather than reconstruct the call

#### Scenario: A parity test constructs its own reference

- **WHEN** a test compares two surfaces' output but hand-builds the reference input
- **THEN** it proves parity only with the hand-construction, and SHALL build the reference the way
  the product does

### Requirement: The reach guard covers every surface, in every call shape

A guard asserting that the product supplies an extraction option SHALL sweep every product
directory, not only the one the fix was made in, and SHALL recognize a call written without an
options object.

#### Scenario: A headless surface is left unwired

- **WHEN** a `tools/` call site omits the option while `src/` passes it
- **THEN** the guard SHALL fail and name that file

#### Scenario: A call is written with no options object at all

- **WHEN** a call site reads `extractAll(tree)` with no second argument
- **THEN** the guard SHALL treat it as unwired rather than not matching it
