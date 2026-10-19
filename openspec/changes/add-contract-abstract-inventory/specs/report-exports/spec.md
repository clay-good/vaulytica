# report-exports — delta

## ADDED Requirements

### Requirement: A contract abstract is a provenance-carrying projection of extracted facts

The product SHALL produce, for one document, an abstract with the fields listed in the proposal, each non-empty value carrying the section it was read from, leaving a field blank when the extractor found nothing, and stating in its first line that it is extracted text and not a legal summary.

#### Scenario: Ordinary MSA

- **WHEN** an MSA states a three-year term from the Effective Date, automatic renewal with 60 days' notice, New York law, and a cap of 12 months' fees
- **THEN** the abstract shows those values with their section labels, and `expiry` is filled only if the register resolved the Effective Date to a calendar date

#### Scenario: Silence stays blank

- **WHEN** a document has no assignment clause
- **THEN** `assignment` is blank, not "freely assignable"

### Requirement: A folder yields an inventory with one row per file

For a folder, bundle, or `.zip`, the product SHALL write `inventory-csv` and `inventory-json` with one row per document and one `not_analyzed` row per unreadable file, sorted by title, carrying an `inventory_hash` namespaced apart from every `result_hash`, and a per-column coverage count.

#### Scenario: Forty vendor agreements

- **WHEN** a folder of 40 agreements and one corrupt file is analyzed with `--format inventory-csv`
- **THEN** the CSV has 41 data rows, the corrupt file's row says `not_analyzed` with the reason, and the coverage line shows how many rows filled each column

### Requirement: The inventory is deterministic and reaches every export surface

The same folder SHALL produce byte-identical inventory files on any machine; the formats SHALL be available in the tab, the CLI, the Action, and MCP `export_report`, and a read-only MCP `abstract_document` tool SHALL return one document's abstract.

#### Scenario: Parity

- **WHEN** the browser bundle view and `analyze <dir> --format inventory-json` run over the same files
- **THEN** the JSON bodies and `inventory_hash` are identical
