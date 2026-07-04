# privacy-posture — delta

## ADDED Requirements

### Requirement: Privacy claims state exactly what is observable

Public copy (README, site) SHALL claim that document content never leaves the browser tab and MUST NOT claim the absence of all network activity; where copy invites the reader to inspect the network panel, it SHALL describe what the panel will actually show (same-origin static asset fetches only, none carrying document content).

#### Scenario: A skeptical attorney opens DevTools before analyzing

- **WHEN** a first-time visitor opens the network panel and then analyzes a document
- **THEN** every request they observe is consistent with the copy's description: same-origin GETs for the app's own assets, no request carrying any part of their document

### Requirement: The analysis path performs no cross-origin requests

During a complete analysis of any supported input (DOCX, PDF, paste, bundle), the application SHALL issue no cross-origin network request and no request with a body; an automated end-to-end test MUST intercept all requests during full DOCX and PDF analyses and fail on any violation.

#### Scenario: PDF analysis under interception

- **WHEN** the e2e suite analyzes a PDF with all requests intercepted
- **THEN** every request is a same-origin GET for a static asset
- **AND** no request is issued to any other origin (including pdf.js worker, font, or cmap assets)

#### Scenario: A cross-origin request regression

- **WHEN** a change causes any analysis-time request to a foreign origin
- **THEN** the e2e gate fails naming the offending URL

### Requirement: PDF engine assets are pinned same-origin

The PDF ingestion path SHALL explicitly configure its worker script and any auxiliary data (standard fonts, cmaps) to resolve from bundled same-origin assets, and MUST NOT rely on a library default that can reach a CDN.

#### Scenario: Worker resolution offline

- **WHEN** the app is loaded and a PDF is analyzed with all foreign origins unreachable
- **THEN** ingestion completes normally using the bundled worker and font assets
