# fix-privacy-claim-accuracy

## Why

The privacy copy overstates what a skeptical reader will observe. `site/index.html:1792` claims "zero network calls during analysis" and README.md:23/:830 invite the reader to "open DevTools and watch the network panel go quiet" / "the network panel stays empty" — but `runPipeline` fetches the DKB and playbook JSON (same-origin static assets) the moment analysis starts (`src/ui/pipeline.ts:753`, `:774`), so a first-run network panel visibly fills with requests. No document content is transmitted — the true claim is strictly stronger than most competitors can make — but the literal claim is false, and it fails in front of exactly the technically careful attorney the copy is written to convince. One open question rides along: whether pdf.js resolves its worker script or standard font data from a CDN when unconfigured (no `workerSrc` assignment was found in `src/`), which would make even the corrected claim wrong for PDF analysis.

## What Changes

- Reword every privacy claim (README, site) to the defensible invariant: *your document never leaves the tab* — the only network requests are same-origin fetches of the app's own static assets (rule data, playbooks), and none carries document content. Keep the DevTools invitation, scoped to what the panel will actually show.
- Prove the invariant instead of asserting it: an e2e test intercepts all requests while a DOCX and a PDF are fully analyzed, asserting (a) zero cross-origin requests, (b) every request is a GET for a same-origin static asset, and (c) no request body exists at all during the run.
- Pin pdf.js assets same-origin: set `GlobalWorkerOptions.workerSrc` (and standard-font/cmap paths if used) to bundled assets explicitly, so PDF analysis can never reach out to a CDN; the e2e PDF run enforces it.

## Impact

- Affected specs: `privacy-posture` (new capability spec)
- Affected code: README.md, `site/index.html`, `src/ingest/pdf.ts` (explicit worker/font asset wiring), `vite.config.ts` if worker bundling needs it, new Playwright e2e
- Risk: none to analysis output — copy and asset-resolution changes only; the e2e converts the product's strongest promise from prose into a gate.
