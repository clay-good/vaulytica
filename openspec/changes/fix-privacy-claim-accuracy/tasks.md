# Tasks

- [ ] 1. Measure current behavior: run a DOCX and a PDF analysis under Playwright request interception; record every request (URL, method, origin, body presence). Confirm or refute the pdf.js CDN question (worker script, standard fonts, cmaps).
- [ ] 2. Pin pdf.js assets: set `GlobalWorkerOptions.workerSrc` (and font/cmap paths if step 1 shows them fetched) to same-origin bundled assets; verify a PDF still ingests byte-identically (existing goldens).
- [ ] 3. Rewrite the copy: `site/index.html:1792` ("zero network calls during analysis") and `:2252`, README.md:23 and :830 — claim document-content non-transmission plus same-origin-static-assets-only, and describe what DevTools will actually show.
- [ ] 4. Add the e2e gate: full analyze flow for DOCX and PDF with route interception asserting zero cross-origin requests, GET-only same-origin static assets, and no request bodies; wire into the existing e2e suite.
- [ ] 5. Sweep for other absolute privacy claims (docs/, DISCLAIMER.md, site meta tags) and align them with the same wording.
- [ ] 6. Full gate: `npm run typecheck && npm run lint && npm test && npm run build` plus the e2e suite.
