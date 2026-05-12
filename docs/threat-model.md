# Threat model

Vaulytica's privacy posture is a single, **unfakeable** claim:

> The contract you drop never leaves your browser tab.

This document spells out what that means, what it protects against, and what it does not.

## What Vaulytica protects against

### Network exfiltration

The contract is read into a `File` / `ArrayBuffer`, parsed by `pdfjs-dist` / `mammoth` in the browser, fed through the rule engine, and converted to a DOCX `Blob` — all in the same JavaScript context. There is **no `fetch()` call that sends the document anywhere.** The static Content Security Policy (CSP) shipped via [`dist/_headers`](../vite.config.ts) declares `connect-src 'self'`, which means even a future bug or supply-chain compromise cannot smuggle the document to a third-party endpoint without the browser blocking it.

You can verify this yourself:

1. Open DevTools → Network panel.
2. Filter to "Fetch/XHR".
3. Drop your contract.
4. Watch the request list. The only entries you will see are first-party loads of the DKB JSON, the playbook JSON, and the hashed JS bundles — all from `https://vaulytica.com`. **No request body ever carries your document.**

### Vendor mining and model training

Vaulytica has no AI in the pipeline. No clause, no excerpt, no embedding is sent anywhere. The classifier is a static TF-IDF vocabulary trained offline against CUAD + LEDGAR + EDGAR exhibits — see [data-sources.md](data-sources.md). Your contract is **never** used to train, fine-tune, or augment any model.

### Server breach

Vaulytica is a static site on Cloudflare Pages. There is no application server, no database, no log of analyses, no analytics, no telemetry. A breach of any Vaulytica-controlled infrastructure cannot leak your contract because the contract was never stored on that infrastructure. The most an attacker could do by compromising the host is serve a tampered JS bundle to future visitors — see "Verification procedure" below for how to defend against that.

### Recovery / discoverability

Vaulytica's operators (currently the GitHub user that owns this repo) have no ability to recover an analysis you ran. The `result_hash` in the audit trail is reproducible, but the input document is not stored. If you need to prove what you saw, save the DOCX report alongside the input file.

## What Vaulytica does NOT protect against

These are out of scope by design:

### A compromised browser

If a malicious browser extension, a hostile build of the browser itself, or an in-browser keylogger can read what you read, Vaulytica cannot help. Inspect your extensions; use a clean profile for sensitive work.

### Malicious browser extensions with broad permissions

Any extension with `*://*/*` host permissions can intercept document content before Vaulytica sees it. The same caveat as a compromised browser applies.

### The user themselves

If you save the DOCX report to Dropbox / Drive / Slack / a corporate share, the report (which embeds quoted excerpts of the original contract in its findings) is now on whatever surface you uploaded it to. Vaulytica's privacy story ends at the moment of download.

### Side-channel attacks on the operating system

Memory scraping, swap-file recovery, hibernate-file recovery — these affect every browser application and are out of scope.

### Vaulytica-tampered builds

A supply-chain attacker who compromises the repo, the Cloudflare Pages deployment, or the npm dependency graph could theoretically push a build that exfiltrates the document via a permitted same-origin endpoint (a worker script, say). The strict CSP makes this materially harder — there *is* no permitted endpoint — and SRI on the main module-script tag (see step 6 of the verification procedure) means a swap-at-the-edge no longer executes silently. The threat is not zero, but the cost-of-exploitation has gone from "swap a JS file" to "produce a hash collision against a SHA-384 plus get past the strict CSP plus convince a user not to notice a blank page."

## The unfakeable claim

The privacy posture is unfakeable in the precise sense that **anyone with a browser and a network panel can verify it in real time**. Vaulytica makes no claim that requires trusting our infrastructure logs, our audit logs, or our SOC 2 report. The only thing you have to trust is what your browser tells you, and the browser will tell you the truth about what was fetched. That is the whole product.

## Verification procedure

If you need to vouch for Vaulytica before recommending it to a client or colleague:

1. **Read the source.** Vaulytica is open source under MIT. Start at [`src/ui/main.ts`](../src/ui/main.ts) — the entire client pipeline is wired from one file. Trace the data flow and confirm no `fetch()` call carries the input document.
2. **Confirm the CSP.** In a deployed environment, `curl -I https://vaulytica.com/ | grep -i content-security-policy` will return the static header. Confirm `connect-src 'self'` — that single directive forbids any cross-origin POST.
3. **Watch the network panel during a real analysis.** Drop a fixture contract. Filter to Fetch/XHR. Confirm zero outbound bodies.
4. **Reproduce a report.** Determinism is verifiable: see [determinism.md](determinism.md). A report with a given `result_hash` can be regenerated byte-for-byte. If Vaulytica's behavior were tampered with on the server side, the hash would drift.
5. **Compare bundle hashes.** The `dist/` build is reproducible from the tagged commit. Compare the `dist/assets/main-*.js` hash against a local `npm ci && npm run build` of the same tag to confirm no smuggled bundle was served.
6. **Confirm SRI is enforced.** The main `<script type="module">` tag in `dist/index.html` carries an `integrity="sha384-…"` + `crossorigin="anonymous"` pair generated at build time by the SRI plugin in `vite.config.ts`. If the served bundle's bytes don't hash to the declared value, the browser refuses to execute it — the page goes blank rather than running tampered code. View source on the deployed site to read the live hash; recompute locally to compare.

## Surface area for further hardening

These are not threats today but are worth tracking:

- **SRI on dynamic-import chunks.** Today's SRI plugin covers the eagerly-loaded entry only. Dynamic-import chunks (the analysis pipeline, vendor chunks) load *after* the entry has already passed SRI; an attacker who could swap a vendor chunk would first have had to bypass the entry SRI. Belt-and-suspenders SRI on dynamic chunks requires `build.modulePreload.resolveDependencies` hookery; tracked.
- **A `report-uri` for CSP violations** so we can see *if* anyone is trying to smuggle content out via an allow-listed scheme. Currently absent because a `report-uri` would itself require a permitted reporting endpoint.
- **Signed commits + tagged releases** so the supply chain from "commit" to "deploy" is verifiable end-to-end. Currently the Cloudflare deploy verifies the GitHub Action signature but not commit signatures.
