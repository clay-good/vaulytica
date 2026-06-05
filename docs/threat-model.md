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

## v3 additions

v3 introduces five new attack surfaces and trust assumptions worth
calling out honestly. None of them weaken the v2 posture; all of them
warrant explicit treatment because v3 expands the DKB, the rule catalog,
and the citation surface area.

### 1. DKB integrity

v3 ships ~24 fetcher-derived bundles of regulator text in the DKB
(`dkb/dist/<version>/`). The runtime verifies these in three ways:

- The DKB manifest carries a `version` string and `sources[].id` /
  `source_url` pairs; the loader at `src/dkb/loader.ts` validates the
  manifest shape with Zod before any rule consumes it.
- Every v3 node carries `dkb_node_version` and `dkb_node_last_validated_at`,
  so a stale node surfaces in the loader output.
- Every v3 citation carries `content_hash_at_pin =
  sha256(normalizeForHash(snapshotText))` (see Step 20). The build
  pipeline re-fetches the upstream URL on each weekly run and compares
  the hash.

What this protects against: a tampered DKB JSON whose contents disagree
with the regulator's published text. The hash check would fail and the
loader would refuse to accept the manifest.

What it does not protect against: a clean swap of *both* the DKB JSON
*and* the bundle at the same time. SRI on the entry bundle
(Verification step 6) makes that materially harder, but a sufficiently
motivated adversary with control of the deploy could in principle ship
a tampered DKB with a tampered runtime that does not check it. See
"v3 still does not protect against" below.

### 2. The staleness gate

When the DKB build pipeline detects upstream drift, the affected rule
is moved into a stale-citation queue and disabled (`enabled: false`).
The build itself exits non-zero if any drift is unacknowledged in
`dkb-staleness-ack.yml`. Acks are explicit (`{node_id, citation,
acknowledged_by, reason}`) and leave an auditable trail.

What this protects against: silent drift between regulator text and
the DKB. A finding cited against a section that no longer exists at
that URL is the kind of error that erodes trust in a compliance tool;
the staleness gate prevents it.

How it might be bypassed: a human reviewer hand-acks a drift in
`dkb-staleness-ack.yml` without actually reading the diff. The
acknowledgment is auditable but it is still a human decision; treat
the ack file as a security-sensitive artifact in code review.

### 3. The citation surface

v3 reports surface every citation in three places:

- Inline next to the finding (the `[1] [3] [5]` bibliography numbers).
- In the §55 citation index appendix with a clickable URL.
- In the per-page footer's "Citations as of [DKB build date]" line.

A reader of a printed single page can verify the report against its
source. This is the v3 analogue of the v2 "fingerprint of the input
file is recorded above" line on the report cover.

What this protects against: a malicious DKB that lies about a CFR
section — the citation index gives the reader the URL to verify, and
the staleness gate would catch the drift on the next weekly build.

What it does not protect against: a DKB that silently swaps two
correctly-cited but unrelated facts. The hash check would not catch
this because each individual citation is internally consistent; only
end-to-end fixtures (Step 34 goldens) catch this class of bug.

### 4. The "consensus practice" AI-addendum disclaimer

The AI-addendum playbook (spec-v3 §34) cites NIST AI RMF, the EU AI
Act, and FTC enforcement actions rather than controlling statute. Each
ADDENDA-NNN rule in that surface carries the "consensus practice, not
statute" framing explicitly in its description, and the report's §59
disclaimer reinforces it:

> Where v3 cites a "consensus practice" rather than a controlling
> regulation (notably in the AI-Addendum playbook), Vaulytica is
> reporting industry norms, not law. Failing one of these checks is
> not a regulatory violation. It is an observation worth a
> conversation with counsel.

What this protects against: a user mistaking the AI-addendum findings
for legal claims. The disclaimer is dry, prominent, and unavoidable in
the report.

What it does not protect against: a user who reads only the
compliance-matrix summary cell. A future build will tag the
AI-addendum row in the matrix explicitly as "consensus practice" to
narrow this gap.

### 5. The non-promise of universal coverage

v3 covers the source catalog in [`docs/v3/regulators.md`](v3/regulators.md)
and no more. Unsupported regulators surface as `N/A` cells in the
compliance matrix with a "not yet covered" note. The non-promise is
made explicit in:

- The compliance-matrix section ("It does not opine on a regulator-
  specific posture not covered by the source catalog").
- The v3 overview ("v3 also does not cover every jurisdiction in every
  regulator's universe").
- The report disclaimer block.

What this protects against: a user paging through a green compliance
matrix and concluding the document is "compliant" with regulators v3
does not cover. Every uncovered regulator shows `N/A` rather than
silently passing.

What it does not protect against: a user who skips the matrix entirely
and reads only the findings count. Counts alone are misleading; the
matrix and the source catalog together are the citable surface.

## What v3 still does not protect against

- A regulator whose stable URL goes 404 between weekly builds — the
  staleness gate catches this at build time, but a user running an
  older deployed build may run against a since-removed citation. The
  citation-as-of footer line lets a reader notice the staleness.
- A "consensus practice" that hardens into statute mid-period. The
  AI-addendum surface in particular has a roughly 3- to 6-month
  half-life on consensus practice; treat it as a moving target.
- An adversarial document drafted specifically to evade v3's regex
  patterns. The rules are deterministic, which means they are
  predictable; a determined drafter can craft text that satisfies the
  presence patterns without satisfying the regulator's intent. The
  rules are conservative on purpose (false-negative-prefer over
  false-positive) so adversarial documents that slip through still
  get reviewed by counsel.
- A jurisdictional carve-out (e.g., Cal. Civ. Code § 1668 in a
  contract that explicitly waives California's choice-of-law rule).
  v3 flags the statute reference but cannot reason about the waiver
  unless the waiver is also pattern-matched. Treat the v3 findings as
  a checklist, not a determination.

## v4 additions — multi-document surface

### Multi-doc ingest (zip + folder + multi-file drop)

Same client-side posture as v1–v3: zip decompression runs via `fflate`
entirely in the browser; no temporary upload, no server touch. The
per-bundle cap (50 files / 200 MB) is enforced before decompression
begins — a zip bomb that would expand beyond the cap is rejected at the
outer-size check, preventing memory-exhaustion DoS in the tab. Each file
in the bundle is parsed independently by the same single-document
extractors used in v1–v3; no new network surface is introduced.

### Cross-document rules (CROSS-* families)

Seven rule families operate across the parsed documents in a bundle:
CROSS-PARTY (party-name drift — e.g., "Acme Corp." in the MSA vs.
"Acme Corporation" in the SOW), CROSS-JURIS (governing-law conflict
between documents), CROSS-DEFTERM (a defined term used across documents
but defined inconsistently), CROSS-DATE (effective-date paradox — an
amendment pre-dates its parent agreement), CROSS-AMOUNT (cap or payment
amounts that contradict between an MSA and its order form),
CROSS-MISSING (a document referenced by name in the bundle that is
absent from the bundle), and CROSS-PRECEDENCE (conflicting precedence
clauses). Each finding cites every contributing document by its
per-bundle index. What they do not protect against: a controlling
document that the user never included in the bundle — CROSS-MISSING
fires only when a document is referenced by name in a present document.

### Bundle fingerprint determinism

The bundle fingerprint is `SHA-256(sorted per-doc hashes || cross-doc
outcome bytes)`. Inputs are sorted lexicographically before hashing so
the fingerprint is independent of the order in which the user dropped
the files. The same bundle of documents produces a byte-identical
fingerprint across machines and operating systems, consistent with v1–v3
determinism guarantees.

### Expanded family catalog (16 sub-domains)

v4 adds sub-domains B (corporate governance), C (equity / cap-table),
D (M&A), E (real-estate expanded), F (employment expanded), G
(settlement / demand), H (IP / licensing expanded), I (privacy
expanded), J (healthcare), K (insurance), L (banking / lending), M
(construction), N (trust / estate / family), O (compliance policies),
and P (regulatory prose). Sub-domains N and P carry mandatory
per-output disclaimers (execution-formality and filing-schema
respectively, per spec-v4 §6 footnotes). These disclaimers appear in
the report cover and cannot be suppressed; they are not a threat-model
control but a disclosure-accuracy measure.

### What v4 still does not protect against

- State-law variance the DKB has not yet indexed. v4's source catalog
  covers CA / NY / TX / FL / IL for most state-keyed families; other
  jurisdictions surface as `N/A` in the compliance matrix.
- A bundle that omits a controlling document. CROSS-MISSING fires on
  named references but cannot know what the user forgot to include.
- Regulator filing schemas that v4 explicitly does not lint: SEC EDGAR
  XBRL, FINRA WebCRD, and other machine-submission formats. v4 lints
  the prose of regulatory-facing documents (Form ADV narrative, Reg S-K
  Item 105 disclosures), not the structured-data envelope a filing
  system validates separately.

## v6 additions — workflow surface

v6 expands *what you can do with* a run (compare versions, enforce your
own standard, export findings, aggregate a portfolio) and deepens what
the engine already does. Each feature passed the same five-part posture
filter (deterministic / no-AI / no-server / citable / lints-not-drafts).
Two of them open new trust surfaces worth stating explicitly.

### User-supplied playbooks (Part II)

A custom playbook is an arbitrary `.json` file the user loads from their
own disk. It is held in the tab exactly like the user's document:
loaded via the file input, validated against the public schema with
`zod`, and kept in memory for the session. It is **never uploaded** —
the privacy guard (`tests/integration/custom-playbook-privacy.test.ts`)
asserts no playbook bytes appear in any network request, the same
discipline the corpus-exclusion tests apply to document content.

What a malicious or malformed playbook **cannot** do:

- **Execute code.** The `custom_rules` block is a constrained,
  declarative predicate set (`clause_present`, `numeric_threshold`,
  `governing_law_in`, …) evaluated by the engine's interpreter over the
  same extracted facts the built-in rules use. There is no
  free-code-execution path, no `eval`, no regex supplied as code — a
  custom rule is data, so a custom playbook is as auditable and
  deterministic as a built-in one and cannot exfiltrate or compute
  arbitrarily.
- **Forge provenance.** Findings produced by a user playbook carry
  `source: "custom-playbook"`, so the report always distinguishes "your
  standard flagged this" from "Vaulytica's catalog flagged this." A
  custom rule without a citation is marked `uncited (team policy)`,
  never silently presented as a Vaulytica-authored, DKB-grounded
  finding.
- **Silently mis-run.** A playbook that fails schema validation is
  rejected with human-readable errors before any rule runs; a playbook
  targeting a retired catalog version warns rather than failing
  opaquely. A rule the playbook references that does not exist in the
  catalog is surfaced as unevaluable, not skipped quietly.

What this still does not protect against: a user who loads a *wrong*
playbook (an honest standard that encodes a position their own counsel
would reject). v6 enforces the standard the user supplies; it does not
opine on whether that standard is good — the same way it lints a
document without judging whether the deal is wise.

### Jurisdiction overlays (Part VI §21)

The state-law overlay catalog (`src/dkb/state-overlays.ts`) is a frozen,
hand-curated, `zod`-validated module — not a runtime fetcher and not a
user input. Overlays are selected deterministically from the matched
family (a function of the playbook id) and the governing-law state read
out of the extracted jurisdiction references, and are surfaced as a
**citable reference layer alongside** the report, not as `EngineRun`
findings, so no existing `result_hash` changes. Coverage is honest by
construction: a governing-law state with no overlay node is reported as
an explicit gap (`uncovered_states`), never silently treated as a clean
pass. The same boundary as v4 holds — state-law variance the catalog has
not indexed surfaces as an honest N/A. The residential-deposit overlays
gate to the residential lease playbook only; the commercial-lease
playbook is excluded, so a residential deposit-cap statute is never
mis-applied to a commercial lease.

## v7 additions — proof surface

v7 deepens extraction and adds many test artifacts. Both the determinism
and the privacy claims must hold *unweakened*, and the new test
machinery must not become a new exfiltration or trust surface.

### Deepened extraction does not silently change output

Every extractor change in v7 is **additive and fixture-gated**. New
record fields (`fiscal_period`, `range_max`, `per_unit`, `aliases`,
`dba`, `nested_triggers`, `obligor_exclusion`, `reference`, `scope`,
`circular_terms`, `sub_ref`, `fallback_jurisdiction`) are optional, and
the extracted-data stream is **not part of `result_hash`** — only a rule
that reads a new signal can change a finding. The single intentional
behavior change (the prohibitive/permissive modal signal) shipped with a
line-reviewed golden re-baseline touching only OBLI-005; nothing was
silently absorbed. New cross-document rules fire only in bundle mode, so
single-document `result_hash` is byte-unchanged.

### Test artifacts stay in the repo / the tab

Property generators (`fast-check`), the parity harness, and the Node
accuracy pipeline are **build-and-CI-only** — never imported by `src/`,
so none ship in the browser bundle. The existing import-direction guard
(`tests/integration/accuracy-corpus-guard.test.ts`) enforces that `src/`
never imports `tools/accuracy` or the corpus; the parity test lives in
`tools/` and imports `src/` (the allowed direction), so the shipped
bundle is unaffected. `fast-check` generates inputs and Stryker (when it
lands) mutates code, both at build time — neither introduces a
probabilistic component into the shipped path. The engine remains a pure
synchronous function.

### Report provenance and the executive summary leak nothing new

The JSON `provenance` block stamps version strings (DKB, engine,
rule-taxonomy) already implied by the run; the portfolio
`executive_summary` is pure aggregation over per-document findings the
report already contains. Both live outside every `result_hash` and
bundle fingerprint, and neither emits document content that was not
already in the report. The `.ics` verify-manually events surface
unresolved deadlines (with their source section) that were previously
dropped — strictly *more* of the user's own document, never anything
external.

### Responsiveness gate is an observation, not a surface

The responsiveness Playwright spec only measures `scrollWidth` against
`clientWidth` at fixed viewports against the already-deployed site; it
introduces no new input channel and no network egress beyond the
same-origin page load the other e2e specs already make.
