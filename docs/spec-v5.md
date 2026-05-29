# Vaulytica v5 — Ground Truth

> **Status:** specification, not yet implemented.
> **Scope:** measure and prove the engine's accuracy. No new document families, no new rules-for-the-sake-of-rules, no UI rebuild. v5 builds the corpus, the metrics harness, the legal-review ledger, and the public trust artifacts that turn "1,000 rules that pass their own synthetic fixtures" into "a tool whose error rate is known, published, and reproducible." It also lands the deployment and real-user gates that v1–v4 left pending.
> **Cousin docs:** [`spec.md`](spec.md) (v1, 17 steps, 1.0.0), [`spec-v3.md`](spec-v3.md) (regulated agreements), [`spec-v4.md`](spec-v4.md) (all logically-operative legal documents).

---

# Part 0 — Intent

## §1. Why we're doing this

Vaulytica's one-line pitch is **"the second pair of eyes you can cite."** Everything in the product is bent toward that promise: determinism, citation pinning, the audit trail, the no-AI posture. The argument is that a probabilistic tool produces an answer you cannot stake a review on, and a deterministic one produces an answer you can.

There is a hole in the middle of that argument. *Deterministic* is not the same as *correct.* A rule that fires the same way every time can be reliably, reproducibly **wrong** — it can flag a clause that is actually fine (a false positive that erodes a reviewer's trust within minutes), or stay silent on a clause that is actually defective (a false negative that is worse, because the user believes they had a second pair of eyes and did not). Vaulytica today proves determinism three different ways and proves correctness **zero** ways.

Concretely, after v4 the engine ships ~1,000 rules across 30+ playbooks, 2,235 passing tests, and a green four-gate CI. But every one of those tests is a **synthetic fixture authored by the same person who authored the rule.** A fixture is built to make a rule fire; the rule is built to fire on the fixture. The loop is closed and self-confirming. We have never measured how the engine behaves on a contract it has not seen, written by a lawyer who has never heard of Vaulytica. We do not know our precision. We do not know our recall. We do not know our false-positive rate. We have never had a practicing attorney confirm that a single rule's *legal premise* is sound — only that its regex matches the fixture.

The §8 open-question resolution in spec-v4 is the tell: the classifier confidence threshold was "calibrated against the labeled golden corpus," but that corpus is the synthetic fixtures. We tuned a real parameter against fake data and recorded it as resolved. That is the pattern v5 exists to break.

v5 is the validation layer. It does not make the engine bigger. It makes the engine's accuracy **measured, legally vetted, and publicly defensible** — which is the only thing that converts a green test suite into a tool a senior partner can actually sign off on.

## §2. What v5 explicitly is and is not

**v5 is:**

- A **real-document corpus**: licensed, attributable, real-world legal documents (not synthetic fixtures), each annotated with a gold-standard set of which findings *should* and *should not* appear.
- A **measurement harness** that runs the full engine over the corpus and computes precision, recall, F1, and a confusion matrix — per rule, per family, per sub-domain, per severity, and overall — deterministically and offline, the same way every time.
- A **legal-basis ledger**: a per-rule record of the legal authority the rule rests on, reviewed and signed off by a credentialed reviewer, with a confidence tier and a retirement path for rules that do not survive review.
- A **calibration pass**: severities re-grounded against measured impact, a published false-positive budget, and the classifier re-evaluated against real documents instead of fixtures.
- An **explainability surface**: every finding (and every notably *absent* finding) carries the evidence span and the plain-language reason it fired, so a human can adjudicate it in seconds.
- A set of **public trust artifacts**: a versioned accuracy report, a methodology page, and an honest-limits disclosure, all generated from the harness so they cannot drift from reality.
- The **deployment and real-user validation work** that v1/v3/v4 launch checklists left `⏳ pending` / `🟡 partial` because they require a live site and real humans.

**v5 is not:**

- A new catalog of document families. The taxonomy froze at v4's 16 sub-domains. v5 may *retire* or *split* rules as a consequence of review, but it does not chase new surfaces.
- A model. The corpus is used to **measure** the deterministic engine, never to train anything. No statistics derived from the corpus are shipped to the browser as decision logic; the engine remains pure-function `(DocumentTree[], DKB, Playbook) → Findings`. (See §27.)
- A change to the runtime privacy posture. The corpus and the harness are **build-and-CI-only.** Not one byte of corpus, score, or annotation ships in the deployed bundle or leaves the developer's machine at runtime. The user's document still never leaves the tab.
- A loosening of determinism. Every metric is computed from canonical, sorted facts; the scoreboard is byte-reproducible across machines exactly as `result_hash` is.

## §3. The single claim v5 must back

If v5 ships one number, it is this:

> On a corpus of **N real legal documents** we did not write, Vaulytica's findings agree with a credentialed reviewer's gold annotations with **precision P** and **recall R**, reproducibly, and here is the per-rule breakdown so you can see exactly where it is strong and where it is weak.

Every part of v5 exists to produce that sentence honestly and keep it true on every commit.

---

# Part I — The ground-truth corpus

## §4. Corpus composition and sourcing

The corpus is the foundation; if it is not real and not legally clean, nothing built on it counts. Requirements:

- **Real, not synthetic.** Documents drafted by practicing lawyers for actual transactions, not authored to exercise a rule. Synthetic fixtures stay where they are (they remain the *unit* regression layer); they are explicitly excluded from the *accuracy* corpus and the harness asserts the two sets are disjoint.
- **License-clean and attributable.** Every document carries a provenance record: source, license, retrieval date, and redaction log. Acceptable sources, in priority order:
  1. **Public filings** — SEC EDGAR material-contract exhibits (10-K Ex-10, 8-K), which are public-domain U.S. government republications of real executed agreements. This is the richest clean vein: real MSAs, employment agreements, credit agreements, merger agreements, bylaws, indemnification agreements, leases.
  2. **CC0 / open-license template banks** — Common Paper, Y Combinator (SAFE, Series A), Bonterms, NVCA model docs, Orrick Start-up Forms, GitHub-hosted CC0 contract sets.
  3. **Academic research corpora** — CUAD (Atticus, CC-BY-4.0), LEDGAR, ContractNLI, where the license permits redistribution or in-repo reference.
  4. **Donated documents** — explicitly contributed under a contributor agreement that permits inclusion, fully redacted of party-identifying detail.
- **Redaction.** Party names, signatures, account numbers, addresses, and any PII are mechanically scrubbed and the scrub is logged. Redaction must not perturb the structural features the engine reads (clause headings, defined terms, governing-law phrasing survive; only identities are masked).
- **Coverage targets.** The corpus must touch every sub-domain v4 claims to support, with a stated minimum per family so no family ships an accuracy claim backed by zero real documents:

  | Tier | Families | Min real docs per family | Rationale |
  |------|----------|--------------------------|-----------|
  | A — flagship | NDA, MSA, SaaS, DPA, BAA, employment, lease | 15 | Highest usage; EDGAR + Common Paper supply volume |
  | B — common | equity/SAFE, settlement, IP license, loan, governance | 8 | EDGAR exhibits + NVCA/YC templates |
  | C — long-tail | M&A, insurance, construction, trust/estate, compliance policy, regulatory prose | 4 | Sparser clean sources; honestly flagged as thin |

  A family below its minimum ships with an explicit `corpus_thin` flag on its accuracy claim (§22) rather than a fabricated number.
- **Negative and clean documents.** The corpus is not all defective docs. It must include **well-drafted, clean** documents (a finding-free or near-finding-free run is the expected output) so false-positive rate is measurable. A corpus of only-broken contracts measures recall and lies about precision.

## §5. The annotation protocol

A document without a gold annotation is unusable for measurement. The annotation is the human's ground-truth statement of what the engine *should* produce.

- **Annotation unit.** For each (document, applicable playbook) pair, an annotator records the **expected finding set**: which rule IDs should fire (a true defect/absence is present) and, by omission, which should not. Optionally, free-form "the engine should ideally catch X" notes capture defects no current rule covers (these feed the v4-non-promise backlog, not the score).
- **Annotators are credentialed.** Annotation is a legal judgment, not data entry. Annotators are licensed attorneys or supervised senior law students with a documented review by an attorney. Each annotation records the annotator ID and date.
- **Double-annotation + adjudication.** Each document is annotated independently by two annotators. Disagreements are surfaced by the harness and resolved by a third senior adjudicator. **Inter-annotator agreement (Cohen's κ) is itself measured and published** — if the humans cannot agree on whether a clause is defective, the engine cannot be graded against a coin flip, and that rule's metric is marked low-confidence.
- **Blind to engine output.** Annotators do not see Vaulytica's findings before annotating. Annotating against the tool's output launders the tool's errors into the ground truth.
- **Schema.** Annotations are stored as canonical JSON sidecars, one per (document × playbook), version-stamped to the corpus release and the DKB version they were made against.

## §6. The gold-standard schema

```jsonc
{
  "corpus_doc_id": "edgar-10k-ex10-2021-acme-msa-redacted",   // stable, opaque
  "source": { "origin": "SEC EDGAR", "accession": "...", "license": "US-Gov-PD",
              "retrieved_at": "2026-06-01", "redaction_log": "redactions/....json" },
  "applicable_playbooks": ["msa-vendor-deep"],
  "annotations": [
    {
      "playbook_id": "msa-vendor-deep",
      "annotator_a": "att-014", "annotator_b": "att-022", "adjudicator": null,
      "kappa_input": true,
      "dkb_version_at_annotation": "2026-06-01.1",
      "expected_findings": [
        { "rule_id": "MSA-006", "verdict": "should_fire",
          "evidence_hint": "no liability cap in §11", "severity_expected": "high" },
        { "rule_id": "MSA-024", "verdict": "should_not_fire",
          "note": "governing law and venue both NY — consistent" }
      ],
      "uncovered_defects": [
        { "description": "one-sided audit right with no notice period", "no_rule_yet": true }
      ]
    }
  ]
}
```

`should_fire` / `should_not_fire` are the gradable verdicts. `uncovered_defects` are tracked but never scored against the engine (you cannot dock recall for a rule that does not exist; you *can* prioritize building it).

## §7. Corpus governance and versioning

- **The corpus is a versioned artifact** (`corpus/CORPUS_VERSION`), released on its own cadence, decoupled from the DKB. Every accuracy number is stamped `(corpus_version, dkb_version, engine_commit)` so a published score is always reproducible.
- **No silent edits.** Adding, removing, or re-annotating a document bumps the corpus version and is logged in `corpus/CHANGELOG.md`. Scores across corpus versions are never compared without noting the version change.
- **Storage.** Redacted text + JSON annotations live in-repo (or in a Git-LFS / submodule pointer if size warrants — decided in Step 67). Original unredacted source is **never** committed; only the redacted derivative and the provenance record.
- **Frozen test split.** A fixed held-out subset is designated the **regression split** and is the one CI gates on (§11). The remainder is the **development split** used while authoring rules. A rule author may see the dev split; the regression split is touched only by CI. This prevents the engine from being implicitly overfit to the documents that grade it.

---

# Part II — The measurement harness

## §8. Metric definitions

For every rule, against the regression split, the harness counts:

- **TP** — rule fired and gold says `should_fire`.
- **FP** — rule fired and gold says `should_not_fire` (or is silent on a doc where the playbook applies).
- **FN** — rule did not fire and gold says `should_fire`.
- **TN** — rule did not fire and gold says `should_not_fire`.

From these, per rule, per family, per sub-domain, per severity, and overall:

- **Precision** = TP / (TP + FP) — "when Vaulytica flags it, how often is it right?" This is the trust metric; a low-precision rule trains users to ignore the tool.
- **Recall** = TP / (TP + FN) — "of the real defects, how many did we catch?" This is the value metric; the whole point is the second pair of eyes.
- **F1** = harmonic mean — the single headline per rule.
- **Macro vs micro averages** are both reported: macro (mean over rules) so a high-volume rule cannot mask a broken rare one; micro (pooled counts) so the overall number reflects real document mix.
- **Confusion at the document level**: for each (doc × playbook), the full set diff between produced and expected findings.

Metrics are only computed where κ-agreement existed; rules graded only against documents the annotators disagreed on are reported as `low_confidence` rather than given a false-precise number.

## §9. Harness architecture

- **Location:** `tools/accuracy/` (build-and-CI-only; never imported by `src/`).
- **Pure and deterministic:** `runAccuracy(corpusVersion, engineCommit) → Scoreboard`. It loads the regression split, runs the real engine (`runEngine` / `runEngineMulti`, unchanged) over each (doc × applicable playbook), diffs against gold, and emits the scoreboard. No randomness, no network, no timestamps in the hashed output (same discipline as `result_hash`: `elapsed_ms` and wall-clock are excluded).
- **Reuses the real pipeline.** The harness must call the exact ingest → extract → classify → engine → (no report needed) path the browser uses, so a measured number reflects shipped behavior, not a test-only shortcut.
- **Reproducible scoreboard hash:** `SHA-256(canonical(scoreboard))` is stable across machines. Two engineers running `npm run accuracy` on the same `(corpus, commit)` get byte-identical scoreboards — the same contract `result_hash` already honors, extended to the metrics layer.

## §10. The scoreboard artifact

`tools/accuracy/SCOREBOARD.md` (human) + `scoreboard.json` (machine), regenerated by `npm run accuracy`:

- Headline: overall precision / recall / F1 (macro + micro), corpus + DKB + commit stamp, doc count, κ.
- Per-sub-domain table, sorted worst-F1 first (the honest direction).
- Per-rule table with TP/FP/FN, precision, recall, F1, confidence flag, and the legal-review tier from Part III.
- A **"worst offenders" section**: the 20 lowest-precision and 20 lowest-recall rules, named, so the next work is never guessed.
- A **"thin coverage" section**: every family below its §4 minimum, named, so no number is silently fabricated.

## §11. Regression gates

The accuracy harness becomes a **fifth CI gate** (joining lint, typecheck, test, build), but a *threshold* gate, not a *green/red* gate, because real-world accuracy is never 100% and pretending otherwise reintroduces the original dishonesty:

- **Floor gates (hard fail):** overall micro-precision ≥ `P_floor`, overall micro-recall ≥ `R_floor`, no shipped rule with precision < `rule_precision_floor` on ≥ K graded documents. Initial floors are set empirically from the **first** full run (Step 71), not aspirationally — we measure first, then set the floor just under the measured value so regressions fail.
- **Ratchet:** floors only move up. A commit that drops overall F1 below the recorded best fails CI and must be justified in the PR (a deliberate precision/recall trade is allowed but must be explicit and re-baseline the scoreboard).
- **New-rule rule:** a rule may not ship (or stay shipped) without ≥ K graded real documents exercising it, or it is marked `unmeasured` and excluded from the headline precision/recall — and that exclusion count is itself published, so "we shipped 1,000 rules but only measured 600" can never hide.

---

# Part III — Legal accuracy review

Measurement tells us whether a rule matches human annotations. It does not tell us whether the rule's *legal premise* is sound — annotators could share a misconception. Part III grounds each rule in authority a third party can check.

## §12. The legal-basis ledger

For every rule, a record in `docs/legal-basis/<family>.md` (and a machine mirror enforced by test):

```jsonc
{
  "rule_id": "BAA-019",
  "claim": "A BAA must require the business associate to report breaches of unsecured PHI to the covered entity.",
  "legal_basis": [
    { "authority": "45 C.F.R. § 164.410", "pinpoint": "(a)(1)", "dkb_node": "hipaa-baa-breach-notification" }
  ],
  "review": { "reviewer": "att-007", "credential": "JD, licensed NY bar #...", "date": "2026-06-15",
              "verdict": "sound", "tier": "established" },
  "notes": "Distinct from § 164.404 (CE→individual) and § 164.408 (CE→HHS); this rule targets BA→CE only."
}
```

- **`legal_basis` must be non-empty and DKB-linked.** This extends the existing v1 invariant ("every rule cites ≥1 DKB entry") from "has a citation" to "the citation actually supports the claim, confirmed by a human."
- **`verdict`** ∈ `sound` | `sound-but-narrow` | `disputed` | `unsound`. An `unsound` verdict triggers the retirement path (§14).
- **`tier`** ∈ `established` (black-letter law or model-code text) | `prevailing-practice` (widely-followed convention, e.g. a 30-day breach-notice window) | `opinion` (the rule encodes a defensible-but-contestable preference). **Tier is surfaced to the user** (§21) so a finding grounded in a statute reads differently from one grounded in a drafting preference — which is exactly the honesty the no-AI pitch demands.

## §13. Reviewer protocol and credentials

- Reviewers are licensed attorneys; credential and bar number are recorded (the bar number is for the maintainer's records, not published verbatim).
- A rule is not `sound`-signed by the same person who authored it. Author ≠ reviewer, the same separation §5 requires for annotation.
- Review is batched by family so a reviewer holds one body of law in context at a time (all BAA rules together, all SAFE rules together).
- The ledger is the launch artifact for the trust claim, the way `LAUNCH.md` is for the determinism claim: anyone can audit which rules a lawyer actually blessed and which are still author-asserted.

## §14. Disputed and retired rules

- A rule that reviews `unsound` is **retired**, not silently deleted: it moves to `retired` status, the playbooks that referenced it drop it, and `docs/legal-basis/retired.md` records why. This mirrors the existing playbook-deprecation pattern (`superseded_by`, `deprecated: true`) the codebase already enforces.
- A rule that reviews `disputed` may ship only if downgraded to `tier: opinion` and surfaced as such; it never counts toward an `established`-tier accuracy claim.
- Retirement that drops measured coverage is logged in the scoreboard so recall changes are explained, not mysterious.

## §15. The confidence tier in the engine

`tier` is added to the `Rule` type and threaded into `Finding` output, so the report, the JSON, and the UI can all distinguish a statutory finding from a preference. This is the only `src/` change Part III requires; it is additive and does not alter rule logic or the `result_hash` of existing findings except to add a field (which forces a deliberate baseline regen, tracked as its own step).

---

# Part IV — Calibration

## §16. Severity calibration

Severities (`critical` / `high` / `medium` / `low`) were assigned by rule authors a priori. v5 re-grounds them:

- A reviewed mapping from `tier` + measured impact to severity, documented per family.
- Cross-family consistency check: a "missing liability cap" and a "missing breach-notification clause" should rank by a stated, defensible scale, not by which author felt strongly that day.
- Severity changes are deliberate baseline regens, never incidental.

## §17. The false-positive budget

- A published, per-family **maximum acceptable false-positive rate.** Precision-killing rules (those that cry wolf) are the fastest way to lose a professional user, so the budget is explicit and gated (§11).
- Rules over budget are either tightened (narrower trigger), downgraded to `opinion` tier (so the user reads them as advisory), or retired. The choice is recorded.

## §18. Classifier accuracy on real documents

- The v4 sub-domain classifier (~70% top-1 on synthetic fixtures per the build-frontier note) is **re-measured on the real corpus**, since classifier feature tables tuned on fixtures may behave very differently on real prose.
- Confusion matrix per sub-domain (the build-frontier note already lists the suspected confusions: healthcare→privacy, ip-licensing→equity, settlement→commercial, compliance→employment). v5 confirms or refutes each on real data and re-tunes the feature table against the corpus, not the fixtures.
- The §8 threshold resolution from spec-v4 is **re-opened and re-decided against real documents**, with the same sweep methodology but honest inputs.

---

# Part V — Explainability and the citable trail

The pitch is "a finding you can cite." A reviewer can only cite a finding they can adjudicate fast. v5 makes each finding self-explaining.

## §19. Evidence spans

- Every `Finding` carries the **exact text span** (clause, sentence, offset) that triggered it — not just a section number. The extractor already walks the document tree; this surfaces the span it matched on.
- For **absence** findings ("no liability cap present"), the finding carries *where the engine looked* (the sections scanned) so "you missed it, it's in §14" is checkable in one click rather than a debate.

## §20. Why-fired / why-not

- The report and JSON gain a per-finding **rationale line**: the rule's `claim` (§12) in plain language + the legal basis + the matched span. This already mostly exists as rule metadata; v5 makes it a first-class, user-visible field.
- A debug-grade **"why did rule X *not* fire on this document"** trace, available in the JSON output (off by default in the DOCX to keep it readable), so a skeptical user — or a contributor — can audit a silence. This is the single most requested thing of any linter and the hardest to fake without determinism; Vaulytica can offer it precisely because it is deterministic.

## §21. The rule card

- Each finding links to a **rule card**: ID, claim, legal basis with pinpoint citations, tier badge (`established` / `prevailing-practice` / `opinion`), measured precision/recall from the latest scoreboard, and DKB source hash + retrieval date.
- The tier badge and the measured-precision number on the card are the honesty payload: the user sees not just "we flagged this" but "we flagged this, here's the statute, here's how tied-to-law-vs-preference it is, and here's how often this specific rule is right."

---

# Part VI — Public trust artifacts

Everything above is internal unless it is published. The differentiator only pays off if the buyer can see it.

## §22. The accuracy report

- A public page (`site/accuracy.html`, generated from `scoreboard.json`) carrying the headline precision/recall, the per-sub-domain breakdown, the corpus size and composition, κ, and the worst-offenders and thin-coverage sections **unredacted.** Publishing your own weak spots is the credibility move; a tool that only advertises its wins reads like every AI contract tool the README mocks.
- Versioned and dated. Stale = disabled, the same posture the DKB staleness gate already enforces for citations.

## §23. The methodology page

- `docs/v5/methodology.md` + a public-facing summary: how the corpus was built, how annotation worked, what κ means and what ours is, how precision/recall are computed, and exactly what the numbers do and do not claim. This is the document a careful general counsel reads before approving the tool for their team.

## §24. Honest-limits disclosure

- An expansion of the existing "What I do not do" section with the **measured** limits: families with thin corpus coverage, rules at `opinion` tier, known classifier confusions, and the precision floor (so "Vaulytica is right when it flags something ~X% of the time; here is the X, and here is where it is lowest"). This is consistent with the existing three-place disclaimer discipline and strengthens, rather than undercuts, the brand.

---

# Part VII — Deployment and real-user validation

Five launch-checklist rows across v1/v3/v4 are `⏳ pending` or `🟡 partial` for one reason: **there is no deployed `https://vaulytica.com`** and **no real human has been put in front of it.** No accuracy claim matters if no one can reach the tool, and no usability claim is backed until a non-author uses it. v5 closes this.

## §25. Deploy and flip the pending rows

- Stand up the deployment (Cloudflare Pages per the existing `deploy.yml`), run the post-deploy Playwright smoke suite, and flip the mechanically-verifiable pending rows: zero-outbound-request privacy claim (v1-a), cross-machine determinism (v1-c, via the committed `test-matrix.yml` first all-green run), live Lighthouse 4G budget (v1-l, v3-e, v4-e), live axe audit (v1-h, v3-f, v4-f), PWA install + offline (v1-i, v4-d), OG/link preview (v1-j), FAQ rich-results (v1-k), first weekly DKB rebuild stamping `retrieved_at` ≤ 7 days (v1-e, v3-i, v4-i), cross-browser multi-doc ingest on real devices (v4-o).
- These are operational, not architectural — the code and tests already exist and assert the static half. v5 simply requires the deploy to happen and the live verifications to be recorded with verifier + date, per `LAUNCH.md`'s sign-off discipline.

## §26. The real-user usability gate

- The v1-o gate ("one non-lawyer and one lawyer each drop a contract and produce a report without a clarifying question; the lawyer's only critique is wording, not correctness") runs against the deployed site with the corpus documents.
- A short structured protocol: task, observed friction, time-to-first-report, and — critically — the lawyer's correctness critique fed back as candidate `uncovered_defects` (§6) and candidate false-positive reports (§17). The first real users become the first corpus contributors.

---

# Part VIII — Determinism and privacy preservation

v5 must not weaken the two load-bearing claims.

- **Runtime privacy unchanged.** Corpus, annotations, scoreboard, and harness live in `tools/accuracy/`, `corpus/`, and `docs/`. None is imported by `src/`. A build-time guard (extending the existing bundle-size / static-HTML test family) asserts the deployed bundle contains no corpus text and no scoreboard data. The user's document still never leaves the tab; DevTools still shows zero outbound requests.
- **Determinism extended, not altered.** The scoreboard hash is computed with the same canonicalization discipline as `result_hash` (sorted keys, wall-clock excluded). The one `src/` touch — the `tier` field on `Finding` (§15) — forces a single deliberate golden-baseline regen, performed in its own step and reviewed as a P0-adjacent change per the existing determinism guardrail.
- **No AI, still.** The corpus measures the engine; it never feeds a model and no corpus-derived statistic becomes runtime decision logic. The classifier feature table re-tuned in §18 remains a hand-authored, inspectable, deterministic table — calibrated against real data, but still a table, not a model.

---

# Part IX — Build plan

Each step is a prompt-sized unit, continuing the global numbering after v4's Step 66. Verification gate for every step: `npm run typecheck && lint && test && build` green; from Step 71 on, `npm run accuracy` within gate.

| # | Step | Output |
|---|------|--------|
| 67 | Corpus scaffolding + provenance + redaction tooling | `corpus/` layout, `CORPUS_VERSION`, provenance schema, redaction script + redaction log, storage decision (in-repo vs LFS/submodule), disjoint-from-fixtures guard test. |
| 68 | Seed corpus — Tier A (EDGAR + Common Paper) | ≥15 real redacted docs each for NDA, MSA, SaaS, DPA, BAA, employment, lease. Provenance records committed. |
| 69 | Annotation schema + tooling + protocol doc | Gold-standard JSON schema (§6), `docs/v5/annotation-protocol.md`, double-annotation + κ computation tooling, adjudication workflow. |
| 70 | Tier A annotations + κ baseline | Two-annotator gold sets for all Tier A docs; κ computed and recorded; adjudications logged. |
| 71 | Accuracy harness v1 + first scoreboard | `tools/accuracy/` runner, metric computation (§8), `SCOREBOARD.md` + `scoreboard.json`, reproducible hash. **First honest precision/recall numbers recorded.** Empirical floors set just under measured. |
| 72 | Accuracy CI gate (threshold + ratchet) | `npm run accuracy` wired as fifth gate; floor + ratchet logic; `unmeasured`-rule exclusion accounting. |
| 73 | Tier B corpus + annotations | ≥8 real docs each for equity/SAFE, settlement, IP license, loan, governance; annotated; scoreboard extended. |
| 74 | Tier C corpus + annotations (thin, flagged) | ≥4 real docs each for M&A, insurance, construction, trust/estate, compliance policy, regulatory prose; `corpus_thin` flags wired. |
| 75 | Legal-basis ledger scaffolding + `tier` on Rule/Finding | Ledger schema + machine mirror test; `tier` field added to `Rule` and `Finding`; **deliberate golden baseline regen** (P0-reviewed). |
| 76 | Legal review — Tier A families | Attorney sign-off on NDA/MSA/SaaS/DPA/BAA/employment/lease rules; verdicts + tiers recorded; first retirements processed. |
| 77 | Legal review — Tier B + C families | Sign-off on remaining families; disputed/unsound handling; retired.md populated. |
| 78 | Severity calibration + false-positive budget | Reviewed severity mapping; per-family FP budget published + gated; over-budget rules tightened/downgraded/retired. |
| 79 | Classifier re-measurement + re-tune on real corpus | Confusion matrix on real docs; feature-table re-tune; §8 threshold re-decided with honest inputs; calibration test re-pointed at corpus. |
| 80 | Explainability — evidence spans + rationale | `Finding` carries matched span + scanned-sections for absence findings; rationale line in report + JSON. |
| 81 | Explainability — why-not trace + rule cards | JSON why-not trace; rule-card data assembled from ledger + scoreboard; tier badge + measured-precision surfaced in report/UI. |
| 82 | Public accuracy report + methodology page | `site/accuracy.html` generated from `scoreboard.json`; `docs/v5/methodology.md`; honest-limits disclosure expansion. |
| 83 | Privacy/determinism guards for the v5 surface | Bundle-excludes-corpus guard; scoreboard-hash determinism test; confirm no corpus-derived runtime logic. |
| 84 | Deploy + flip mechanical launch rows | Live deploy; smoke suite; record verifier + date for v1-a/c/e/h/i/j/k/l, v3-e/f/i, v4-d/e/f/i/o. |
| 85 | Real-user usability gate | v1-o protocol against deployed site with corpus docs; lawyer + non-lawyer; feedback → uncovered_defects + FP candidates. |
| 86 | v5 launch checklist + version bump | Full v5 launch checklist (corpus version, κ, precision/recall floors, ledger completeness, deploy green); bump to 5.0.0; tag v5.0.0. |

Total work: **20 build steps.** Unlike v1–v4, several steps (68, 70, 73, 74, 76, 77, 85) gate on **human** work (real-document sourcing, attorney annotation/review, real users) that cannot be compressed by writing code faster — this is the honest cost of the validation layer and the reason it was deferred until the engine was complete.

---

# Part X — Open questions for the maintainer

1. **Corpus storage.** In-repo redacted text vs Git-LFS vs a separate `vaulytica-corpus` submodule with its own license file. Size and clone-time vs convenience. Decide in Step 67.
2. **Annotator sourcing and cost.** Credentialed annotation is the real bottleneck and the real expense. Options: the maintainer self-annotates the flagship families (fast, but author≈reviewer risk for rules the maintainer also wrote), a contracted attorney, or a law-school clinic partnership. The κ requirement (§5) needs ≥2 independent annotators per doc regardless.
3. **EDGAR redaction fidelity.** EDGAR exhibits are already public, so redaction is lighter (mostly already-redacted by filers), but confirm no residual PII and that redaction does not strip structural cues the extractor needs. Pilot on 5 docs before Step 68 scales.
4. **Floor-setting philosophy.** Set floors just under the first measured value (regression-only), or set an aspirational target and treat the gap as a backlog? Recommendation: regression-only floors at first (Step 71), aspirational targets tracked separately in the scoreboard, so CI never blocks on an unmet aspiration.
5. **Tier badge in the DOCX.** Surfacing `established` vs `opinion` per finding is honest but adds report noise. All findings, or only where tier ≠ `established`? Recommendation: a compact badge column, full explanation on the rule card.
6. **Publishing weak spots.** §22 publishes worst-offender rules and thin families. Confirm appetite — it is the credibility move, but it is also a competitor's roadmap. Recommendation: publish; the determinism + citability moat is not the rule list, it's the method.
7. **κ threshold for `low_confidence`.** What κ below which a rule's metric is flagged unreliable? Standard interpretive cutoffs (e.g. κ < 0.6 = "moderate") are a starting point; decide against the first measured κ in Step 70.
8. **Re-opening spec-v4 §8.** The classifier threshold was marked resolved against synthetic fixtures. §18/Step 79 re-opens it against real data. Confirm this supersedes the v4 resolution rather than conflicting with it (it does; record the supersession in spec-v4 §8 with a pointer here).

---

# Part XI — What this gives the user

After v5 lands, the pitch stops being a promise and becomes a measurement:

> "Drop your legal docs. Vaulytica deterministically lints them against published authority — and on a corpus of real contracts we did not write, every rule's precision and recall is measured, published, and reproducible on your own machine. Every finding shows you the clause it matched, the statute or practice behind it, whether that's black-letter law or a drafting preference, and how often this specific rule is right. It runs offline, never leaves your browser, and gives the same answer every time. We publish where we're weak. A lawyer can sign off on the method, not just the output."

v1–v4 built a deterministic engine and a 1,000-rule library. v5 is what lets a professional stake a review on it: not "it always says the same thing," but **"it is right this often, here's the proof, and here's exactly where it isn't."** That is the difference between a clever tool and a citable one — and it is the only remaining gap between what Vaulytica claims and what it has demonstrated.
