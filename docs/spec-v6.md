# Vaulytica v6 — Workflow

> **Status:** specification, partially implemented. Steps 87–88 (findings-to-action exports + deadlines `.ics`, Part III), Steps 89–90 (version comparison engine + report + compare UI, Part I), and Steps 91–94 (public playbook schema + validator, load-a-playbook UI with augment/replace + provenance, custom-rule interpreter, and the authoring guide + worked examples — the full bring-your-own-playbook track, Part II) landed 2026-05-29. Steps 95–97 (model-clause references, Part IV; portfolio risk matrix, Part V) landed 2026-05-31. Steps 99–100 (Part VI depth: classifier re-engineering, new cross-document families) landed 2026-06-01 — see [`BUILD_PROGRESS.md`](../BUILD_PROGRESS.md). Remainder: Step 98 (extraction recall — gated behind v5 measurement, see Part IX #7), Step 101 (jurisdiction overlays), Step 102 (v6 docs + version bump).
> **Scope:** expand *what you can do with* Vaulytica, and deepen what it already does — without leaving the deterministic, no-AI, no-server, browser-only, citable posture. v6 moves the product from "drop one document, get findings" toward "fit into how a legal team actually reviews": compare versions, enforce *your own* standard, turn findings into action, and reach documents and jurisdictions currently out of scope.
> **Cousin docs:** [`spec.md`](spec.md) (v1), [`spec-v3.md`](spec-v3.md) (regulated agreements), [`spec-v4.md`](spec-v4.md) (all logically-operative legal documents), [`spec-v5.md`](spec-v5.md) (Ground Truth — accuracy & validation).
> **Relationship to v5:** v5 *measures* the engine; v6 *extends* it. They are independent and can proceed in parallel — but v6 features must be added to the v5 corpus and harness as they land, so accuracy is measured on the new surfaces too. Every v6 cross-reference to "measured" assumes the v5 harness exists.

---

# Part 0 — Intent

## §1. Why we're doing this

v1–v4 answered "what documents can Vaulytica read, and how many things can it check?" The answer is now broad: 16 sub-domains, ~1,000 rules, multi-document bundles. The product is live at `vaulytica.com` and works.

What it does *not* yet do is fit the **shape of a review**. A lawyer's day is not "open one document, read a list of issues." It is: compare the redline opposing counsel just sent against the last version; check an inbound contract against *our* negotiation positions, not a generic checklist; turn the issues into a list of things to fix and dates to track; and do that across the stack of agreements sitting in a deal folder. Vaulytica today produces an excellent single-document report and then stops at the edge of the workflow.

v6 closes that gap on the **use-case** axis the way v4 closed it on the **document-family** axis — and it does so without adding a model, a server, or a probabilistic answer. Every feature here is either a deterministic operation over the runs the engine already produces (comparison, export, aggregation) or a deterministic application of a user-supplied deterministic artifact (a custom playbook). Nothing here weakens the claim that you can reproduce the result and cite the rule.

## §2. What v6 explicitly is and is not

**v6 is:**

- **Version comparison.** Drop two versions of a document (or a clean + a redline); see exactly what each edit did to the risk surface — which findings it resolved, which it introduced, which it left untouched. (Part I.)
- **Bring-your-own playbook.** A team encodes its own positions and checklist as a structured playbook, loads it client-side, and Vaulytica enforces *that* standard alongside or instead of the built-ins. (Part II.)
- **Findings-to-action.** The obligations ledger and key dates the engine already extracts become exportable artifacts: a fix-list checklist and a deadlines calendar. (Part III.)
- **Model-clause references.** For high-severity findings, a pointer to a citation-grounded public model clause that shows "what good looks like" — a reference, never a generated redline. (Part IV.)
- **Portfolio mode.** Deepening the existing bundle: drop a folder of many contracts, get a risk matrix across them. (Part V.)
- **Depth.** Better extraction recall, a more accurate classifier, more cross-document families, and broader state-law coverage for the most state-sensitive families. (Part VI.)

**v6 is not:**

- **A drafting tool.** v6 compares, lints, enforces, exports, and *references*. It never generates contract language. The v4 non-promise stands: "v4 lints, it does not draft." Model-clause references (Part IV) surface *existing public* language with attribution; they do not write the user's clause. The line is bright and stated in §3.
- **An AI feature.** No model, no copilot, no embeddings-as-decision-logic. Comparison is a deterministic diff of two deterministic runs. Custom-playbook matching is the same pure-function engine pointed at a user-supplied playbook. Classifier improvements (Part VI) remain hand-authored, inspectable feature tables.
- **A server feature.** A custom playbook is loaded and held **in the tab**, exactly like the user's document. It is never uploaded. Export artifacts are generated client-side and downloaded. DevTools still shows zero outbound requests.
- **A UI rebuild.** The four document states, the drop zone, the theme toggle, and the inline-diagram architecture stay. New surfaces are additive: a compare affordance, a "load a playbook" affordance, export buttons on the complete state, and the portfolio matrix as a bundle-report section.

## §3. The posture filter (the gate every feature passed)

A feature ships in v6 only if it answers **yes** to all five:

1. **Deterministic?** Same inputs → byte-identical output, reproducible across machines. (A comparison is `diff(run(A), run(B))`; both runs are already deterministic, so the diff is.)
2. **No AI?** No probabilistic component anywhere in the decision path.
3. **No server?** Runs entirely in the tab; no user content leaves the browser.
4. **Citable?** Every finding still traces to a rule and a DKB-pinned source. User-supplied rules (Part II) cite the user's own authority; the engine records provenance either way.
5. **Lints, doesn't draft?** Produces analysis, comparison, enforcement, or a reference — never generated legal language.

Features that fail the filter are listed as non-promises in §24, with the reason, so the boundary is explicit rather than rediscovered per-PR.

---

# Part I — Version comparison

## §4. The use case

Opposing counsel sends a redline. The single most common real question is not "what's wrong with this document?" but **"what changed, and did it get better or worse?"** Vaulytica already produces a deterministic finding set per document; comparing two finding sets is a deterministic, posture-clean operation that answers exactly that.

## §5. What it does

- **Input:** two documents the user designates as **base** and **revised** (two drops, or a two-slot compare affordance). Both must classify to the same family (or the user confirms the pairing); a cross-family compare is refused with a clear message rather than producing nonsense.
- **Operation:** run the full engine on each independently, then compute the **finding delta**:
  - **Resolved** — fired on base, absent on revised (the edit fixed it).
  - **Introduced** — absent on base, fired on revised (the edit created a problem).
  - **Unchanged** — fired on both (still open).
  - **Carried-clean** — absent on both (no regression).
- **Risk-surface summary:** counts by severity for each bucket, so "this redline resolved 2 high-severity issues but introduced 1 critical" is the headline.
- **Clause-level delta (optional, deterministic):** where a finding's evidence span (v5 §19) exists on both sides, show the base vs revised text of the triggering clause side by side. This is a text diff of two extracted spans — deterministic, no generation.

## §6. Determinism and report

- The comparison `result_hash` is `SHA-256(base_run_hash + revised_run_hash + canonical(delta))`. Same two documents → same comparison hash, on any machine.
- Output is a **comparison report** (DOCX + JSON): cover names both versions and their hashes; an exec summary leads with the risk-surface delta; per-bucket sections list findings with their rule cards; the clause-level delta appendix where spans are available. The audit trail names both DKB versions (they must match; a mismatch is flagged, since comparing across DKB versions is not apples-to-apples).
- Edge cases: identical documents → "no change" report (not an error); base passes clean and revised passes clean → "no regression" headline; family mismatch → refusal with guidance.

---

# Part II — Bring-your-own playbook

## §7. The use case

This is the largest single expansion in v6. Today Vaulytica enforces *its* opinion. Every legal team has *its own* positions — the liability cap it will accept, the data-handling terms it requires, the clauses it always strikes. The highest-leverage thing the tool can do is enforce **the team's own standard** on every inbound contract, deterministically, without that standard ever leaving the building.

The engine is already a pure function of `(DocumentTree[], DKB, Playbook)`. A playbook is already a structured selection of rules plus thresholds. v6 makes the playbook a **first-class, user-supplied, client-side artifact** with a public schema.

## §8. What it does

- **A public playbook schema.** The internal playbook JSON shape becomes a documented, versioned, public schema (`docs/v6/playbook-schema.md` + a published JSON Schema). It covers: rule selection from the built-in catalog, per-rule severity overrides, threshold parameters (e.g. acceptable cap multiple, max notice-period days), required-clause assertions, and a `custom_rules` block (see §9).
- **Load a playbook in the tab.** A "use your own playbook" affordance accepts a local `.json` playbook file. It is validated against the schema (`zod`, already a dependency) and held in memory for the session. It is **never uploaded**; the privacy guard (Part VII / v5 §VIII) asserts no playbook bytes leave the tab.
- **Enforcement.** The engine runs the user's playbook exactly as it runs a built-in one. Findings from user-selected rules carry a provenance marker (`source: "custom-playbook"`) so the report distinguishes "your standard flagged this" from "Vaulytica's catalog flagged this."
- **Compose, don't replace by default.** The user chooses: *augment* (built-in playbook + custom positions) or *replace* (only the custom standard). Augment is the default; replace is explicit.

## §9. Custom rules — the bounded, deterministic kind

The schema must let a team encode positions Vaulytica's catalog does not, **without** opening a Turing-complete rule language (which would break determinism guarantees and auditability). The `custom_rules` block is a constrained, declarative DSL over the same extracted facts the built-in rules use:

- **Predicate kinds:** `clause_present` / `clause_absent` (keyed by a labeled pattern or a section heading), `numeric_threshold` (on an extracted amount/duration, e.g. "liability cap ≥ 12× fees"), `defined_term_present`, `governing_law_in {allowed set}`, `cross_ref_resolves`. Each maps to an existing extractor output.
- **Each custom rule carries its own citation field** — the team's internal policy reference or a public authority — so the citability invariant holds for user rules too. A custom rule with no citation is allowed but the report marks it `uncited (team policy)`, never silently.
- **No free code execution.** Predicates are data, evaluated by the engine's interpreter, so a custom playbook is as deterministic and auditable as a built-in one and cannot exfiltrate or compute arbitrarily.

## §10. Authoring and validation

- **`docs/v6/authoring-a-playbook.md`** — a guide with worked examples (a SaaS-buyer's standard, a vendor's red-lines).
- **A client-side validator** in the UI: load → schema check → human-readable errors → preview of which catalog rules the playbook selects before running. A malformed playbook never silently mis-runs.
- **Versioning:** a playbook declares the `catalog_version` it targets; loading a playbook authored against an older catalog warns about rules that have since been retired (ties into v5 §14 retirement) rather than failing opaquely.

---

# Part III — From findings to action

## §11. The use case

A finding list is the start of work, not the end. The two artifacts a reviewer actually needs next are **a list of things to fix** and **a list of dates to track**. The engine already extracts both — the obligations ledger and the temporal facts (effective dates, terms, renewal/auto-renew, notice windows). v6 turns them into downloadable, tool-agnostic artifacts. This is the cheapest high-value feature in the spec: the data exists, only the export is new.

## §12. What it does

- **Fix-list export.** The findings, ordered by severity, as a checklist — Markdown and CSV. Each row: rule ID, severity, tier (v5 §12), the clause/section, the plain-language claim, and (where available) the model-clause reference (Part IV). This is the artifact a reviewer pastes into a comment thread or a tracker.
- **Deadlines calendar export.** Extracted dated obligations — effective date, term end, renewal/auto-renew trigger, notice-by dates, payment milestones — as an **`.ics` file** the user imports into any calendar. Each event names the source clause and is tagged with a lead-time reminder for notice windows (e.g. "auto-renew notice due 60 days before term end" becomes a dated event with the deadline computed deterministically from the extracted term and notice period).
- **Obligations ledger export.** The existing ledger as CSV: obligor, obligation, trigger, deadline, source clause — so it drops into a spreadsheet or contract-management system.

## §13. Determinism and scope

- All exports are pure functions of the run; same run → byte-identical export (the `.ics` uses a fixed, deterministic UID derivation and excludes wall-clock generation timestamps, same discipline as `result_hash`).
- Scope guard: the calendar export computes dates only where the engine extracted an unambiguous date or a date arithmetic it can do deterministically (term + notice period). Ambiguous or unparseable dates are listed in the fix-list as "date present but not machine-readable — verify manually" rather than guessed. No fabricated dates, ever.

---

# Part IV — Model-clause references

## §14. The use case and the bright line

The most common follow-up to "this clause is defective" is "so what should it say?" Vaulytica does **not** draft. But it can do the posture-clean adjacent thing: **point to an existing public model clause** that the finding's DKB source already references, with full attribution — "what good looks like," not "here is your clause."

The bright line (restating §3.5): v6 surfaces a *reference to public model language* (Common Paper, NVCA model docs, Bonterms, statutory safe-harbor text, etc.) that is already in the DKB pipeline. It links/quotes with attribution. It never composes language tailored to the user's document, never fills in party names or terms, never "rewrites." The user adapts the public model themselves or hands it to their lawyer.

## §15. What it does

- For findings whose rule has an associated public model clause in the DKB, the rule card (v5 §21) gains a **"reference model clause"** section: the attributed public text, its source, and its license.
- Coverage is honest: only rules with a genuine public model reference get one. The rest say nothing rather than inventing a reference. A coverage count is published (how many rules carry a model reference), same anti-silent-truncation discipline as v5 §10.
- This depends on the DKB carrying model-clause nodes; Part IV includes the DKB-node and fetcher work to source them from the existing public catalogs the build pipeline already pulls.

---

# Part V — Portfolio mode (deepening the bundle)

## §16. The use case

v4 ships multi-document bundles with a consolidated report and cross-document consistency. The next step for a team is the **portfolio question**: "across these 40 vendor agreements, which ones lack a liability cap? which auto-renew in the next 90 days? which are missing a DPA?" The bundle engine already runs each document; v6 adds a deterministic aggregation layer on top.

## §17. What it does

- **Risk matrix:** a documents × key-findings grid in the bundle report — rows are documents, columns are a curated set of high-signal checks (cap present, auto-renew, governing law, DPA companion present, breach-notice window), cells are pass/fail/N-A with the same shading discipline as the v3 compliance matrix.
- **Portfolio rollups:** counts and lists — "12 of 40 lack a liability cap," "5 auto-renew within 90 days (with dates, from Part III's extraction)."
- **Deterministic:** the matrix is a sorted, canonical projection of the per-document runs; the portfolio `result_hash` extends the existing bundle fingerprint. Same folder → same matrix.
- **Scale guard:** a stated, enforced cap on bundle size (already exists per v4 §8); beyond it, the UI tells the user the cap rather than silently truncating, and the report notes how many documents were included.

---

# Part VI — Depth (deepening what exists)

These are not new use cases; they make every existing one more correct. They interlock with v5: v5 measures where the engine is weak, v6 Part VI acts on it. Sequence Part VI work behind the relevant v5 measurements where possible, so effort targets measured weakness rather than guessed weakness.

## §18. Extraction recall

- Improve the extractors most downstream rules depend on — amounts, dates, parties, obligations, defined terms, cross-references — prioritized by which extractor failures the v5 harness shows costing the most recall. Each improvement is a deterministic parser change with its own fixtures and a measured before/after on the corpus.

## §19. Classifier accuracy

- Lift sub-domain top-1 above its current ~70% (per the maintainer's build-frontier note) by re-engineering the feature table against real documents (v5 §18) — the known confusions (healthcare→privacy, ip-licensing→equity, settlement→commercial, compliance→employment) are the named targets. Remains a hand-authored, inspectable table; no model.

## §20. Cross-document consistency families

- Add CROSS-* families beyond v4's seven where real bundles show recurring inconsistencies (e.g. cross-document defined-term *definition* drift vs mere usage drift; indemnity-cap stacking across an MSA + order form; survival-clause conflicts). Each new family ships with a dedicated bundle fixture, as v4 required.

## §21. Jurisdiction overlays

- Broaden state-law coverage beyond CA/NY/TX/FL/IL for the families where state law dominates outcomes — employment (non-compete enforceability), residential leases (deposit/notice rules), lending (usury caps). Use the consolidated per-(sub-domain × state) overlay-node pattern v4 §open-question-4 proposed, so coverage grows without a 50 × N node explosion. Honest `N/A` for uncovered states stays the default, never a silent wrong answer.

---

# Part VII — Determinism and privacy preservation

v6 must not weaken the two load-bearing claims, and it adds a new surface (user-supplied playbooks) that needs its own guard.

- **Custom playbooks stay in the tab.** Loaded, validated, and held client-side exactly like the user's document. The privacy guard (extending the v5 §VIII / bundle-excludes-corpus test family) asserts no playbook bytes appear in any network request. The threat-model doc gains a "user-supplied playbook" section: same posture — client-side, no exfil.
- **Every new operation is deterministic.** Comparison hash, export bytes, portfolio matrix, and custom-playbook runs all follow the existing canonicalization discipline (sorted keys, wall-clock excluded). Each gets a two-run byte-identical test, the same contract `result_hash` already honors.
- **Citability holds.** Built-in findings cite the DKB. Custom-rule findings cite the team's reference or are marked `uncited (team policy)`. Model-clause references (Part IV) carry source + license. No finding is ever uncited *and* unmarked.
- **No AI.** Restated because it is the moat: nothing in v6 introduces a probabilistic component. Comparison is set arithmetic over deterministic runs; custom rules are a declarative DSL; classifier work is a feature table.

---

# Part VIII — Build plan

Each step is a prompt-sized unit, continuing the global numbering after v5's Step 86. (v6 and v5 can interleave; where a v6 step references "measured," it assumes the corresponding v5 step has landed.) Verification gate for every step: `npm run typecheck && lint && test && build` green.

Ordered by value-to-effort, fastest high-value first:

| # | Step | Output | Tier |
|---|------|--------|------|
| 87 | Findings-to-action exports ✅ | Fix-list (Markdown + CSV) + obligations CSV from the existing ledger; deterministic, two-run-identical tests. **Done 2026-05-29** (`src/report/exports.ts`). | Quick win |
| 88 | Deadlines `.ics` export ✅ | Deterministic calendar from extracted temporal facts + computed notice deadlines; ambiguous-date guard; fixtures. **Done 2026-05-29** (`src/report/exports.ts`). | Quick win |
| 89 | Version comparison engine ✅ | `diff(run(base), run(revised))` → resolved/introduced/unchanged buckets + carried-clean count; comparison `result_hash`; family-mismatch refusal. **Done 2026-05-29** (`src/report/compare.ts`). | Flagship |
| 90 | Version comparison report + UI compare affordance ✅ | Comparison DOCX + JSON; compare affordance + `comparison-complete` state; clause-level span delta appendix. **Done 2026-05-29** (`src/report/compare-docx.ts`, `src/ui/`). | Flagship |
| 91 | Public playbook schema + JSON Schema + validator ✅ | Documented, versioned schema; `zod` validator; `docs/v6/playbook-schema.md` + `playbook.schema.json`. **Done 2026-05-29** (`src/playbooks/custom-playbook.ts`). | Flagship |
| 92 | Load-a-playbook UI + augment/replace modes + provenance ✅ | Client-side load + validate + preview; `source: custom-playbook` on findings; privacy guard test. **Done 2026-05-29** (`src/ui/playbook-panel.ts`, `src/playbooks/custom-run.ts`, pipeline `custom_playbook` option, `tests/integration/custom-playbook-privacy.test.ts`). | Flagship |
| 93 | Custom-rules declarative DSL + interpreter ✅ | Bounded predicate set over existing extractor outputs; per-rule citation; determinism + auditability tests; end-to-end corpus harness. **Done 2026-05-29** (`src/playbooks/custom-interpreter.ts`). | Flagship |
| 94 | Authoring guide + worked examples ✅ | `docs/v6/authoring-a-playbook.md`; SaaS-buyer + vendor red-line example playbooks committed. **Done 2026-05-29** (`docs/v6/authoring-a-playbook.md`, `docs/v6/examples/*.playbook.json`, validated by `src/playbooks/example-playbooks.test.ts`). | Flagship |
| 95 | DKB model-clause nodes + fetchers ✅ | Model-clause node type + zod schema; curated catalog of public model clauses (Common Paper, Bonterms, EU SCCs); honest coverage count. **Done 2026-05-31** (`src/dkb/model-clauses.ts`). | Deepen |
| 96 | Model-clause references on rule cards ✅ | "Reference model clause" section on each finding's rule card (DOCX) + `model_clause_references` in the JSON report; coverage published in the audit trail; honest (only where a real reference exists); `result_hash` unchanged (references live outside the run). **Done 2026-05-31** (`src/report/docx.ts`, `src/report/json.ts`). | Deepen |
| 97 | Portfolio risk matrix + rollups ✅ | Documents × key-checks matrix in the bundle report (DOCX section + `portfolio` in bundle JSON); rollups; `portfolio_fingerprint` extends the bundle fingerprint; 50-row scale guard with no silent truncation. **Done 2026-05-31** (`src/report/portfolio.ts`). | Deepen |
| 98 | Extraction recall pass | Targeted extractor improvements against v5-measured weakness; before/after on corpus. | Depth |
| 99 | Classifier feature-table re-engineering ✅ | Lifted sub-domain top-1 from 53/75 (70.7%) to 75/75 (100%) on the labeled golden corpus by adding corpus-exclusive distinguishing phrases to the four named confusions (healthcare→privacy, ip-licensing→equity, settlement→commercial, compliance→employment) plus equity and privacy; remains a hand-authored, inspectable table; false-positive ceiling dropped to 0.000. **Done 2026-06-01** (`dkb/v4/sub-domain-features.json`, `tests/v4/extract/classifier-accuracy.test.ts`, recalibrated `classifier-calibration.test.ts`). | Depth |
| 100 | Cross-document families expansion ✅ | Three new CROSS-* families with dedicated bundle fixtures: CROSS-DEFTERM-002 (defined-term *usage* drift vs the existing *definition* drift), CROSS-INDEMNITY-001 (indemnity-cap stacking across MSA + order form), CROSS-SURVIVAL-001 (confidentiality survival-period conflict). Ten v4 CROSS-* rules total. **Done 2026-06-01** (`src/engine/consistency/rules/v4/cross-doc-rules.ts`, `tests/golden/v4/bundles/{defterm-usage-drift,indemnity-cap-stacking,survival-conflict}/`). | Depth |
| 101 | Jurisdiction overlay expansion | Per-(sub-domain × state) overlays for employment / residential lease / lending; honest N/A elsewhere. | Depth |
| 102 | v6 docs + threat-model update + launch checklist + version bump | `docs/v6/` overview + per-feature docs; threat-model "user-supplied playbook" section; v6 launch checklist; bump to 6.0.0; tag v6.0.0. | Close |

Total work: **16 build steps.** The quick wins (87–88) and the first flagship (89–90, comparison) are posture-trivial — pure deterministic operations over runs the engine already produces — and could ship in days. The custom-playbook track (91–94) is the largest and highest-leverage; it is the feature most likely to change who adopts the tool (from individuals to teams enforcing a standard).

---

# Part IX — Open questions for the maintainer

1. **Priority order.** The build plan recommends quick-wins → comparison → custom playbooks → references → depth. If lawyer feedback (your in-flight outreach) points hard at one use case, resequence around it — the four flagship tracks (I–IV) are independent. Which do your lawyers ask for first? (My prior: custom playbooks and comparison, in that order, are what turn it from a personal tool into a team tool.)
2. **Custom-rule DSL surface.** §9 proposes a bounded declarative predicate set. Too small and teams can't express their positions; too large and it stops being auditable/deterministic. Start minimal (the §9 list) and grow on demand, or design the fuller surface up front? Recommendation: start minimal, grow from real custom-playbook requests.
3. **The model-clause line.** Part IV references public model clauses but never drafts. Is even *quoting* an attributed public model clause too close to the "we don't draft" promise for comfort, or is the reference-with-attribution framing clearly on the right side? Recommendation: ship it, framed explicitly as reference-not-redline; it is high-value and the attribution keeps it honest. But it is the one feature nearest the line, so it's your call.
4. **Comparison input pairing.** Auto-detect base vs revised (by content heuristics) or always require the user to designate? Recommendation: always require designation — guessing which is newer is exactly the kind of probabilistic call the product avoids.
5. **Playbook sharing.** Custom playbooks stay in the tab by design. Do teams want a way to *share* a playbook internally (a file they pass around), and is a plain exported `.json` enough, or do they want a signed/versioned playbook artifact? Recommendation: plain `.json` first; signing is a later step if asked.
6. **Portfolio scale cap.** What's the honest upper bound on bundle size for the 4G-mobile performance budget (v4 §17)? Re-measure once the matrix aggregation lands; surface the cap in the UI.
7. **v5/v6 interleave.** Some v6 depth steps (98, 99) are strictly better after the corresponding v5 measurement exists. Hard-sequence them behind v5, or let them proceed on the synthetic fixtures and re-measure later? Recommendation: let exports/comparison/custom-playbooks (the use-case expansion) proceed independently of v5; gate only the *depth* steps (Part VI) behind v5 measurement so they target real weakness.

---

# Part X — What this gives the user

After v6 lands, the pitch grows from "a linter for one document" to "a review workflow you can still cite":

> "Drop a contract and get deterministic, citation-grounded findings — then do the things review actually needs. Compare opposing counsel's redline against your last version and see exactly what each edit did to your risk. Load *your team's own* positions as a playbook and enforce them on every inbound contract — your standard never leaves your browser. Turn the findings into a fix-list and the deadlines into a calendar. Drop a whole deal folder and get a risk matrix across it. Still deterministic, still no AI, still nothing leaves the tab, still every finding cites a rule."

v4 widened *what* Vaulytica reads. v5 proves *how well* it reads. v6 makes it *useful in the workflow* — comparison, your-own-standard enforcement, action exports, portfolio view — while every feature passes the same five-part posture filter that has been the moat since v1. The promise is unchanged: you can reproduce the result, and you can cite the rule.
