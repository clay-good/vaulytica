# Vaulytica v12 — Cross-Document Posture Coherence

> **Status:** **Thrusts A, B & C implemented and shipped (A: 9.7.0; B+C: 9.8.0).** This spec extends the v10 **Negotiation Posture** feature along the v4 **cross-document** axis: it reports how a team's posture sits across a *bundle* of documents — whether every document holds the same rung on each negotiation front, or one undercuts the position. It continues the global step numbering after v11's Step 180, beginning at **Step 181**. **Thrust A** — the pure [`bundlePostureCoherence`](../src/report/posture-coherence.ts) coherence engine, its headless surface in `vaulytica analyze --posture` over a bundle, and the CI gate `vaulytica analyze --posture --fail-on-divergence` — is live. **Thrust B** wires a per-document posture through the browser bundle pipeline and renders a mobile-safe coherence card; **Thrust C** renders a trailing "Posture Coherence" section in the consolidated bundle DOCX — both additive, both omitted when no positions are supplied (every existing bundle golden byte-unchanged).
> **Scope:** one idea, sitting exactly at the intersection of two shipped axes. v4 reasons across a **bundle** (the MSA, the SOW, the order form, the DPA — and the cross-document inconsistencies between them). v10 scores a **single** document against the team's tiered ladder (which rung each dimension meets: ideal / acceptable / below-floor / not-stated). A deal is rarely one document, and the question a deal lead most needs answered across a package is neither of those alone: *does every document in this deal hold the same line on each front, or does one of them quietly give away the cap I won in the MSA?* v12 answers it by diffing one v10 posture per document — no new extractor, no new predicate, no fuzzy logic.
> **Posture (unchanged, non-negotiable):** deterministic (same postures + same document order → identical `coherence_hash`, on any machine, forever), no AI / no probabilistic path, no server (every document and the coherence stay on the user's machine), citable (the coherence is derived from one posture per document, each of which already cites that document's own clause and the team's own playbook), lints / references / positions — but never drafts, and never renders a legal conclusion. The coherence is **advisory**: it states where each front sits across the team's own ladder, never that a term became legally adequate, enforceable, or that the weakest document legally governs. Every step passes the §3 filter or it does not ship.
> **Cousin docs:** [`spec.md`](spec.md) (v1, the linter), [`spec-v4.md`](spec-v4.md) (Depth & Breadth — **the cross-document axis**, §11 the consolidated bundle report), [`spec-v10.md`](spec-v10.md) (Negotiation Posture — **the posture axis** this deepens), [`spec-v11.md`](spec-v11.md) (Posture Movement — the version-over-version sibling on the *other* derived axis), [`spec-v8.md`](spec-v8.md) (Reach — the headless CLI this rides on). Progress in [`BUILD_PROGRESS.md`](../BUILD_PROGRESS.md).

---

# Part 0 — Intent

## §1. Why we're doing this

v10 gives a negotiator a snapshot of *one* document: drop a draft, read which rung of your ladder each dimension meets. v11 tracks that snapshot *version-over-version*: when the counterparty sends a counter, which way did each front move? Both reason about a single document over time.

But a deal is a **package**, not a document. The liability cap you won in the MSA can be silently re-capped in the order form. Your Delaware governing-law clause can be contradicted by a Texas one in the SOW. Each document, read in isolation, may look fine — and the v10 posture of each, read in isolation, *is* fine. The risk lives in the **gap between** them, and in a deal package the **weakest** document usually governs your exposure: a cap that is ideal in the MSA but below-floor in the order form leaves you protected only to the order form's floor.

Today, to catch this, a deal lead runs each document's posture and eyeballs the cards side by side, dimension by dimension, hunting for a rung that disagrees. That is manual, error-prone, and exactly the kind of deterministic bookkeeping a linter should do. v12 does it: given one v10 posture per document — all computed by the v10 evaluator against the **same** positions — it classifies each dimension's coherence across the bundle:

- **aligned** — two or more documents state the front and they all land on the *same* rung. The position is held consistently across the package.
- **divergent** — two or more documents state the front and they land on *different* rungs (e.g. *ideal* in the MSA, *below-floor* in the order form). The bundle disagrees with itself.
- **single** — exactly one document states the front; the others are silent. There is nothing cross-document to compare.
- **unstated** — no document states the front (all `unevaluable`). Silence is never a divergence.

And for every front that *is* stated somewhere, v12 surfaces the **binding floor**: the weakest stated rung across the bundle and the document(s) carrying it — the front a deal lead most needs to reconcile before signing.

The deal lead runs the package once and reads, on every front at once: *liability cap divergent — ideal in the MSA, below-floor in the order form; binding floor below-floor in the order form, reconcile before signing; governing law aligned at ideal across all three — good; indemnity stated only in the MSA — confirm the SOW inherits it.* The single across-the-package question, computed without a model and without a server.

## §2. What v12 is and is not

**It is:**
- A **pure diff of N v10 postures.** [`bundlePostureCoherence(documents)`](../src/report/posture-coherence.ts) takes one `{ document, posture }` per document and returns a `PostureCoherence`: per-dimension `{ tiers, weakest_tier, weakest_documents, coherence }`, coherence counts, and its own `coherence_hash`. No document parsing, no extraction, no predicate evaluation happens here — the classification is already done; v12 only compares the tier labels across documents.
- A **well-ordered binding floor.** It reuses the single `TIER_RANK` table v11 introduced (ideal=3 > acceptable=2 > below-acceptable=1; `unevaluable` unranked) to find the weakest *stated* rung. The binding floor is never an unstated front — "not stated" is not a point on the ideal→floor axis (the §3 honesty contract).
- An **advisory, additive surface.** The `coherence_hash` is namespaced apart from each document's `result_hash` and the bundle fingerprint; computing it moves no golden. It surfaces in the headless `analyze --posture` bundle output and gates CI via `--fail-on-divergence`.

**It is not:**
- A **new classifier.** v12 introduces no new matching logic. A coherence is decided by comparing tier strings the v10 evaluator already produced. The v6 false-positive surface and the v10 unevaluable-honesty surface both carry over unchanged because nothing new is measured.
- A **renderer of legal conclusions.** A coherence reports *where each front sits across the team's own ladder*, never "the order form's cap legally governs" or "this term is enforceable." Which document legally controls on a conflict is a fact- and order-of-precedence question (often answered by the documents' own integration clauses) — the team's judgment, not v12's. v12 reports the *rung* spread and names the weakest; it does not adjudicate precedence.
- A **dishonest comparison of unstated data.** A dimension a document does not state is `unevaluable`, which is unranked: it is never folded into a divergence and never lowers the binding floor. A front no document states is `unstated`, and a front only one document states is `single` — never a false divergence.
- A **cross-ladder comparison.** A coherence is meaningful only when every posture was computed against the **same** positions. The CLI applies the one active custom playbook to every document in the bundle; comparing postures computed from different ladders is out of scope (and would be nonsense, the same way v6 refuses a cross-family finding compare and v11 refuses a cross-ladder movement).

## §3. The posture filter (the gate every step passes)

Identical to v6–v11 §3, restated because v12 introduces a new output category (a *spread* of rungs across documents, and a *binding floor*) — a place an over-claim is easy to make by accident:

```
Deterministic?  same postures + same document order → identical coherence_hash,
                on any machine, forever.
No AI?          no probabilistic component anywhere in the path (it is a set of
                string compares + a min over a ranked table).
No server?      every document and the coherence stay on the user's machine.
Citable?        the coherence derives from one posture per document, each citing
                that document's own clause and the team's own playbook.
Lints/positions, not drafts?  classifies a spread across documents — never
                writes, proposes, redacts, renders a legal conclusion, or
                adjudicates which document legally controls.
```

Three v12-specific corollaries:
- **1. The binding floor is a well-ordered minimum.** The weakest stated rung is the `min` over the same `TIER_RANK` table v11 ranks improved/regressed by. Same postures → same floor, byte-for-byte. The floor is reported over *stated* documents only; an unstated document is unranked and never the floor.
- **2. Unstated is never a divergence and never a floor.** A front is `divergent` only when two or more documents *state* it on different rungs. A front no document states (`unstated`) or only one document states (`single`) is reported honestly and never trips the gate. The v10 "below-floor only on evaluable data" honesty extends to "a divergence is reported only when two or more documents are stated."
- **3. Advisory, never a precedence conclusion.** A coherence reports a spread on the team's own ladder and names the weakest document. It never asserts that the weakest document *legally governs*, that a term became adequate, enforceable, market, or required — order-of-precedence across a bundle is the team's judgment, encoded in the documents' own integration clauses.

## §4. How the thrusts sequence

**The coherence engine and its headless surface (A) land first and complete the idea on the axis it most naturally lives.** The classifier is a pure function over N existing postures, so it sits on a fully-proven base and adds no extractor, no predicate, and no fuzzy logic. The headless `analyze --posture` command already computes one posture per document when run over a bundle (a directory or glob); Thrust A collects those postures after the per-document loop and reports the coherence — a render-side, additive addition that moves no existing per-document JSON, golden, or `result_hash`. The CI gate `--fail-on-divergence` follows the exact `--fail-on` / `--fail-on-regression` pattern.

**The browser-UI bundle card and the consolidated-DOCX bundle section land next (Thrust B/C, shipped 9.8.0).** Before B, the browser bundle flow did not compute a per-document posture — posture was a single-document surface in the UI. Thrust B threads the active custom playbook into the bundle pipeline so each document is classified against the **same** positions, collects the postures into a `bundlePostureCoherence`, and renders a mobile-safe coherence card in the bundle-complete state (reusing the v10 `np-*` overflow-wrap styles + a `pc-*` divergence color). Thrust C renders a trailing "Posture Coherence" section in the consolidated bundle DOCX. Both add no new measurement, both are omitted when no positions are supplied (every existing bundle golden byte-unchanged), and the per-document engine run is untouched — the custom playbook contributes only its posture positions to the bundle, exactly as v11 sequenced its DOCX section behind its engine.

---

# THRUST A — THE COHERENCE ENGINE & HEADLESS SURFACE (shipped, 9.7.0)

These steps add the `bundlePostureCoherence` classifier and wire it into the headless `analyze` bundle path and a CI gate. Each coherence is derived from one posture per document, each of which cites that document's own clause and the team's own playbook.

| # | Step | Output | Tier |
|---|------|--------|------|
| 181 ✅ | Coherence engine | [`bundlePostureCoherence`](../src/report/posture-coherence.ts): a pure, deterministic per-dimension cross-document classifier (aligned / divergent / single / unstated), reusing v11's exported `TIER_RANK` to compute the **binding floor** (the weakest stated rung + the document(s) carrying it), coherence counts, and a `coherence_hash` namespaced apart from every `result_hash`. A `hasDivergence(coherence)` predicate mirrors v11's `postureRegressed`. Unit + property-style tests across every coherence kind, the binding floor, determinism, and document-order sensitivity. | Coherence |
| 182 ✅ | Headless coherence | The CLI `analyze` command, run with `--posture` over a **bundle** (≥2 documents), collects each document's posture and prints a "Cross-document posture coherence" summary: the per-kind counts, one ⚠ line per divergent front (the rung spread + the binding floor + the document carrying it), and the `coherence_hash`. A single-document run emits no coherence (nothing to compare). | Coherence |
| 183 ✅ | Divergence gate | The CLI `analyze` command accepts `--fail-on-divergence` (requires `--posture`): it exits non-zero (code 2) when any front is **divergent** — two or more documents stating the same front on different rungs. The gate is the well-ordered spread only; a front only one document states (`single`) or no document states (`unstated`) is reported but never trips it (§3 honesty — silence is not a disagreement). Reported alongside `--fail-on`; either tripping sets exit 2. | Coherence |

---

# THRUST B — THE BROWSER-UI COHERENCE CARD (shipped, 9.8.0)

These steps wire a per-document posture through the browser bundle pipeline and render the coherence in the bundle-complete view. No new measurement: the per-document engine run is untouched; the active custom playbook contributes only its posture positions to the bundle.

| # | Step | Output | Tier |
|---|------|--------|------|
| 184 ✅ | Per-document posture in the bundle | [`prepareBundle`](../src/ui/pipeline.ts) evaluates `evaluateNegotiationPosture` for each document when the active custom playbook defines `negotiation_positions` — every document classified against the **same** positions, independent of which rule set drove its engine run. Stored on `BundlePerDocument.negotiation_posture` (own `posture_hash`, outside `result_hash`). [`runBundleReport`](../src/ui/pipeline.ts) collects the postures and computes a `bundlePostureCoherence` when every document carries one (a bundle is always ≥2 documents). [main.ts](../src/ui/main.ts) threads the active custom playbook into `runBundlePipeline`. | Coherence |
| 185 ✅ | Bundle-complete coherence card | The bundle-complete state renders a mobile-safe "Posture coherence" card: the per-kind counts, one card per front (the rung spread across the documents + the binding floor naming the weakest document), color-coded by a `pc-*` left border (green aligned, red divergent, blue stated-by-one, grey unstated), reusing the v10 `np-*` overflow-wrap styles. Hidden when no coherence was computed. Verified vertical-scroll-only 320–1280px + WCAG 2 AA. | Coherence |

---

# THRUST C — THE CONSOLIDATED-DOCX SECTION (shipped, 9.8.0)

| # | Step | Output | Tier |
|---|------|--------|------|
| 186 ✅ | Bundle DOCX "Posture Coherence" section | [`buildBundleDocxReport`](../src/report/bundle.ts) renders a trailing, optional "Posture Coherence" section: the per-kind counts + a color-coded table (Front · Coherence · per-document rung · binding floor). Omitted entirely when no `posture_coherence` is supplied, so every existing bundle golden is byte-unchanged. Advisory — it names the weakest document but never adjudicates which document legally governs. | Coherence |

---

# Part XV — Build plan

Each step is a prompt-sized unit, continuing the global numbering after v11's Step 180. Verification gate for every step: `npm run typecheck && lint && test && build` green; the v7 coverage/parity/property gates, the v8 fuzz + citation gates, the v9 no-wall-clock gate, and the responsiveness e2e (every view-state vertical-scroll-only 320–1280px, WCAG 2 AA) stay green.

Status legend: **✅ shipped** · ⬜ proposed.

| # | Step | Output | Tier |
|---|------|--------|------|
| 181 ✅ | Coherence engine | `bundlePostureCoherence` reusing v11's `TIER_RANK`; per-dimension aligned/divergent/single/unstated; binding floor; `coherence_hash`. `hasDivergence` predicate. Unit tests across every kind + determinism + order sensitivity. | Coherence |
| 182 ✅ | Headless coherence | CLI `analyze --posture` over a bundle → a "Cross-document posture coherence" summary (counts + per-divergent-front spread + binding floor + `coherence_hash`). | Coherence |
| 183 ✅ | Divergence gate | CLI `analyze --posture --fail-on-divergence` → exit 2 when any front diverges across the bundle. | Coherence |
| 184 ✅ | Per-document posture in the bundle | `prepareBundle` evaluates a posture per document against the same positions; `runBundleReport` collects them into a `bundlePostureCoherence`; `main.ts` threads the custom playbook into the bundle pipeline. | Coherence |
| 185 ✅ | Bundle-complete coherence card | The bundle-complete state renders a mobile-safe `pc-*` coherence card (counts + per-front rung spread + binding floor). Verified 320–1280px + WCAG 2 AA. | Coherence |
| 186 ✅ | Bundle DOCX "Posture Coherence" section | `buildBundleDocxReport` renders a trailing color-coded coherence table, omitted when no positions are supplied. | Coherence |

Total work: **6 build steps (181–186), all shipped.** Every step is additive — an analyze run with no positions, or a bundle with no active posture playbook, yields no coherence, so every existing per-document `result_hash` and bundle golden is byte-unchanged.

---

# Part XVI — Principled deferrals

- **A browser-UI bundle coherence card.** ✅ **Shipped (Thrust B, 9.8.0).** The browser bundle flow now computes a per-document posture when the active custom playbook defines positions: [`prepareBundle`](../src/ui/pipeline.ts) evaluates `evaluateNegotiationPosture` for each document against the same positions (independent of the per-doc engine run, which is untouched), [`runBundleReport`](../src/ui/pipeline.ts) collects them into a `bundlePostureCoherence`, and the bundle-complete state renders a mobile-safe "Posture coherence" card (reusing the v10 `np-*` overflow-wrap styles + a `pc-*` divergence color), each front showing the rung spread + the binding floor. Omitted when no positions are supplied. Verified vertical-scroll-only 320–1280px + WCAG 2 AA.
- **A consolidated-DOCX "Posture Coherence" section.** ✅ **Shipped (Thrust C, 9.8.0).** [`buildBundleDocxReport`](../src/report/bundle.ts) renders a color-coded per-front coherence table (Front · Coherence · per-document rung · binding floor) as a trailing optional section, omitted when no positions are supplied so every bundle golden is byte-unchanged. Advisory — it reports the rung spread and names the weakest document, never which document legally governs (§3 corollary 3).
- **Order-of-precedence reconciliation.** v12 names the *weakest rung* and the document carrying it; it deliberately does **not** assert which document *legally governs* on a conflict. That is an order-of-precedence judgment, often answered by the documents' own integration/precedence clauses — attorney-gated territory v5/v7 already defer. v12 reports the spread and stops at the §3 corollary-3 bright line.
- **Cross-document posture movement.** Computing how a bundle's coherence *moved* version-over-version (the v11 axis composed with this one — "the order form's cap regressed relative to the MSA between rounds") sits on top of both derived axes and is a larger surface. Noted for a future spec, as v11 noted this one.

---

# Part XVII — Open questions for the maintainer

1. **Rank `unevaluable` as the bottom rung for the floor?** Today the binding floor is the weakest *stated* rung; an unstated document does not lower it. Recommendation: **keep it unranked** — the v10 §3 contract is explicit that "not stated" must never be conflated with "below floor," and a deal lead reads a `single`/`unstated` front as "confirm the other documents inherit this" rather than a false floor at the bottom.
2. **Gate on `single` (a front only one document states)?** A front stated in the MSA but silent in the SOW could be a genuine gap (the SOW should inherit the cap but doesn't restate it). Recommendation: **report, never gate, in v12** — whether silence is a gap or correct inheritance-by-reference is a precedence judgment (the §3 corollary-3 bright line); a team that wants to gate on it composes from the `coherence.counts.single`.

---

# Part XVIII — What this gives the user

- **Your ladder, held across the whole deal.** Encode your positions once. Drop the MSA, the SOW, and the order form together — and the analyze run tells you, on every front at once, whether the package holds the same line or one document undercuts it: aligned, divergent, stated-by-one, or unstated. The snapshot v10 gave you for one document, and the trajectory v11 gave you across versions, becomes the **coverage across the package** you actually sign.
- **The binding floor, named.** For every front some document states, v12 names the weakest rung and the document carrying it — the cap that actually governs your exposure when the order form quietly re-caps what the MSA won. The thing a deal lead hunts for by eye, computed deterministically.
- **The same five promises.** Deterministic, no AI, no server, citable, never drafts — every line of v12 passes the §3 gate. The coherence derives from one posture per document, each citing your own playbook and that document's own clause; an unstated front is never a false divergence; and the thing you most need across a package — *does every document hold my line* — is computed without a model and without a server.
