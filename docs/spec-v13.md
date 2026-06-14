# Vaulytica v13 — Cross-Document Posture Movement

> **Status:** **Thrust A implemented and shipped (9.9.0).** This spec sits at the intersection of v11's **version-comparison** axis and v12's **cross-document** axis: it reports how a deal package's posture *coherence* moved between two rounds. It continues the global step numbering after v12's Step 186, beginning at **Step 187**. **Thrust A** — the pure [`compareCoherence`](../src/report/coherence-movement.ts) movement classifier, its headless surface in `vaulytica analyze --posture --baseline <bundle>`, and the CI gate `--fail-on-coherence-regression` — is live. **Thrust B** (a browser-UI two-round bundle card) and **Thrust C** (a DOCX section) are proposed; both wait on a two-bundle comparison surface that does not yet exist in the UI, and both are additive (omitted when no baseline is supplied).
> **Scope:** one idea, sitting exactly at the intersection of two already-derived axes. v11 diffs two postures of **one** document across **two** versions (the movement). v12 diffs N postures across a **bundle** at **one** round (the coherence). A negotiation is a *sequence of packages*, and the question a deal lead most needs answered round-over-round across a package is neither of those alone: *when the counterparty sends a revised package, did the weakest document on each front — the rung that actually governs my exposure — get better or worse, and did any front the package agreed on quietly split apart?* v13 answers it by diffing two v12 coherences — no new extractor, no new predicate, no fuzzy logic.
> **Posture (unchanged, non-negotiable):** deterministic (same two coherences + same front order → identical `movement_hash`, on any machine, forever), no AI / no probabilistic path, no server (every document and the movement stay on the user's machine), citable (the movement is derived from two coherences, each of which derives from one posture per document, each of which already cites that document's own clause and the team's own playbook), lints / references / positions — but never drafts, and never renders a legal conclusion. The movement is **advisory**: it states where the bundle's binding floor moved on the team's own ladder and whether the package fractured or reconciled, never that a term became legally adequate, enforceable, or that the weakest document legally governs. Every step passes the §3 filter or it does not ship.
> **Cousin docs:** [`spec.md`](spec.md) (v1, the linter), [`spec-v4.md`](spec-v4.md) (Depth & Breadth — **the cross-document axis**, §11 the consolidated bundle report), [`spec-v6.md`](spec-v6.md) (Workflow — **the version-comparison axis**), [`spec-v10.md`](spec-v10.md) (Negotiation Posture — the posture base), [`spec-v11.md`](spec-v11.md) (Posture Movement — **the version-over-version sibling**), [`spec-v12.md`](spec-v12.md) (Posture Coherence — **the cross-document sibling this composes with**), [`spec-v8.md`](spec-v8.md) (Reach — the headless CLI this rides on). Progress in [`BUILD_PROGRESS.md`](../BUILD_PROGRESS.md).

---

# Part 0 — Intent

## §1. Why we're doing this

The posture feature now reasons along two derived axes. v11 tracks a single document over time: the counterparty sends a counter, and each front shows whether your position improved, regressed, or held. v12 reasons across a single package at one moment: the MSA, the SOW, and the order form, and whether they hold the same line on each front or one undercuts it — and the **binding floor**, the weakest stated rung, which in a deal package is the rung that actually governs your exposure.

But a real negotiation is a **sequence of packages**. Round one is an MSA plus an order form. Round two is the revised MSA plus the revised order form. The deal lead's actual question is the composition of the two axes: *between rounds, did the binding floor on each front get better or worse, and did any front the package agreed on in round one quietly fracture in round two?* The liability cap may have been divergent at an acceptable floor in round one and is now divergent at a below-floor one — the counterparty did not touch the MSA, but quietly re-capped the order form two documents over, and the rung that governs exposure dropped. v11 cannot see it (it diffs one document). v12 cannot see it (it scores one round). Only the diff of two v12 coherences can.

Today, to catch this, a deal lead runs v12 on round one, runs it again on round two, and eyeballs the two coherence cards side by side, front by front, hunting for a binding floor that dropped. That is manual, error-prone, and exactly the kind of deterministic bookkeeping a linter should do. v13 does it: given two v12 coherences — both computed against the **same** positions — it classifies, per negotiation front, how the binding floor moved and how the coherence kind shifted:

- **binding-floor movement** (the headline, the well-ordered signal): `improved` / `regressed` / `unchanged` / `newly-stated` / `now-unstated`. The weakest stated rung across the package moved which way? This reuses v11's exact movement vocabulary and `TIER_RANK` table, applied to the floor.
- **coherence shift** (the advisory companion): `fractured` (a front the package agreed on, or had not split on, now diverges), `reconciled` (a divergent front no longer diverges), `realigned` (the stating set changed without crossing the divergence line), or `unchanged`.

The deal lead runs the two rounds once and reads, on every front at once: *liability cap binding floor regressed — acceptable in round one, below-floor in round two; governing law reconciled — divergent last round, aligned now; indemnity unchanged.* The single round-over-round-across-the-package question, computed without a model and without a server.

## §2. What v13 is and is not

**It is:**
- A **pure diff of two v12 coherences.** [`compareCoherence(base, revised)`](../src/report/coherence-movement.ts) takes two `PostureCoherence` objects and returns a `CoherenceMovement`: per-front `{ base_coherence, revised_coherence, base_floor, revised_floor, floor_movement, coherence_shift }`, floor- and shift-count tallies, and its own `movement_hash`. No document parsing, no extraction, no predicate evaluation, and no coherence computation happens here — both coherences are already done; v13 only compares the floor tier and the coherence label across rounds.
- A **front-matched diff.** Fronts are matched by **dimension** (the negotiation front), never by document. The two rounds may carry different document filenames (`msa-v1.docx` vs `msa-v2.docx`) or a different document count (round two adds a DPA) — the dimension is the stable key, so a rename or an added document never confuses the movement.
- A **well-ordered binding-floor movement.** It reuses the single `TIER_RANK` table v11 introduced and v12 reused (ideal=3 > acceptable=2 > below-acceptable=1; `unevaluable` unranked) to rank the floor's movement. A floor transition touching an unstated side is `newly-stated` / `now-unstated`, never ranked as improved or regressed.
- An **advisory, additive surface.** The `movement_hash` is namespaced apart from each document's `result_hash`, each `posture_hash`, and each `coherence_hash`; computing it moves no golden. It surfaces in the headless `analyze --posture --baseline <bundle>` output and gates CI via `--fail-on-coherence-regression`.

**It is not:**
- A **new classifier.** v13 introduces no new matching logic. A movement is decided by comparing the floor tier strings and the coherence labels the v12 engine already produced. The v6 false-positive surface, the v10 unevaluable-honesty surface, and the v12 unstated-is-never-a-divergence surface all carry over unchanged because nothing new is measured.
- A **renderer of legal conclusions.** A movement reports *where the bundle's floor moved on the team's own ladder* and *whether the package fractured or reconciled*, never "the order form's re-cap legally governs" or "this term became enforceable." Which document legally controls on a conflict, and whether a now-acceptable floor is *legally* sufficient, are the team's judgment; v13 reports the transition and stops.
- A **dishonest comparison of unstated data.** A front no document states on a side has no binding floor; a transition into or out of that state is `newly-stated` / `now-unstated`, never a ranked regression. A front that fell off the ladder entirely is reported but never trips the gate (§3 corollary 2).
- A **cross-ladder comparison.** A movement is meaningful only when both coherences were computed against the **same** positions. The CLI applies the one active custom playbook to every document in both rounds; comparing coherences computed from different ladders is out of scope (and would be nonsense, the same way v11 refuses a cross-ladder movement and v12 refuses a cross-ladder coherence).

## §3. The posture filter (the gate every step passes)

Identical to v6–v12 §3, restated because v13 composes two derived outputs (a *spread* over a *trajectory*) — a place an over-claim is easy to make by accident:

```
Deterministic?  same two coherences + same front order → identical movement_hash,
                on any machine, forever.
No AI?          no probabilistic component anywhere in the path (it is a set of
                string compares + one rank lookup per front).
No server?      every document and the movement stay on the user's machine.
Citable?        the movement derives from two coherences, each from one posture
                per document, each citing that document's own clause and the
                team's own playbook.
Lints/positions, not drafts?  classifies how a spread moved across rounds —
                never writes, proposes, redacts, renders a legal conclusion, or
                adjudicates which document legally controls.
```

Three v13-specific corollaries:
- **1. The floor movement is a well-ordered comparison.** Improved/regressed is decided by the same `TIER_RANK` table v11 and v12 rank by; equal rank only occurs for the same tier (→ unchanged). Same two coherences → same movement, byte-for-byte.
- **2. Unstated is never ranked, on either side.** A floor transition touching an unstated front is `newly-stated`, `now-unstated`, or `unchanged` — never improved or regressed. A front that dropped off the ladder (`now-unstated`) is reported but never trips the gate; a team that wants to gate on a dropped front composes it from `floor_counts`. The v12 "a divergence is reported only when two or more documents are stated" honesty extends to "a floor movement across a stated rung is reported only when both rounds state it."
- **3. Advisory, never a precedence or adequacy conclusion.** A movement reports a shift on the team's own ladder. It never asserts a term became legally adequate, enforceable, market, or required, nor which document *legally governs* on a conflict — order-of-precedence across a bundle is the team's judgment, encoded in the documents' own integration clauses (the v12 §3 corollary-3 bright line, carried forward).

## §4. How the thrusts sequence

**The movement engine and its headless surface (A) land first and complete the idea on the axis it most naturally lives.** The classifier is a pure function over two existing coherences, so it sits on a fully-proven base and adds no extractor, no predicate, and no fuzzy logic. The headless `analyze --posture` command already computes one coherence over a bundle (v12); Thrust A adds a `--baseline <bundle>` flag that analyzes a second bundle against the **same** playbook, computes its coherence, and reports the movement between the two — a render-side, additive addition that moves no existing per-document JSON, golden, `result_hash`, or `coherence_hash`. The CI gate `--fail-on-coherence-regression` follows the exact `--fail-on` / `--fail-on-regression` / `--fail-on-divergence` pattern.

**The browser-UI card and the DOCX section (Thrust B/C) are proposed, not built.** Before B, the browser flow has no two-bundle comparison surface: the UI compares two single documents (v6/v11) or analyzes one bundle (v4/v12), but never two bundles. A v13 UI card therefore waits on a "compare two rounds of a package" surface that does not yet exist — a larger lift than v12's, which only had to thread a posture through an *existing* bundle flow. Both B and C are additive and omitted when no baseline is supplied (every existing golden byte-unchanged), and are noted as the spec's principled deferrals below.

---

# THRUST A — THE MOVEMENT ENGINE & HEADLESS SURFACE (shipped, 9.9.0)

These steps add the `compareCoherence` classifier and wire it into the headless `analyze` bundle path and a CI gate. Each movement is derived from two coherences, each of which derives from one posture per document, each citing that document's own clause and the team's own playbook.

| # | Step | Output | Tier |
|---|------|--------|------|
| 187 ✅ | Movement engine | [`compareCoherence`](../src/report/coherence-movement.ts): a pure, deterministic per-front cross-round classifier. For each negotiation front (matched by dimension): the binding-floor movement (`improved` / `regressed` / `unchanged` / `newly-stated` / `now-unstated`, + defensive `appeared` / `disappeared`) reusing v11's exported `TIER_RANK`, and the coherence shift (`fractured` / `reconciled` / `realigned` / `unchanged`). Floor- and shift-count tallies and a `movement_hash` namespaced apart from every `coherence_hash`. A `coherenceRegressed(movement)` predicate mirrors v11's `postureRegressed` and v12's `hasDivergence`. Unit + property-style tests across every floor movement, every shift, the front-by-dimension matching (renamed/added documents), determinism, and direction sensitivity. | Movement |
| 188 ✅ | Headless movement | The CLI `analyze` command accepts `--baseline <path\|glob\|dir>` (requires `--posture`): it analyzes the baseline bundle against the **same** custom playbook, computes its v12 coherence, diffs it against the primary bundle's coherence, and prints a "Cross-document posture movement (vs. baseline)" summary — the floor- and shift-count lines, one line per front whose floor moved or whose package fractured/reconciled (an unmoved front is omitted), and the `movement_hash`. A baseline that yields no coherence (fewer than two documents with a posture) is a hard error, not a silent no-op. | Movement |
| 189 ✅ | Regression gate | The CLI `analyze` command accepts `--fail-on-coherence-regression` (requires `--baseline`): it exits non-zero (code 2) when any front's binding floor moved to a strictly worse **stated** rung between the rounds. The gate is the well-ordered floor worsening only; a front that dropped off the ladder (`now-unstated`) is reported but never trips it (§3 corollary 2 — a dropped front is not conflated with a rung regression; a team that wants to gate on it composes from `floor_counts`). Reported alongside `--fail-on` and `--fail-on-divergence`; any tripping sets exit 2. | Movement |

---

# Part XV — Build plan

Each step is a prompt-sized unit, continuing the global numbering after v12's Step 186. Verification gate for every step: `npm run typecheck && lint && test && build` green; the v7 coverage/parity/property gates, the v8 fuzz + citation gates, the v9 no-wall-clock gate, and the responsiveness e2e (every view-state vertical-scroll-only 320–1280px, WCAG 2 AA) stay green.

Status legend: **✅ shipped** · ⬜ proposed.

| # | Step | Output | Tier |
|---|------|--------|------|
| 187 ✅ | Movement engine | `compareCoherence` reusing v11's `TIER_RANK`; per-front binding-floor movement + coherence shift; floor/shift counts; `movement_hash`. `coherenceRegressed` predicate. Unit tests across every movement + shift + determinism + direction sensitivity. | Movement |
| 188 ✅ | Headless movement | CLI `analyze --posture --baseline <bundle>` → a "Cross-document posture movement" summary (floor/shift counts + per-moved-front line + `movement_hash`). | Movement |
| 189 ✅ | Regression gate | CLI `analyze --posture --baseline <bundle> --fail-on-coherence-regression` → exit 2 when any front's binding floor regressed to a strictly worse stated rung. | Movement |
| 190 ⬜ | Browser-UI two-round card | A bundle-vs-baseline comparison surface in the browser, rendering a mobile-safe per-front movement card (floor movement + coherence shift). Proposed — waits on a two-bundle UI flow. | Movement |
| 191 ⬜ | DOCX movement section | A "Posture Movement (Across the Package)" section in a two-round deliverable, color-coded per-front. Proposed — waits on Step 190's surface. | Movement |

Total work shipped this spec: **3 build steps (187–189).** Every step is additive — an analyze run with no `--baseline` yields no movement, so every existing per-document `result_hash`, `coherence_hash`, and bundle golden is byte-unchanged.

---

# Part XVI — Principled deferrals

- **A browser-UI two-round card (Step 190).** ⬜ Proposed. The browser flow has no two-bundle comparison surface yet (the UI compares two single documents or analyzes one bundle, never two bundles). A v13 card waits on that surface; when it lands it reuses the v12 `pc-*` styles plus a `pm-*`-style direction color, exactly as v11's card reused v10's. Additive — omitted when no baseline is supplied.
- **A DOCX movement section (Step 191).** ⬜ Proposed, behind Step 190. Renders a trailing color-coded per-front movement table in the two-round deliverable; omitted when no baseline is supplied so every bundle golden stays byte-unchanged.
- **Gate on a fracture (a front that newly diverges across the package).** v13 gates on the well-ordered binding-floor regression only. A front that *fractured* (`fractured` shift) without its floor dropping — e.g. the package split from aligned-at-ideal to ideal-vs-acceptable — is a genuine signal a team may want to gate on, but it is not a floor regression; recommendation: **report, never gate, in v13** (compose from `shift_counts.fractured`), mirroring how v11 reports but does not gate `now-unstated` and v12 reports but does not gate `single`.
- **Three-rung movement.** If v10 ever grows a third authored rung, `TIER_RANK` is the single place to extend the order; the floor classifier needs no other change. Noted, not built (v10 ships two rungs).

---

# Part XVII — Open questions for the maintainer

1. **Match fronts by document as well as by dimension?** Today a movement matches fronts by dimension only, so it answers "did the *bundle's* floor on the cap move?" but not "did *this specific document's* rung on the cap move?" The latter is the v11 per-document movement run on each document pair — a composition a team can already get by running `compare --posture` per document. Recommendation: **keep v13 bundle-level** — the binding floor is the exposure-governing number across a package, and per-document movement is already a shipped surface (v11).
2. **Persist a coherence as a baseline artifact instead of re-analyzing?** Today `--baseline` re-analyzes the baseline bundle. A `--baseline-coherence <coherence.json>` that diffs a previously-emitted coherence would be faster and would not need the baseline documents on disk at gate time. Recommendation: **re-analyze in v13** — it keeps one ladder and both rounds in a single auditable run; a saved-coherence import is a larger surface deferred until asked (the v11 saved-posture deferral, one axis over).

---

# Part XVIII — What this gives the user

- **Your ladder, tracked across the whole deal, round over round.** Encode your positions once. Drop round one's package and round two's package — and the analyze run tells you, on every front at once, whether the binding floor that governs your exposure improved or regressed, and whether any front your package agreed on quietly fractured. The snapshot v10 gave you, the trajectory v11 gave you across versions, and the coverage v12 gave you across documents, becomes the **trajectory of the coverage** — the thing a deal lead actually negotiates.
- **The binding floor's movement, gated.** For every front, v13 names how the weakest stated rung moved — and `--fail-on-coherence-regression` turns a regressed floor into a hard CI gate, exactly as `--fail-on-regression` does for a single document and `--fail-on-divergence` does for a single round. The thing a deal lead hunts for across two rounds by eye, computed deterministically and enforced in CI.
- **The same five promises.** Deterministic, no AI, no server, citable, never drafts — every line of v13 passes the §3 gate. The movement derives from two coherences, each from one posture per document, each citing your own playbook and that document's own clause; an unstated front is never a false regression; and the thing you most need round-over-round across a package — *did the floor that governs my exposure get worse* — is computed without a model and without a server.
