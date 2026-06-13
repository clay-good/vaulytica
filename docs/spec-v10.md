# Vaulytica v10 — Negotiation Posture

> **Status:** **Thrust A (the tiered-position ladder) implemented — shipped 9.1.0.** This spec defines v10 on the **v6 bring-your-own-playbook axis** (not the v9 "last look" axis). It continues the global step numbering after v9's Step 165, beginning at **Step 166**. Thrust A — the `negotiation_positions` schema extension, the deterministic tier evaluator ([`evaluateNegotiationPosture`](../src/playbooks/custom-interpreter.ts)), the `NegotiationPosture` artifact with its own `posture_hash`, and the report/tab surfaces — is live and wired into the JSON report (`negotiation_posture` block), the DOCX and HTML reports, and the complete-state tab. Thrusts **B (Posture report & export, Steps 170–172)** and **C (Dimension breadth, Steps 173–175)** remain **proposed — not yet implemented**. The `Status` lines of the prior specs are unchanged by it.
> **Scope:** one idea, deepening the v6 custom-playbook track from *enforcement* to *negotiation*. v6 let a team encode a binary standard — a clause is compliant or it is not, and a finding fires when it is not. A real negotiation is not binary: a team holds an **ideal** position, a **fallback** it will accept, and a **walk-away** below which it escalates. v10 lets the team encode that ladder, and reports **which rung the draft currently sits on**, for each negotiable dimension — so a negotiator opens the report and sees, at a glance, where they have leverage and where they must push. It reuses the v6 §9 bounded predicate DSL wholesale: a tier is classified by exactly the deterministic predicate the custom rules already evaluate, so there is **no new fuzzy logic** and the whole feature inherits v6's posture proofs.
> **Posture (unchanged, non-negotiable):** deterministic (same playbook + same document → identical bytes, on any machine, forever), no AI / no probabilistic path, no server (the playbook, the document, and the posture stay on the user's machine; the tab makes zero cross-origin requests), citable (each position cites the document's own clause and the team's own playbook), lints / references / now *positions* — but never drafts, and never renders a legal conclusion. The posture is **advisory**: it states where the draft sits on the team's own ladder, never that a term is legally adequate, enforceable, or required. Every step passes the §3 filter or it does not ship.
> **Cousin docs:** [`spec.md`](spec.md) (v1, the linter), [`spec-v3.md`](spec-v3.md) (regulated agreements), [`spec-v4.md`](spec-v4.md) (all logically-operative documents), [`spec-v5.md`](spec-v5.md) (Ground Truth), [`spec-v6.md`](spec-v6.md) (Workflow — **the parent axis**: bring-your-own-playbook §8–§10), [`spec-v7.md`](spec-v7.md) (Depth & Proof), [`spec-v8.md`](spec-v8.md) (Hardening & Reach), [`spec-v9.md`](spec-v9.md) (The Last Look). The bounded predicate DSL v10 builds on is [`docs/v6/playbook.schema.json`](v6/playbook.schema.json). Progress in [`BUILD_PROGRESS.md`](../BUILD_PROGRESS.md).

---

# Part 0 — Intent

## §1. Why we're doing this

v6 shipped a team's standard as a set of **predicates that must hold**: a `numeric_threshold` (liability cap ≥ 12× fees), a `governing_law_in` (Delaware or New York), a `clause_present` (a mutual-indemnification clause). When a predicate is false, a finding fires. That is enforcement, and it is exactly right for a compliance gate. It is the wrong shape for a *negotiation*.

A negotiator does not hold one position. They hold a ladder:

- the **ideal** they open with (a 12-month liability cap),
- the **acceptable** floor they will settle for (a 6-month cap),
- and the **walk-away** below which they escalate to a principal (anything less).

When the other side sends a draft with an 8-month cap, the v6 engine says "compliant" if the floor was 6, or "violated" if the bar was 12 — a single bit that throws away the thing the negotiator most needs to know: *the draft is acceptable but not ideal; there is room to push, and the fallback is already met.* v10 reports that. For each dimension the team cares about, it computes which rung of the ladder the draft meets — **ideal**, **acceptable**, **below floor**, or **not stated** — and shows the team's own guidance for that rung. The negotiator opens the report and reads their position on every front at once.

This is the natural, posture-clean deepening of the v6 axis. It needs no new authority (it cites the document's own clause and the team's own playbook), no model (it reuses the deterministic predicate evaluator), and no server.

## §2. What v10 is and is not

**It is:**
- A **schema extension** of the v6 custom playbook: a `negotiation_positions` array, each item a `dimension` plus two predicates — `ideal` (the stricter bar) and `acceptable` (the floor) — drawn from the **same** §9 DSL the custom rules use, plus optional per-tier `guidance` text.
- A **deterministic tier classifier**: the existing `evaluatePredicate` decides, for each position, the highest rung the draft meets. Monotone by construction — `ideal` is strict, `acceptable` is the floor — so the ladder is well-ordered.
- An **advisory posture artifact** (`NegotiationPosture`) with its own `posture_hash`, surfaced in the JSON report, the DOCX and HTML reports, and the tab — **outside** the engine `result_hash` (it is a property of the team's ladder, not the catalog finding set; the v8 Step-146 / v9 "field outside the run" precedent).

**It is not:**
- A **drafting tool.** v10 positions the draft on a ladder; it never writes a clause, proposes a counter, or redacts a term. The v4 line stands: it lints and positions, it does not draft.
- A **renderer of legal conclusions.** A tier is *where the draft sits on the team's own ladder*, never "this term is enforceable / adequate / market." Whether a 6-month cap is *legally* sufficient is the team's judgment, encoded by the team; v10 only reports against what the team wrote down.
- An **assertion on absent data.** When the dimension's metric or clause is **not stated** in the document, the position is **unevaluable** — never a false "below floor." A walk-away is reported only when both tiers are evaluable and both fail (§3 corollary 2). This is the v5/v6 honesty contract on the posture surface.
- A **model, a server, or a new extractor.** No probabilistic component. Nothing leaves the tab. v10 reuses the v6 metric/clause extraction; it adds **no** new extractor in Thrust A (Thrust C proposes broadening the dimension set, gated behind the same measure-first discipline).
- A **UI rebuild.** The complete state gains one additive "Negotiation posture" card; the report gains one section. The four document states and the drop zone are unchanged.

## §3. The posture filter (the gate every step passes)

Identical to v6–v9 §3, restated because v10 introduces a new output category (a *tiered* classification) — the place where an over-claim is easiest to make by accident:

```
Deterministic?  same playbook + same document → identical bytes, on any machine, forever.
No AI?          no probabilistic component anywhere in the path.
No server?      the playbook, the document, and the posture stay on the user's machine;
                the tab makes zero cross-origin requests.
Citable?        each position cites the document's own clause and the team's own playbook.
Lints/positions, not drafts?  finds, classifies, references, explains — never writes,
                proposes, redacts, or renders a legal conclusion.
```

Three v10-specific corollaries:
- **1. The ladder is monotone and deterministic.** `ideal` is the strict predicate, `acceptable` the floor. The classifier evaluates `ideal` first, then `acceptable`, with the existing pure `evaluatePredicate` — no new logic, no ordering ambiguity. Same inputs → same tier, byte-for-byte.
- **2. Below-floor only on evaluable data.** A position is reported **below-acceptable** only when *both* `ideal` and `acceptable` are evaluable and both fail. If either tier is unevaluable (the metric/clause is not stated), the position is **unevaluable** and surfaced "verify manually" — never a false walk-away on data the document does not contain.
- **3. Advisory, never a conclusion.** A tier reports *where the draft sits on the team's own ladder*. It never asserts the term is legally adequate, enforceable, market, or required. The posture cites the team's playbook and the document's clause; the legal judgment stays the team's, exactly as v6 §9 drew the line for custom rules.

## §4. How the thrusts sequence

Dependency-first, mirroring v6–v9 §4. **The tiered-position ladder (A) lands first** because the schema and the evaluator are the foundation every surface consumes; it reuses the v6 predicate evaluator directly, so it sits on top of a proven base and adds no new extractor. **The posture report & export (B) lands second**, deepening the surfaces into a standalone, shareable negotiation sheet and a Markdown/CSV export. **Dimension breadth (C) lands last** because broadening the set of negotiable dimensions (new `numeric_threshold` metrics, structured clause-quality predicates) is the measure-first step — each new dimension needs a fixture pass proving the extraction is reliable before it is wired, exactly as v5 §IX #4 and v7/v8 §4 require.

---

# THRUST A — THE TIERED-POSITION LADDER

These steps add the `negotiation_positions` schema, the deterministic tier evaluator, and the advisory `NegotiationPosture` artifact, wired into the report and the tab. Each position cites the document's own clause and the team's own playbook.

## Part I — The schema

### §5. What it does

Extends [`CustomPlaybook`](../src/playbooks/custom-playbook.ts) with an optional `negotiation_positions` array. Each position is `{ dimension, ideal, acceptable, guidance? }`: `dimension` is a unique human label ("Liability cap"); `ideal` and `acceptable` are predicates from the **existing** §9 discriminated union (`numeric_threshold`, `governing_law_in`, `clause_present`, `clause_absent`, `defined_term_present`, `cross_ref_resolves`); `guidance` carries optional per-tier negotiation notes (`ideal` / `acceptable` / `walk_away`). The Zod schema is the source of truth; the published JSON Schema artifact ([`docs/v6/playbook.schema.json`](v6/playbook.schema.json)) mirrors it, guarded by the schema-artifact test.

### §6. The honest fix

The validator rejects an authoring mistake up front rather than letting it fire silently: a `clause_present`/`clause_absent` tier with neither `pattern` nor `section_heading` (it could never match a concrete clause), and a duplicate `dimension` (each must be addressable in the report). Adding `negotiation_positions` is backward-compatible — the field is optional, the `schema_version` literal is unchanged, and a playbook without it validates and runs exactly as before. A `replace`-mode playbook whose only content is positions is now a legitimate "posture-only" standard.

## Part II — The evaluator

### §7. What it does

`evaluateNegotiationPosture(positions, { tree, extracted })` ([`src/playbooks/custom-interpreter.ts`](../src/playbooks/custom-interpreter.ts)) is a pure function that classifies each position into a `NegotiationTier`: it evaluates `ideal` with the existing `evaluatePredicate`; if compliant, the tier is **ideal**; otherwise it evaluates `acceptable`; if compliant, **acceptable**; if both are evaluable and both fail, **below-acceptable**; otherwise **unevaluable** (§3 corollary 2). It returns a `NegotiationPosture` — the per-dimension results (sorted by dimension for determinism), tier counts, and a `posture_hash` over the canonical `{dimension, tier}` set.

### §8. The honest fix

The classifier introduces **no** new matching logic: a tier is decided by exactly the deterministic predicate the v6 custom rules already evaluate, which is exactly why the v6 false-positive surface does not reappear. The `posture_hash` is namespaced apart from the engine `result_hash`, so the posture is additive — a document run with no positions yields no posture and moves no golden.

## Part III — The surfaces

### §9. What it does

The `NegotiationPosture` is surfaced everywhere the report renders: a `negotiation_posture` block in the JSON report, a "Negotiation Posture" section in the DOCX and HTML reports, and a "Negotiation posture" card on the complete-state tab — each shown only when the active custom playbook defined positions, and omitted otherwise (so a non-custom or position-free run renders identically to before). Each row shows the dimension, the tier reached, the evaluator's explanation (e.g. "Found liability_cap_multiple = 3; requires ≥ 6"), the team's guidance for that rung, and the source section. The tab card is mobile-safe (every cell wraps; no horizontal scroll at any width).

### §10. The fix

The surfaces are render-side and additive: the posture is computed once in the pipeline when a position-bearing custom playbook runs, then passed to the JSON/DOCX/HTML builders as an optional argument (the v9 surface-threading pattern), so no existing caller, golden, or `result_hash` moves.

---

# THRUST B — POSTURE REPORT & EXPORT (proposed)

Deepen the posture from a report *section* into a standalone, shareable **negotiation sheet** — a one-page view a negotiator works down before a call — and a Markdown/CSV export of the ladder (dimension · tier · guidance · clause), reusing the v6/v8 export pipeline. Add a CLI affordance once the CLI accepts a custom playbook file (today the CLI takes only built-in playbook ids, so this is gated on that surface).

| # | Step | Output | Tier |
|---|------|--------|------|
| 170 ⬜ | Negotiation sheet | A standalone, print-clean negotiation sheet (HTML) grouping positions by tier (push-here / hold / escalate) | Posture report |
| 171 ⬜ | Posture export | `negotiation-posture` Markdown + CSV via the v6/v8 export pipeline; structure-tested | Posture report |
| 172 ⬜ | Headless posture | Custom-playbook ingest in the CLI + a `--posture` mode, once the CLI accepts a playbook file | Posture report |

---

# THRUST C — DIMENSION BREADTH (proposed)

Broaden the set of negotiable dimensions a position can assert on — each measure-first. New `numeric_threshold` metrics (cure-period days, auto-renewal-notice days, indemnity-cap amount, uptime-SLA percent), and structured clause-quality predicates (mutual vs. one-way indemnity, carve-outs present) — each gated behind a fixture pass proving the extraction is reliable before it is wired, never guessed.

| # | Step | Output | Tier |
|---|------|--------|------|
| 173 ⬜ | Temporal dimensions | `cure_period_days`, `auto_renewal_notice_days` metrics + extractor fixtures | Dimension breadth |
| 174 ⬜ | Financial dimensions | `indemnity_cap_amount`, `uptime_sla_percent` metrics + fixtures | Dimension breadth |
| 175 ⬜ | Mutuality predicates | a `clause_mutual` predicate (one-way vs. mutual indemnity / termination), fixture-gated | Dimension breadth |

---

# Part XV — Build plan

Each step is a prompt-sized unit, continuing the global numbering after v9's Step 165. Verification gate for every step: `npm run typecheck && lint && test && build` green; the v7 coverage/parity/property/completeness gates, the v8 fuzz + citation-completeness gates, and the v9 no-wall-clock gate stay green.

Status legend: **✅ shipped** · ⬜ proposed.

| # | Step | Output | Tier |
|---|------|--------|------|
| 166 ✅ | Schema | `negotiation_positions` on `CustomPlaybook` (Zod + JSON Schema artifact); validation (tier-predicate well-formedness, unique dimension, posture-only replace mode). | Ladder |
| 167 ✅ | Evaluator | `evaluateNegotiationPosture` reusing `evaluatePredicate`; monotone tier classification; below-floor only on evaluable data; `posture_hash`. Property/unit tests across numeric / governing-law / clause ladders. | Ladder |
| 168 ✅ | JSON + tab | `negotiation_posture` JSON block; a mobile-safe "Negotiation posture" complete-state card; pipeline wiring (computed once when a position-bearing custom playbook runs). | Ladder |
| 169 ✅ | DOCX + HTML | A "Negotiation Posture" section in the DOCX and standalone HTML reports (escaped, additive, zero `result_hash` churn); an example playbook with positions; docs + README + threat-model. | Ladder |
| 170–172 ⬜ | Posture report & export | Standalone negotiation sheet · Markdown/CSV export · headless posture (gated on CLI playbook ingest). | Posture report |
| 173–175 ⬜ | Dimension breadth | Temporal · financial · mutuality dimensions, each measure-first (extractor fixtures before wiring). | Dimension breadth |

Total work: **10 build steps (166–175).** Thrust A (166–169, four steps) is the foundation and is additive — a document run with no positions yields no posture, so the engine `result_hash` never moves. Thrusts B and C are deferred and specified.

---

# Part XVI — Principled deferrals

- **Auto-classifying a tier on an *un-extractable* dimension.** A position can only assert on a dimension the engine can deterministically extract (the v6 metric set + clause/governing-law predicates). v10 does **not** guess a tier from prose it cannot quantify; an unstated dimension is honestly `unevaluable`. Broadening the extractable set is Thrust C, measure-first.
- **Proposing the counter.** v10 reports the draft's rung and the team's guidance; it never drafts the counter-position language. That crosses the v4 lint-not-draft line. The guidance the team *wrote* is surfaced verbatim; nothing is generated.
- **A market/benchmark tier.** "Is a 6-month cap *market*?" requires a benchmark dataset Vaulytica does not have and could not source without an attorney-gated corpus (the v5 frontier). v10 classifies only against the team's **own** ladder, never an external benchmark.
- **Cross-document posture.** Computing a posture across a bundle (e.g. the MSA's cap vs. the SOW's) is a genuinely useful extension on the v4 cross-document axis, but it sits there, not on this one; noted for a future spec.

---

# Part XVII — Open questions for the maintainer

1. **More than two rungs?** The ladder is `ideal` / `acceptable` today (with `below` and `unevaluable` derived). Some teams hold three offered positions (ideal / target / reservation). Recommendation: **two authored rungs in v10** — they cover the dominant ideal/floor case and keep the classifier unambiguous; a third authored rung is a clean Thrust-B extension if a user asks.
2. **Escalate-below-floor as a finding?** Should a below-floor position also fire an engine `Finding` (so a CI gate can fail on it), or stay advisory-only? Recommendation: **advisory-only in v10** — posture is a negotiation aid, not a compliance gate; a team that wants a hard gate already has the v6 `custom_rule` for exactly that. A future `escalate_on` flag could opt a position into a finding.

---

# Part XVIII — What this gives the user

- **Your ladder, scored against the draft.** Encode your ideal and your floor once, per dimension. Drop the counterparty's draft and the report tells you, on every front at once: *liability cap is acceptable but not ideal — push for 12 months; governing law is ideal — hold; indemnity is below your floor — escalate.* The single bit v6 gave you becomes the rung you actually negotiate on.
- **Deterministic, where every other tool guesses.** A language-model "negotiation assistant" reads the draft and produces a confident, different answer every time. v10 classifies each position with the same pure predicate twice and gets the same rung, byte-for-byte, on any machine — a posture a partner can sign off on and a client can reproduce.
- **The same five promises.** Deterministic, no AI, no server, citable, never drafts — every line of v10 passes the §3 gate. The posture cites your own playbook and the document's own clause; an unstated dimension is honestly unevaluable, never a false walk-away; and the thing you most need before a negotiation — *where do I stand on each front* — is computed without a model and without a server.
