# Vaulytica v11 — Negotiation Posture Movement

> **Status:** **Thrust A implemented and shipped (9.4.0).** This spec extends the v10 **Negotiation Posture** feature along the v6 **version-comparison** axis: it reports how a team's posture *moved* between two drafts. It continues the global step numbering after v10's Step 175, beginning at **Step 176**. **Thrust A** — the pure [`comparePosture`](../src/report/posture-movement.ts) movement classifier, the additive `posture_movement` block in the comparison JSON, a mobile-safe "Posture movement" card in the comparison-complete tab, and the headless `vaulytica compare --posture` mode — is live.
> **Scope:** one idea, sitting exactly at the intersection of two shipped axes. v6 compares two **drafts** (the finding delta: resolved / introduced / unchanged). v10 scores a **single** draft against the team's tiered ladder (which rung each dimension meets: ideal / acceptable / below-floor / not-stated). A negotiation is a *sequence* of drafts, and the question a negotiator most needs answered round-over-round is neither of those alone: *when the counterparty sends a revised draft, did my position on each front improve, regress, or stay put?* v11 answers it by diffing two v10 postures — no new extractor, no new predicate, no fuzzy logic.
> **Posture (unchanged, non-negotiable):** deterministic (same two postures → identical `movement_hash`, on any machine, forever), no AI / no probabilistic path, no server (both drafts and the movement stay on the user's machine), citable (the movement is derived from two postures, each of which already cites the document's own clause and the team's own playbook), lints / references / positions — but never drafts, and never renders a legal conclusion. The movement is **advisory**: it states where the draft moved on the team's own ladder, never that a term became legally adequate, enforceable, or required. Every step passes the §3 filter or it does not ship.
> **Cousin docs:** [`spec.md`](spec.md) (v1, the linter), [`spec-v6.md`](spec-v6.md) (Workflow — **the comparison axis**, §I version comparison), [`spec-v10.md`](spec-v10.md) (Negotiation Posture — **the posture axis** this deepens), [`spec-v8.md`](spec-v8.md) (Reach — the headless CLI and the clause-redline that `posture_movement` rides alongside). Progress in [`BUILD_PROGRESS.md`](../BUILD_PROGRESS.md).

---

# Part 0 — Intent

## §1. Why we're doing this

v10 gave a negotiator a snapshot: drop a draft, read which rung of your ladder each dimension meets. That is exactly right for the *first* look at a counterparty's paper. But negotiation is iterative — paper goes back and forth — and a snapshot of the latest draft throws away the thing a negotiator carries in their head between rounds: *where was I, and which way did this revision move me?*

Today, to answer that, a negotiator re-runs the new draft and eyeballs the two posture cards side by side. That is manual, error-prone, and exactly the kind of deterministic bookkeeping a linter should do. v11 does it: given the base draft's posture and the revised draft's posture — both computed by the v10 evaluator against the **same** positions — it classifies each dimension's transition:

- **improved** — both drafts state the term; the revised rung is strictly closer to ideal (e.g. *below-floor → acceptable*).
- **regressed** — both state it; the revised rung is strictly worse (e.g. *ideal → acceptable*).
- **unchanged** — the same rung on both drafts (including *not-stated → not-stated*).
- **newly-stated** — the dimension was unstated in the base and is now on the ladder.
- **now-unstated** — the dimension was on the ladder in the base and is absent from the revised draft.

The negotiator opens the comparison and reads, on every front at once: *liability cap improved (below-floor → acceptable) — good, but still not ideal; governing law regressed (ideal → below-floor) — push back hard; indemnity unchanged — still escalate.* The single round-over-round question, computed without a model and without a server.

## §2. What v11 is and is not

**It is:**
- A **pure diff of two v10 postures.** [`comparePosture(base, revised)`](../src/report/posture-movement.ts) takes two `NegotiationPosture` objects and returns a `PostureMovement`: per-dimension `{ base_tier, revised_tier, movement }`, movement counts, and its own `movement_hash`. No document parsing, no extraction, no predicate evaluation happens here — the classification is already done; v11 only compares the two tier labels.
- A **well-ordered rung comparison.** A single `TIER_RANK` table (ideal=3 > acceptable=2 > below-acceptable=1) decides improved vs. regressed. `unevaluable` is deliberately **unranked** — "not stated" is not a point on the ideal→floor axis, so it is never compared as better or worse than a stated rung (the §3 honesty contract).
- An **advisory, additive surface.** The `movement_hash` is namespaced apart from the comparison `result_hash`; passing the movement to the report builders moves no golden. It surfaces in the comparison JSON, the comparison-complete tab card, and the headless `compare --posture` output.

**It is not:**
- A **new classifier.** v11 introduces no new matching logic. A movement is decided by comparing two tier strings the v10 evaluator already produced. The v6 false-positive surface and the v10 unevaluable-honesty surface both carry over unchanged because nothing new is measured.
- A **renderer of legal conclusions.** A movement reports *where the draft moved on the team's own ladder*, never "this term became enforceable / adequate / market." Whether a now-acceptable cap is *legally* sufficient is the team's judgment, encoded in their ladder; v11 only reports the transition.
- A **dishonest comparison of unstated data.** A dimension that is `unevaluable` on either side is never folded into improved/regressed (that would conflate "not stated" with "below floor"). It gets its own honest label (`newly-stated` / `now-unstated`), and `unchanged` covers both-unstated.
- A **cross-family or cross-ladder comparison.** A movement is meaningful only when both postures were computed against the **same** positions. The UI and CLI both apply the one active custom playbook to both drafts; comparing two different ladders is out of scope (and would be nonsense, the same way v6 refuses a cross-family finding compare).

## §3. The posture filter (the gate every step passes)

Identical to v6–v10 §3, restated because v11 introduces a new output category (a *transition* between rungs) — a place an over-claim is easy to make by accident:

```
Deterministic?  same two postures → identical movement_hash, on any machine, forever.
No AI?          no probabilistic component anywhere in the path (it is a string compare).
No server?      both drafts and the movement stay on the user's machine.
Citable?        the movement derives from two postures, each citing the document's
                own clause and the team's own playbook.
Lints/positions, not drafts?  classifies a transition — never writes, proposes,
                redacts, or renders a legal conclusion.
```

Three v11-specific corollaries:
- **1. The rung order is total and deterministic.** improved/regressed is decided by one `TIER_RANK` table; equal rank only occurs for the same tier (→ unchanged). Same two postures → same movement, byte-for-byte.
- **2. Unstated is never ranked.** A transition touching `unevaluable` is labeled `newly-stated`, `now-unstated`, or `unchanged` — never improved or regressed. The v10 "below-floor only on evaluable data" honesty extends to "a movement across a stated rung is reported only when both sides are stated."
- **3. Advisory, never a conclusion.** A movement reports a shift on the team's own ladder. It never asserts a term became legally adequate, enforceable, market, or required.

## §4. How the thrusts sequence

**The movement engine and its surfaces (A) land first and complete the idea** — the classifier is a pure function over two existing postures, so it sits on a fully-proven base and adds no extractor, no predicate, and no fuzzy logic. Surfaces are render-side and additive (the v9/v10 trailing-optional-argument threading pattern), so no existing comparison caller, golden, or `result_hash` moves. Further thrusts (a DOCX/HTML comparison-report section; a CI `--fail-on-regression` gate) are noted as principled deferrals, not yet built.

---

# THRUST A — THE MOVEMENT ENGINE & SURFACES (shipped, 9.4.0)

These steps add the `comparePosture` classifier and wire its `PostureMovement` into the comparison JSON, the comparison-complete tab, and the headless CLI. Each movement is derived from two postures that each cite the document's own clause and the team's own playbook.

| # | Step | Output | Tier |
|---|------|--------|------|
| 176 ✅ | Movement engine | [`comparePosture`](../src/report/posture-movement.ts): a pure, deterministic per-dimension transition classifier (improved / regressed / unchanged / newly-stated / now-unstated, + defensive appeared / disappeared), a `TIER_RANK` table with `unevaluable` unranked, movement counts, and a `movement_hash` namespaced apart from `result_hash`. Unit + property-style tests across every transition. | Movement |
| 177 ✅ | JSON + tab | An additive `posture_movement` block in the comparison JSON ([`buildComparisonJson`](../src/report/compare.ts), trailing optional arg); a mobile-safe "Posture movement" card in the comparison-complete tab (reuses the v10 `np-*` overflow-wrap styles + `pm-*` direction colors); UI wiring threads the base posture and the active custom playbook through `runComparison` so the revised draft is classified against the same ladder. | Movement |
| 178 ✅ | Headless movement | The CLI `compare` command accepts `--playbook-file <path>` + `--posture` (mirroring `analyze`): it classifies both drafts against the playbook's `negotiation_positions` and emits a `posture_movement` JSON block (or a Markdown table) — a redline gate can show how each front moved between two versions in CI. | Movement |

---

# Part XV — Build plan

Each step is a prompt-sized unit, continuing the global numbering after v10's Step 175. Verification gate for every step: `npm run typecheck && lint && test && build` green; the v7 coverage/parity/property gates, the v8 fuzz + citation gates, the v9 no-wall-clock gate, and the responsiveness e2e (every view-state vertical-scroll-only 320–1280px, WCAG 2 AA) stay green.

Status legend: **✅ shipped** · ⬜ proposed.

| # | Step | Output | Tier |
|---|------|--------|------|
| 176 ✅ | Movement engine | `comparePosture` reusing the v10 tier labels; total rung order; unstated never ranked; `movement_hash`. Unit tests across every transition + determinism. | Movement |
| 177 ✅ | JSON + tab | `posture_movement` JSON block; a mobile-safe "Posture movement" comparison-complete card; UI wiring (base posture + active playbook threaded through the comparison). | Movement |
| 178 ✅ | Headless movement | CLI `compare --playbook-file <path> --posture` → `posture_movement` JSON / Markdown table. | Movement |

Total work: **3 build steps (176–178), all shipped.** Thrust A is the foundation and is additive — a comparison run with no positions yields no movement, so the comparison `result_hash` never moves. Every surface is render-side; zero golden churn.

---

# Part XVI — Principled deferrals

- **A DOCX/HTML comparison-report section.** v11 surfaces the movement in the comparison JSON, the tab, and the CLI. Rendering it into the Word and standalone-HTML comparison reports is a clean, additive follow-up (the exact v9/v10 surface-threading pattern), deferred only to bound this thrust — not a posture question.
- **A CI `--fail-on-regression` gate.** `compare --posture` reports the movement; a flag that exits non-zero when any dimension regressed (or fell below floor) would make it a hard gate, exactly as `--fail-on` does for the introduced-finding bucket. Deferred; the recommendation mirrors v10's "advisory-only" default — a team that wants a hard gate composes it from the JSON today.
- **Three-rung movement.** If v10 ever grows a third authored rung (ideal / target / reservation), `TIER_RANK` is the single place to extend the order; the movement classifier needs no other change. Noted, not built (v10 ships two rungs).
- **Cross-document posture movement.** Computing how a posture moved across a *bundle* (the MSA's cap vs. the SOW's, version-over-version) sits on the v4 cross-document axis, not this one; noted for a future spec, as in v10.

---

# Part XVII — Open questions for the maintainer

1. **Rank `unevaluable` as the bottom rung?** Today `unevaluable` is unranked, so *not-stated → below-floor* is `newly-stated`, not `regressed`. Recommendation: **keep it unranked** — the v10 §3 contract is explicit that "not stated" must never be conflated with "below floor," and a negotiator reads `newly-stated` as "they put it on the table" rather than a false regression.
2. **Surface the movement on the single-document tab too?** A user could compare a draft against a *prior saved posture* without re-running both. Recommendation: **comparison-only in v11** — it keeps the one ladder and the two drafts in a single, auditable run; a saved-posture import is a larger surface deferred until asked.

---

# Part XVIII — What this gives the user

- **Your ladder, tracked round-over-round.** Encode your positions once. Drop the counterparty's first draft, then their counter — and the comparison tells you, on every front at once, *which way each rung moved*: improved, regressed, unchanged, newly-stated, or now-unstated. The snapshot v10 gave you becomes the trajectory you actually negotiate on.
- **Deterministic, where every other tool guesses.** A language-model "negotiation tracker" reads two drafts and produces a confident, different summary every time. v11 compares two pure tier classifications and gets the same movement, byte-for-byte, on any machine — a trajectory a partner can sign off on and a client can reproduce.
- **The same five promises.** Deterministic, no AI, no server, citable, never drafts — every line of v11 passes the §3 gate. The movement derives from two postures that each cite your own playbook and the document's own clause; an unstated front is never a false regression; and the thing you most need between rounds — *which way did this revision move me* — is computed without a model and without a server.
