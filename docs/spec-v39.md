# Vaulytica v39 — Document-Free Exposure Cadence (How Often a Front Flips, Not How Long It Stays — the Churn Mirror of v31's Dwell)

> **Status:** **Shipped (9.36.0).** v31 gave the posture archive its **dwell** axis (what *share* of a front's stated span sat below floor — how *long* a front is an unaccepted position). v24 gave it the **count** axis (how *many times* a front's standing crosses the floor). Neither reads the **rate**: across the transitions a front actually had, how *often* did it flip across the floor? Two fronts with identical below-floor share — both below half their stated rounds — can be opposites: one dips once and holds (a steady concession), the other alternates every round (a flickering, never-settled front). v31 calls them the same; v24, gating on the raw count, calls a front that crossed twice in twenty transitions just as `volatile` as one that crossed twice in two. v39 is the **churn mirror of v31's dwell**: per front, the floor crossings normalized by its transition opportunities (`crossings / transitions`), gated on the one tuning-free condition — a front that crossed for a strict **majority** of its transitions (`--fail-on-oscillating-front`): it flips sides more often than it holds one. It continues the global step numbering after v38's Step 218, beginning at **Step 219**. One new subcommand, one pure module, **zero** change to any existing source file.
> **Scope:** one idea — the *churn* counterpart to v31's *occupancy*. v31 reads how **long** a front stays on a side; v39 reads how **often** it changes sides. It is not a new crossing, ordering, or pairwise read; it scans the same per-front crossing events v24 already counts (`coherence-volatility`) and normalizes them by the transitions between the rounds that *stated* the front, asking "did this front flip across the floor more often than it held a side?" The use case is the front that can never settle: v31 says "Cap was below floor 3 of 6 rounds"; v24 says "Cap crossed the floor twice"; v39 says "but **Term** flipped on **all five** of its transitions — every round reopens what the last one closed." Where v31 names the *standing burden* and v24 the *count*, v39 names the *instability rate* — orthogonal to both.
> **Posture (unchanged, non-negotiable):** deterministic (the cadence verdict is a pure scan over the binding floors v12 derived — crossings counted by the same silence-skipping pass v24 uses, the busiest-cadence pick decided by *integer cross-multiplication* (`crossings × transitions`), the gate a strict-majority integer comparison (`crossings × 2 > transitions`); no float threshold enters the verdict, so the same artifacts → identical `cadence_hash`, on any machine, forever), no AI / no probabilistic path, no server (N local files in, one report out; no socket), citable (the artifacts carry the same per-front binding floors v12 derived from each document's own clause and the team's own playbook — v39 adds no new claim), lints / references / positions — but never drafts, and never renders a legal conclusion. The command is **advisory and verifiable**: every artifact is hash-verified (a tampered round is a hard error, side-labeled by round index), and the ladders are checked for a match across the _whole_ sequence (any cross-ladder pair is refused) via the same `verifyCoherenceSequence` loader the twenty-two trend/exposure/persistence/breadth/recurrence/volatility/synchrony/settling/onset/latency/concurrency/relapse/tenure/affinity/recovery-affinity/opposition/precedence/concession/recovery-order/weak-front commands use, unchanged. Every step passes the §3 filter or it does not ship.
> **Cousin docs:** [`spec.md`](spec.md) (v1, the linter), [`spec-v8.md`](spec-v8.md) (Reach — the headless CLI this rides on), [`spec-v10.md`](spec-v10.md) (Negotiation Posture — the **rung ladder** and the `below-acceptable` floor), [`spec-v12.md`](spec-v12.md) (Posture Coherence — the artifact's payload and the **binding floor** `weakest_tier`), [`spec-v14.md`](spec-v14.md) (Saved Coherence Baselines — the artifact this consumes), [`spec-v15.md`](spec-v15.md) (Ladder-Pinned Coherence Baselines — the cross-ladder guard), [`spec-v24.md`](spec-v24.md) (Document-Free Exposure Volatility — **the crossing *count* this normalizes**), [`spec-v31.md`](spec-v31.md) (Document-Free Exposure Tenure — **the *dwell* this mirrors; v39 reads churn where v31 reads occupancy**). Progress in [`BUILD_PROGRESS.md`](../BUILD_PROGRESS.md).

---

# Part 0 — Intent

## §1. Why we're doing this

v38's Open Question #1 named the next axis explicitly: with the pairwise-precedence family and its first synthesis complete, the natural next reads are *magnitude* or **a fresh per-front cadence read (below/above oscillation rate)**, not another pairwise direction or conjunction. v39 is that per-front cadence.

The archive already has two per-front reads of the below-floor data that v39 sits between:

- **v31 (tenure / dwell):** what *share* of a front's stated rounds sat below floor. It answers "how long was this front an unaccepted position?" — the standing burden. But a front below floor 3 of 6 rounds could have been below for a single unbroken stretch (one concession that held) or below on alternating rounds (a flickering standing). v31 cannot tell them apart — same share, opposite stability.
- **v24 (volatility / count):** how *many times* a front's standing crossed the floor. It answers "how many times did this front change sides?" — but blind to *opportunity*. A front that crossed twice across twenty transitions trips v24's `≥ 2` gate exactly as a front that crossed twice across two; the first is occasionally noisy, the second never holds a side, and v24 calls them the same.

The missing read is the **rate**: crossings normalized by the transitions that could have carried one. That is the signal a deal lead watching for an unstable front actually wants:

- **The oscillating front.** Term is stated in six rounds and crosses the floor on all five of its transitions — a 100% cadence. Every round reopens what the last one closed; the counterparty concedes and reclaims it in lockstep. It is the front that never settles, and the one a deal lead cannot bank as resolved.
- **The settled front (cleared).** Cap is stated in six rounds, dips below floor once at round 4, and holds — one crossing in five transitions, a 20% cadence. v24 may call it `monotone`/`volatile` by raw count, but its standing is stable; the cadence gate clears it.

To v31 and v24 read alone this rate is invisible — v31 throws away the order of the below-floor rounds (it counts a share), and v24 throws away the denominator (it counts crossings, not transitions). v39 supplies the normalization and the one verdict whose meaning needs no tuning: per front, the `crossings`, the `transitions` (= `stated_rounds − 1`), the `cadence` (`crossings / transitions`), a `class` (`oscillating` / `settled` / `static` / `unstated`), and the deal's `busiest_dimension` / `max_cadence` and `oscillating` gate. All of it is a scan over the same `floors[]` the whole family reads — no new event, no new ordering, no new float.

## §2. What v39 is and is not

**It is:**

- A **document-free exposure-cadence command.** `coherence-cadence <r1.coherence.json> … <rN.coherence.json>` reads N ≥ 2 saved coherence artifacts in round order, verifies each, runs the cross-ladder guard across all of them, and prints, per **front**, the floor `crossings` (both directions) out of its `transitions` (the comparisons between consecutive *stated* rounds), the `cadence` (the flip rate), and its `class` — plus the deal's `busiest_dimension` (the highest cadence), `max_cadence`, `total_crossings` (= v24's `crossings` summed), `total_transitions`, and `oscillating` (the gate verdict). Markdown (default) or `--format json`. No documents are read; the engine is never run.
- A **single deal-level per-front gate, on the rate.** `--fail-on-oscillating-front` exits 2 when at least one front crossed the floor for a strict **majority** of its transitions (`crossings × 2 > transitions`) — a front that flips sides more often than it holds one. A strict majority of the transitions (held sides working against it) *is* "this front flips more often than not"; the gate inherits no knob.
- A **whole-sequence-verified input, sharing the v17–v38 front end.** Every artifact's `coherence_hash` is re-derived and checked on load (a tampered/corrupt round is a hard error, errors prefixed `round N:`). The v15/v16 cross-ladder guard runs across the sequence via the same `verifyCoherenceSequence` loader the twenty-two trend/exposure/…/weak-front commands use, with no change to it.
- A **derived report carrying its own fingerprint.** The report carries a `cadence_hash` (a stable SHA-256 over the canonical per-front set — the front, its `floors`, `stated_rounds`, `transitions`, `crossings`, and `class`; the derived float `cadence`, the `busiest_dimension`, `max_cadence`, and `oscillating` are omitted, so the fingerprint is integer-exact over the inputs), namespaced apart from every prior hash (`coherence_hash`, …, `weak_front_hash`), so the same N artifacts in the same order always reproduce the same report.

**It is not:**

- **Not a new diff, classifier, predicate, ordering, or artifact format.** It scans the same crossing events v24 already counts — no new fall, recovery, crossing, or ordering math. v39 is a subcommand plus one pure module (`computeCoherenceCadence`) whose only new logic is the per-front normalization of crossings by transitions. `parsePostureCoherenceJson`, the coherence schema, and every other function are unchanged.
- **Not the volatility command (v24).** v24 gates on the **raw crossing count** (`≥ 2 ⟹ volatile`), blind to opportunity. v39 gates on the **rate** (`crossings × 2 > transitions`). A front that crossed twice in twenty transitions is `volatile` to v24 but `settled` here (a 10% rate); a front that crossed once in its single transition is `monotone` to v24 but `oscillating` here (a 100% rate). They genuinely diverge.
- **Not the tenure command (v31).** v31 reads the *dwell* (the below-floor occupancy share); v39 reads the *churn* (the flip rate). A front below floor for rounds 1–3 of 6 that holds is a `majority` tenure but a `settled` cadence (one crossing in five transitions); a front flipping every round is a `minority` tenure (below half the time) but `oscillating` here. Same dwell, opposite churn — and vice versa.
- **Not a depth- or duration-weighted score.** The floor is binary (`below-acceptable` is the only sub-floor rung), so depth-weighting is not viable; a duration weighting is a magnitude read (the deferred mean-lead-time / mean-below-duration), orthogonal to a flip rate.
- **Not a configurable "flips at least K times" gate.** v39 does not take a `--min-crossings K` knob; the gate fires on a strict majority of the transitions, already tuning-free. The per-front counts are in the JSON for a consumer that wants a different bar.
- **Not a cadence artifact.** v39 introduces no new on-disk format; the report is _derived_, recomputed on demand from the N auditable coherence inputs.
- **Not a sequence the command discovers.** It takes the artifacts **in round order** on the argv, exactly as the twenty-two trend/exposure/… commands do.
- **Not a browser surface.** An N-round per-front cadence synthesis of uploaded artifacts is a CI/dashboard concern (mirroring v16–v38).

## §3. The posture filter (unchanged)

1. **Deterministic** — `computeCoherenceCadence` over N `PostureCoherence` objects is pure: it scans each front's binding floors in one silence-skipping pass (the v24 scan, `localeCompare`-pinned front order), counts `crossings` and `stated_rounds`, derives `transitions = stated_rounds − 1`, and picks the busiest cadence by **integer cross-multiplication** (`crossings × transitions`, earliest label on a tie), never a float compare. The gate is the integer test `crossings × 2 > transitions`. Identical artifacts in identical order → identical `cadence_hash` on any machine.
2. **Honest about unstated data** — a front no document states in a round contributes no transition into or out of it: silence is neither a crossing nor a held side (the §3 contract that keeps `below → unstated → below` zero crossings in v24/v35). The denominator counts only the transitions between consecutive *stated* rounds, so a crossing across a silent gap is attributed to the transition into the round that *reveals* the new standing, never diluted by the silent rounds. A front stated in fewer than two rounds has no transition and carries no cadence (`static`), never ranked; a front no document ever states is `unstated`.
3. **Advisory** — the command names how often each front flipped across the team's own floor. It asserts no legal conclusion.
4. **No server** — N local files in, one report out. No socket, no engine run.
5. **Additive** — a brand-new subcommand and one new pure module. Every existing command (`analyze`, `diff`, `compare`, `compare-coherence`, `coherence-trend`, …, `coherence-weak-front`, `verify`) is byte-for-byte unchanged in _output and goldens_; `coherence-sequence.ts` is imported and reused **without modification** (v39 needs nothing exported that was not already public — like v19–v38, it touches no existing source file's behavior at all).

---

# Part I — The report (pure)

`src/report/coherence-cadence.ts` (a new sibling to `coherence-tenure.ts`):

- **`CadenceClass`** — a front's churn class: `oscillating` (crossed for a strict majority of its transitions, `crossings × 2 > transitions` — flips more often than it holds, the gate-worthy class), `settled` (has ≥ 1 transition but did not cross for a strict majority of them — including zero crossings and an exact split), `static` (stated in exactly one round — no transition to register a crossing over), `unstated` (no document ever stated the front).
- **`CoherenceCadenceFront`** — one front's whole-sequence churn: the `dimension`, the `floors` (binding floor at each round, `null` = unstated), `stated_rounds`, `transitions` (`max(0, stated_rounds − 1)`), `crossings`, `cadence` (`crossings / transitions`, `null` when no transition), and its `class`.
- **`CoherenceCadence`** — the whole-sequence reduction: `rounds` (count), `fronts[]` (the entries above, pinned by `dimension`), `class_counts` (the per-front tally by class), `total_crossings` (= v24's `crossings` summed), `total_transitions`, `max_cadence` (the highest flip rate, `null` when no front ever crossed), `busiest_dimension` (the front owning it, earliest label on a tie), `oscillating` (`≥ 1` oscillating front — the gate verdict), and `cadence_hash`.
- **`computeCoherenceCadence(rounds: PostureCoherence[])`** — the pure, IO-free core. Scans each front's binding floors, counts crossings and stated rounds in one pass, derives transitions and the cadence, classifies each front, selects the busiest by integer cross-multiplication, and returns the reduction with a `cadence_hash`. Requires ≥ 2 rounds (a crossing is a between-round event).
- **`exposureOscillates(cadence)`** — the CI gate predicate: `cadence.oscillating`. The rate read no other command exposes (v24 gates on the count; v31 on the dwell; neither normalizes crossings by opportunity).
- **`buildCoherenceCadenceJson(cadence)`** / **`renderCoherenceCadenceSummary(cadence)`** — the JSON (`schema: vaulytica.posture-cadence.v1`) and human-readable renderers. The summary prints the busiest churn (the front and its flip rate, or none-crossed when no front ever flipped), the class tally, then one line per front that crossed in any transition (`oscillating` first), then the hash.

v39 imports the already-public `PostureCoherence` and `NegotiationTier` types and the shared hashing helpers; no existing source file changes.

# Part II — The command (headless)

`tools/cli/coherence-cadence.ts` (a new sibling to `coherence-tenure.ts`):

- **`computeCoherenceCadenceArtifacts(texts, format?)`** — the pure CLI core. Verifies all N artifacts and runs the cross-ladder guard via the shared `verifyCoherenceSequence` loader (unchanged from v18–v38); on any malformed/tampered round returns `{ ok: false, errors }` (each prefixed `round N:`); on a cross-ladder pair returns `{ ok: false }` naming the two rounds; an unpinned artifact yields `{ ok: true }` with a `ladderNote`. Then `computeCoherenceCadence(rounds)` and renders (markdown summary or JSON), returning `{ ok: true, output, oscillating, ladderNote }`.
- **`runCoherenceCadence(argv)`** — the CLI handler: reads the N files, calls the core, writes the `ladderNote` (if any) to stderr, prints the report to stdout, and — under `--fail-on-oscillating-front` — exits 2 when any front crossed for a strict majority of its transitions. A malformed/tampered/cross-ladder input is a hard exit-1 error. Requires ≥ 2 positionals.

`tools/cli/run.ts` (the dispatcher) gains a `coherence-cadence` case and a `USAGE` entry.

```
# Each round, archive its coherence (kilobytes, no clause text):
vaulytica analyze 'round1/*.docx' --playbook-file team.playbook.json --posture --emit-coherence round1.coherence.json
vaulytica analyze 'round2/*.docx' --playbook-file team.playbook.json --posture --emit-coherence round2.coherence.json
vaulytica analyze 'round3/*.docx' --playbook-file team.playbook.json --posture --emit-coherence round3.coherence.json

# Later — name the deal's never-settling fronts (flip more often than they hold), from the archive alone:
vaulytica coherence-cadence round1.coherence.json round2.coherence.json round3.coherence.json \
  --fail-on-oscillating-front
```

---

# Part XV — Build plan

Continuing the global numbering after v38's Step 218. Verification gate for every step: `npm run typecheck && lint && test && build` green; the v7 coverage/parity/property gates, the v8 fuzz + citation gates, the v9 no-wall-clock gate, and the responsiveness e2e stay green.

Status legend: **✅ shipped** · ⬜ proposed.

| #      | Step                                              | Output | Tier  |
| ------ | ------------------------------------------------- | ----- | ----- |
| 219 ✅ | `coherence-cadence` per-front floor-crossing churn rate & gate | `src/report/coherence-cadence.ts` — `CadenceClass`, `CoherenceCadenceFront`, `CoherenceCadence`, pure `computeCoherenceCadence` (scans each front's binding floors for `crossings` over its `transitions`, derives the `cadence`, classifies `oscillating`/`settled`/`static`/`unstated`, picks the busiest by integer cross-multiplication, deal-level `total_crossings` = v24's summed + `oscillating` gate; namespaced integer-exact `cadence_hash`), `exposureOscillates` predicate (= `oscillating`), JSON + markdown renderers. `tools/cli/coherence-cadence.ts` — `computeCoherenceCadenceArtifacts` (pure, reusing `verifyCoherenceSequence` unchanged) + `runCoherenceCadence` (file IO + exit codes); dispatcher + `USAGE` wired. Tests: cadence identity disk-vs-in-memory, the clear oscillating front vs the settled one, the v24-distinctness case (a `volatile` front that is `settled` here, `total_crossings` = v24's summed), the v31-distinctness case (same below-floor dwell, opposite churn), the §3 silent-gap rule, the `static` single-appearance front, the `unstated`/never-crossed front, the busiest pick by integer ratio (ratio beats label order), tie-break by earliest label, determinism, ≥2-round requirement, cross-ladder refusal across the sequence (naming the two rounds), unpinned-v1 note, tamper rejection (round-prefixed), gate parity, render + JSON. Every existing command's suite passes unchanged. | Reach |

Total work shipped this spec: **1 build step (219).** Purely additive — a new subcommand and one pure module that normalizes the same crossings v24 already counts by the transitions between stated rounds; **no existing source file's behavior changes** (v39 needs nothing newly exported), and every existing command's output and golden is unchanged.

---

# Part XVI — Principled deferrals

- **A magnitude read (mean below-floor duration / mean lead-time, in rounds).** ⬜ Not built. v39 reads the *rate* of flips (an integer count over an integer denominator); the *length* of each below-floor stretch is the deferred magnitude axis (v37/v38 Part XVI's mean-lead-time), a float read orthogonal to a flip rate.
- **A direction-resolved cadence (fall rate vs recovery rate).** ⬜ Not built. A front's falls and recoveries differ by at most one (they alternate), so a per-direction rate carries almost no information beyond the total; v39 reads the direction-blind crossing rate, as v24 counts direction-blind crossings.
- **A configurable "flips at least K times" gate (`--min-crossings K`).** ⬜ Not built. The gate fires on a strict majority of the transitions, already tuning-free. The per-front counts are in the JSON for a consumer wanting a different bar.
- **A standalone cadence artifact (`--emit-cadence`).** ⬜ Deferred, for the same reason v14–v38 keep the derived thing derived: the report is cheaply recomputable from the N coherence artifacts on demand.
- **A directory/glob walker that infers round order.** ⬜ Not built. The command takes artifacts in round order on the argv (the caller's contract, mirroring the twenty-two trend/exposure/… commands).
- **A browser surface for an N-round cadence synthesis.** ⬜ Deferred (v16–v38 Part XVI). The browser does an in-session two-round comparison; an N-artifact per-front churn read is a CI/dashboard concern.

---

# Part XVII — Open questions for the maintainer

1. **Is the per-front family now complete on the binary floor?** v20 (level), v21 (time), v23 (recurrence), v24 (count), v26/v27 (settling/onset), v28/v30 (latency/relapse), v31 (dwell), and v39 (churn rate) cover the per-front below-floor reads the binary floor admits. Recommendation: **treat the per-front rung axes as complete** — the remaining genuinely-new directions are *magnitude* (mean below-floor duration / mean lead-time, in rounds — a float read) or a *2-D* read (per-front × per-step), not another normalization of the same crossings.
2. **Should the busiest-churn headline restrict to oscillating fronts?** Today `busiest_dimension` is the highest cadence among *all* fronts that ever crossed (so a deal with no oscillating front still names its busiest); the `oscillating` gate is separate. Recommendation: **keep the headline broad** — the busiest front is informative even when below the strict-majority bar, and the gate verdict is one field away.

---

# Part XVIII — What this gives the user

- **The deal's never-settling fronts, named from the archive alone.** Archive each round's kilobyte coherence artifact as you go; `coherence-cadence` normalizes each front's floor crossings by its transition opportunities — naming the front that flips sides more often than it holds one, the one a deal lead cannot bank as resolved because every round reopens it. It distinguishes the *oscillating* front (a high flip rate) from the merely *long-suffering* one (a high dwell, v31) and the merely *occasionally-noisy* one (a high raw count over many transitions, v24), with no clause text checked out and no re-analysis run.
- **A gate on instability, not on duration or count.** `--fail-on-oscillating-front` fires only when a front crossed the floor for a strict **majority** of its transitions — orthogonal to v24's count gate (blind to opportunity) and v31's dwell gate (blind to order). It catches the front whose standing never stabilizes, which a level, time, recurrence, count, or occupancy read structurally cannot isolate, because none of them divide crossings by the opportunities to cross.
- **The same five promises.** Deterministic, no AI, no server, citable, never drafts — every line of v39 passes the §3 gate. It scans the same `floors[]` v24 reads, through the loader v18–v38 already share; it adds one per-front normalization over those crossings, no on-disk format, and no change to any existing source file's behavior — every existing surface is byte-for-byte unchanged.
