# Vaulytica v18 — Document-Free Coherence-Shift Trajectory

> **Status:** **Shipped (9.15.0).** v17 answered "across the whole negotiation, did each front's binding *floor* climb, slide, or whipsaw?" — but the floor was never the only signal. Since v13, every cross-document movement has carried a *second* axis beside the floor: did the package **fracture** (a position the documents agreed on now disagrees with itself) or **reconcile** (a divergent front closed up)? v16/v17 archived each round's coherence kind in the artifact but classified the *trajectory* on the floor only. v18 classifies the trajectory on that second axis: across round 1 → round 2 → … → round N, did each front fracture steadily, reconcile steadily, or **oscillate** (split apart and re-merge — a fracture in the middle that a first-vs-last diff would call `unchanged` and hide)? It continues the global step numbering after v17's Step 197, beginning at **Step 198**. One new subcommand, zero new posture math: it composes v16/v17's verified-parse + cross-ladder guard with the existing v13 fracture/reconcile classifier, applied consecutively down the same N artifacts v17 already walks.
> **Scope:** one idea, sitting one axis over from v17 — the fracture/reconcile companion to the floor whipsaw, the exact pairing v13 has where it reports *both* `floor_movement` *and* `coherence_shift` per front. The posture matrix's last open cell on the document-free row: v16 a two-round *movement* (floor + shift), v17 the N-round *floor* trajectory, v18 the N-round *shift* trajectory. It is to v17 what v13's `coherence_shift` is to its `floor_movement`: the same sequence, read on the agreement axis instead of the exposure axis. The use case is the same dashboard or audit log that archived every round's kilobyte coherence artifact and now wants the deal-level *coherence* arc: *which fronts the package steadily split on, which it steadily closed up, and which round-tripped through a fracture the counterparty walked back.*
> **Posture (unchanged, non-negotiable):** deterministic (the trajectory is the same pure fracture/reconcile classifier — `classifyShift`, shared with v13 — applied to each consecutive pair of N `PostureCoherence` objects; same artifacts → identical `shift_trajectory_hash`, on any machine, forever), no AI / no probabilistic path, no server (N local files in, one summary out; no socket), citable (the artifacts carry the same per-front, per-document coherence kinds v12 derived from each document's own clause and the team's own playbook — v18 adds no new claim), lints / references / positions — but never drafts, and never renders a legal conclusion. The command is **advisory and verifiable**: every artifact is hash-verified (a tampered round is a hard error, side-labeled by round index), the ladders are checked for a match across the *whole* sequence (any cross-ladder pair is refused), and the trajectory it prints is the same advisory fracture/reconcile signal v13 produces, accumulated down the sequence. Every step passes the §3 filter or it does not ship.
> **Cousin docs:** [`spec.md`](spec.md) (v1, the linter), [`spec-v8.md`](spec-v8.md) (Reach — the headless CLI this rides on; `diff`/`compare`/`compare-coherence`/`coherence-trend` are its sibling subcommands), [`spec-v12.md`](spec-v12.md) (Posture Coherence — the artifact's payload, where the `aligned`/`divergent`/`single`/`unstated` kind is defined), [`spec-v13.md`](spec-v13.md) (Cross-Document Posture Movement — **the fracture/reconcile `coherence_shift` this accumulates; `classifyShift` is shared from here**), [`spec-v14.md`](spec-v14.md) (Saved Coherence Baselines — the artifact this consumes), [`spec-v15.md`](spec-v15.md) (Ladder-Pinned Coherence Baselines — the cross-ladder guard, run across the whole sequence), [`spec-v16.md`](spec-v16.md) (Document-Free Coherence Movement — the two-artifact command), [`spec-v17.md`](spec-v17.md) (Document-Free Coherence Trajectory — **the floor trajectory this runs beside; Part XVII open question #2 deferred exactly this shift trajectory, and the shared sequence loader is factored from its CLI**). Progress in [`BUILD_PROGRESS.md`](../BUILD_PROGRESS.md).

---

# Part 0 — Intent

## §1. Why we're doing this

v17's Part XVII open question #2 named this command by recommendation-to-defer: "v13 reports a per-step `coherence_shift`; v17 carries each round's coherence kind but classifies the trajectory on the binding floor only. A 'this front fractured in round 3 and reconciled by round 5' path is the advisory companion to the floor whipsaw." That deferral was correct that the floor is *the exposure-governing* signal — but the coherence kind is a *different* signal, not a weaker floor. The floor says **how bad the worst rung is**; the coherence kind says **whether the package agrees with itself**. A bundle can hold its floor steady while quietly fracturing (two documents that both said "cap = 1×" now say "1×" and "2×" — the floor is unchanged, but the package no longer speaks with one voice), and that fracture is exactly what a deal lead reconciling a multi-document package needs to see.

v17 classified the trajectory on the floor only because the floor is the gate-worthy headline. But the per-round coherence kinds were *already in the artifact* (v12 wrote them; v14 preserved them; v17 carried them in `coherences[]` but never reduced them). v18 reduces them — the same way v17 reduced the floors — and surfaces the two signals that only exist at the level of the whole sequence:

1. **The net agreement direction.** Did the package on the cap end the negotiation more split or more unified than it started? A consumer can diff the first and last artifacts — but then it has thrown away every round in between.
2. **The path — the oscillation.** Did the cap *fracture in round 3 and reconcile by round 5*? A first-vs-last diff reports `unchanged` and hides it. N−1 independent pairwise `compare-coherence` runs each report one step but never say "this front split and re-merged across the deal." A recovered fracture is a real signal: it tells you where the counterparty's documents pulled apart, even though they walked it back.

This is the same relationship v17 has to a pairwise floor diff, read on the coherence axis. The composition is small because everything it needs already exists and is already tested: `parsePostureCoherenceJson` (v14) verifies each artifact and surfaces its ladder pin; the v16 cross-ladder guard generalizes across all pins (now shared with v17 in one loader); `classifyShift` (the v13 fracture/reconcile classifier, now exported from `coherence-movement.ts`) classifies each consecutive step; and a tiny pure reducer rolls the per-step shifts into a per-front trajectory. v18 adds **no** posture math — it applies the existing classifier consecutively and counts the results.

## §2. What v18 is and is not

**It is:**
- A **document-free coherence-shift trajectory command.** `coherence-shift-trend <r1.coherence.json> <r2.coherence.json> … <rN.coherence.json>` reads N ≥ 2 saved coherence artifacts in round order, verifies each, runs the cross-ladder guard across all of them, and prints, per negotiation front, the coherence kind at each round, the consecutive shifts, the **net** shift (round 1 → round N), and a **shift trajectory** classification — `steady-fracture`, `steady-reconcile`, `oscillating`, or `stable`. Markdown (default) or `--format json`. No documents are read; the engine is never run.
- A **CI gate primitive over a whole negotiation, on the agreement axis.** `--fail-on-fracture` exits 2 when any front's package fractured at **any step** of the sequence — strictly stronger than a first-vs-last diff, and deliberately so: it catches a transient fracture even when the front reconciled by the final round. (A consumer wanting the weaker net-only gate reads `net_shift_counts.fractured` from the JSON.)
- A **whole-sequence-verified input, sharing v17's front end.** Every artifact's `coherence_hash` is re-derived and checked on load (a tampered/corrupt round is a hard error, errors prefixed `round N:`). The v15/v16 cross-ladder guard runs across the sequence via the same `verifyCoherenceSequence` loader `coherence-trend` now uses: if two or more artifacts are ladder-pinned (`v2`) and any two pins differ, the trend is refused (exit 1); an unpinned (`v1`) artifact anywhere proceeds with a note.

**It is not:**
- **Not a new diff, predicate, classifier, or artifact format.** `classifyShift`, `parsePostureCoherenceJson`, the `v1`/`v2` coherence schema, and the `aligned`/`divergent`/`single`/`unstated` kind are all unchanged; `compareCoherence` and `compareCoherenceTrajectory` are unchanged (the shift trajectory shares v13's classifier, not v17's shape). v18 is a subcommand plus one pure reducer (`compareCoherenceShiftTrajectory`) that composes them.
- **Not a replacement for `coherence-trend`.** It is the *companion*. The floor trajectory governs exposure and stays the headline; the shift trajectory is the advisory agreement signal beside it. A team that wants both runs both commands on the same N artifacts (one shared loader, two trajectories).
- **Not a movement/trajectory artifact.** v18 does not introduce a new on-disk format; the trajectory is *derived*, recomputed on demand from the N auditable coherence inputs — the same "keep the derived thing derived" discipline v14–v17 hold.
- **Not a sequence the command discovers.** It does not glob a directory or sort filenames; the caller passes the artifacts **in round order** on the argv, exactly as `coherence-trend` does (Part XVI).
- **Not a browser surface.** An N-round trend of uploaded artifacts is a CI/dashboard concern, which is what this command serves (Part XVI).

## §3. The posture filter (unchanged)

1. **Deterministic** — `compareCoherenceShiftTrajectory` over N `PostureCoherence` objects is pure; identical artifacts in identical order → identical `shift_trajectory_hash` on any machine. Fronts are pinned by `localeCompare(_, "en")`; the round order is the caller's. The N parses and the ladder compare add no nondeterminism.
2. **Honest about absent fronts** — a step where the front is absent on either side (it appeared or dropped that round) carries no fracture/reconcile signal and classifies as `unchanged` (the same defensive contract v13's `compareCoherence` holds for a missing side); a `realigned` step (the stating set changed without crossing the divergence line) is never counted as a fracture or a reconcile. A front that only ever realigns or appears is `stable`, never a false oscillation.
3. **Advisory** — the command prints a trajectory and, optionally, gates on a fracture. It asserts no legal conclusion.
4. **No server** — N local files in, one summary out. No socket, no engine run.
5. **Additive** — a brand-new subcommand and one new pure module. Every existing command (`analyze`, `diff`, `compare`, `compare-coherence`, `coherence-trend`, `verify`) is byte-for-byte unchanged in *output and goldens*; `coherence-movement.ts` changes only by *exporting* an existing private function (`classifyShift`); and `coherence-trend.ts`'s parse + cross-ladder guard is factored into a shared `coherence-sequence.ts` loader with no change to its behavior, errors, or exit codes (its full test suite passes unchanged).

---

# Part I — The classifier (pure)

`src/report/coherence-shift-trajectory.ts` (a new sibling to `coherence-trajectory.ts`):

- **`CoherenceShiftTrajectoryKind`** — how a front's coherence kind moved across the *whole* sequence:
  - `steady-fracture` — at least one step fractured and **no** step reconciled.
  - `steady-reconcile` — at least one step reconciled and **no** step fractured.
  - `oscillating` — at least one step fractured **and** at least one step reconciled (the package split and re-merged; the signal a first-vs-last diff hides).
  - `stable` — no *directional* shift at any step (only `realigned` / `unchanged` steps). A front whose stating set changed without ever crossing the divergence line is `stable` — honest, never a false oscillation.
- **`compareCoherenceShiftTrajectory(rounds: PostureCoherence[])`** — the pure, IO-free core. Matches fronts by dimension across the union of all rounds (pinned by `localeCompare`); for each front builds the coherence kind at each round (`null` = absent that round) and the shift at each consecutive step via a null-tolerant wrapper over the shared `classifyShift`, computes the **net** shift as the round-1-vs-round-N shift, reduces the steps to a `CoherenceShiftTrajectoryKind`, and returns the per-front set plus `shift_trajectory_counts`, `net_shift_counts`, and a `shift_trajectory_hash` (SHA-256 over the canonical per-front set, namespaced apart from every `coherence_hash`/`movement_hash`/`trajectory_hash`).
- **`shiftTrajectoryFractured(t)`** — the CI gate predicate: true when any front's trajectory is `steady-fracture` or `oscillating` (i.e. the package fractured at *some* step). The fracture/reconcile companion to v17's `trajectoryRegressed`.
- **`buildCoherenceShiftTrajectoryJson(t)`** / **`renderCoherenceShiftTrajectorySummary(t)`** — the JSON (`schema: vaulytica.posture-shift-trajectory.v1`) and human-readable renderers, beside their movement-module siblings.

`classifyShift` was a private helper in `coherence-movement.ts`; v18 **exports** it (no behavior change) so the trajectory reuses the one fracture/reconcile classifier rather than re-deriving it — exactly as v17 exported `classifyFloorMovement`.

# Part II — The command (headless)

`tools/cli/coherence-shift-trend.ts` (a new sibling to `coherence-trend.ts`):

- **`compareCoherenceShiftTrendArtifacts(texts, format?)`** — the pure CLI core. Verifies all N artifacts and runs the cross-ladder guard via the shared `verifyCoherenceSequence` loader; on any malformed/tampered round returns `{ ok: false, errors }` (each prefixed `round N:`); on a cross-ladder pair returns `{ ok: false }` naming the two rounds; an unpinned artifact yields `{ ok: true }` with a `ladderNote`. Then `compareCoherenceShiftTrajectory(rounds)` and renders (markdown summary or JSON), returning `{ ok: true, output, fractured, ladderNote }`.
- **`runCoherenceShiftTrend(argv)`** — the CLI handler: reads the N files, calls the core, writes the `ladderNote` (if any) to stderr, prints the trajectory to stdout, and — under `--fail-on-fracture` — exits 2 on a fracture. A malformed/tampered/cross-ladder input is a hard exit-1 error. Requires ≥ 2 positionals.

`tools/cli/coherence-sequence.ts` (new shared loader) — `verifyCoherenceSequence(texts)`: the parse + hash-verify + cross-ladder guard front end, factored out of `coherence-trend.ts` so both trend commands share one verified-input path. `tools/cli/run.ts` (the dispatcher) gains a `coherence-shift-trend` case and a `USAGE` entry.

```
# Each round, archive its coherence (kilobytes, no clause text):
vaulytica analyze 'round1/*.docx' --playbook-file team.playbook.json --posture --emit-coherence round1.coherence.json
vaulytica analyze 'round2/*.docx' --playbook-file team.playbook.json --posture --emit-coherence round2.coherence.json
vaulytica analyze 'round3/*.docx' --playbook-file team.playbook.json --posture --emit-coherence round3.coherence.json

# Later — read/gate the whole-deal *agreement* arc from the archive alone, no documents:
vaulytica coherence-shift-trend round1.coherence.json round2.coherence.json round3.coherence.json \
  --fail-on-fracture
```

---

# Part XV — Build plan

Continuing the global numbering after v17's Step 197. Verification gate for every step: `npm run typecheck && lint && test && build` green; the v7 coverage/parity/property gates, the v8 fuzz + citation gates, the v9 no-wall-clock gate, and the responsiveness e2e stay green.

Status legend: **✅ shipped** · ⬜ proposed.

| # | Step | Output | Tier |
|---|------|--------|------|
| 198 ✅ | `coherence-shift-trend` trajectory | `src/report/coherence-shift-trajectory.ts` — `CoherenceShiftTrajectoryKind`, pure `compareCoherenceShiftTrajectory` (per-front coherences/shifts/steps + net + trajectory, `shift_trajectory_hash`), `shiftTrajectoryFractured` predicate, JSON + markdown renderers; `classifyShift` exported from `coherence-movement.ts` (no behavior change). `tools/cli/coherence-sequence.ts` — shared `verifyCoherenceSequence` loader (parse + verify + cross-ladder guard), factored out of `coherence-trend.ts`. `tools/cli/coherence-shift-trend.ts` — `compareCoherenceShiftTrendArtifacts` (pure) + `runCoherenceShiftTrend` (file IO + exit codes); dispatcher + `USAGE` wired. Tests: shift-trajectory identity disk-vs-in-memory, oscillation detection (fracture-and-reconcile trips the gate but reports net unchanged), steady-fracture/reconcile, stable on realign-only and appear-only, ≥2-artifact requirement, cross-ladder refusal across the sequence (naming the two rounds), unpinned-v1 note, tamper rejection (round-prefixed), gate-predicate parity; `coherence-trend`'s suite passes unchanged after the loader extraction. | Reach |

Total work shipped this spec: **1 build step (198).** Purely additive — a new subcommand and one pure module, plus a behavior-preserving loader extraction; every existing command's output and golden is unchanged.

---

# Part XVI — Principled deferrals

- **A directory/glob walker that infers round order.** ⬜ Not built. The command takes artifacts in round order on the argv (the caller's contract, mirroring `coherence-trend`). Inferring order from filenames is a dashboard concern with its own ordering policy; the primitive takes an explicit ordered list.
- **A standalone shift-trajectory artifact (`--emit-shift-trajectory`).** ⬜ Deferred, for the same reason v14–v17 keep the derived thing derived: the trajectory is cheaply recomputable from the N coherence artifacts on demand, keeping the auditable inputs (each ladder-pinned, hash-verified) as the source of truth.
- **A net-only gate flag (`--fail-on-net-fracture`).** ⬜ Not built. The default gate fires on any-step fracture (the stronger, oscillation-catching signal); a consumer wanting the weaker first-vs-last gate reads `net_shift_counts.fractured` from the JSON.
- **A unified command that prints both trajectories at once (`coherence-trend --with-shift`).** ⬜ Not built. The two trajectories share a loader but answer different questions (exposure vs agreement) and gate on different predicates; two small single-purpose commands are clearer than one flagged command that does both. A consumer wanting both runs both on the same N artifacts. Noted, not built.
- **A browser surface for an N-round shift trend.** ⬜ Deferred (v16/v17 Part XVI). The browser does an in-session two-round comparison; an N-artifact trend is a CI/dashboard concern.

---

# Part XVII — Open questions for the maintainer

1. **Gate on oscillation separately from steady fracture?** Today `--fail-on-fracture` fires on both (any step fractured). A team might want "fail only if it *ended* split" (net) or "fail only on an *unrecovered* fracture." Recommendation: **keep the single any-step gate** — it is the faithful companion to v17's predicate and the strongest safe default; the JSON carries `net_shift_counts` and per-front `shift_trajectory` for a consumer that wants a narrower gate.
2. **Fold the floor and shift trajectories into one combined report?** v13 reports both axes per front in one object; v17/v18 split them across two commands so each has a single gate predicate and a single hash. Recommendation: **keep them split** at the command layer (clarity and one-gate-per-command), and let a dashboard that wants the v13-style combined per-front view join the two JSON outputs on `dimension` — both are pinned in the same front order, so the join is positional.

---

# Part XVIII — What this gives the user

- **Read the whole negotiation's *agreement* arc from the archive alone.** Archive each round's kilobyte coherence artifact as you go; `coherence-shift-trend` shows, per front, whether the package fractured steadily, reconciled steadily, or oscillated through a fracture it walked back — across the entire deal, with no clause text checked out and no re-analysis run for any round. The companion to v17's floor arc: the floor says how exposed you are, the shift says whether your own package speaks with one voice.
- **A gate that catches the fracture, not just the endpoints.** `--fail-on-fracture` fires when the package split at *any* step — so a front that fractured in round 3 and reconciled by round 5 still trips the gate, where a first-vs-last diff would call it unchanged and wave it through.
- **The same five promises.** Deterministic, no AI, no server, citable, never drafts — every line of v18 passes the §3 gate. It composes v13's fracture/reconcile classifier, v14's verifying parser, and v15/v16's ladder guard (shared with v17) into one headless command; it adds no posture math and no on-disk format, and it leaves every existing surface's output byte-for-byte unchanged.
