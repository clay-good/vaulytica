# Vaulytica v17 — Document-Free Coherence Trajectory

> **Status:** **Shipped (9.14.0).** This spec answers the question a *pair* of rounds cannot: across a whole negotiation — round 1 → round 2 → … → round N — did each front's binding floor climb steadily, slide steadily, or **whipsaw** (dip below floor in the middle and recover)? It continues the global step numbering after v16's Step 196, beginning at **Step 197**. v16 made a single round-over-round movement recomputable from two saved coherence artifacts with no documents on disk; v17 walks a *sequence* of those same artifacts and reports the **trajectory** — the per-front path and net direction across the entire deal — and gates on a floor that regressed at *any* step, not only at the endpoints. One new subcommand, zero new posture math: it composes v16's verified-parse + cross-ladder guard with the existing v11/v13 floor-movement classifier, applied consecutively down the sequence.
> **Scope:** one idea, sitting one axis over from v16. The posture matrix has filled in steadily — v10 a *snapshot* (one document, one version), v11 a *movement* (one document, two versions), v12 a *coherence* (a bundle at one round), v13 the *movement of a coherence* (a bundle across two rounds). v16 made that two-round movement document-free. v17 is the **trajectory of a coherence**: a bundle across *N* rounds, computed from N archived artifacts alone. It is to v16 what v11's trajectory is to v10's snapshot — the signal you only see by looking at the whole sequence, not any one step. The use case is a dashboard or audit log that has archived every round's kilobyte coherence artifact and wants the deal-level arc: *which fronts are steadily improving, which are steadily eroding, and which round-tripped through a below-floor dip that a first-vs-last diff would hide.*
> **Posture (unchanged, non-negotiable):** deterministic (the trajectory is the same pure floor-movement classifier — `classifyFloorMovement`, shared with v11/v13 — applied to each consecutive pair of N `PostureCoherence` objects; same artifacts → identical `trajectory_hash`, on any machine, forever), no AI / no probabilistic path, no server (N local files in, one summary out; no socket), citable (the artifacts carry the same per-front, per-document rungs v12 derived from each document's own clause and the team's own playbook — v17 adds no new claim), lints / references / positions — but never drafts, and never renders a legal conclusion. The command is **advisory and verifiable**: every artifact is hash-verified (a tampered round is a hard error, side-labeled by round index), the ladders are checked for a match across the *whole* sequence (any cross-ladder pair is refused), and the trajectory it prints is the same advisory floor signal v13 produces, accumulated down the sequence. Every step passes the §3 filter or it does not ship.
> **Cousin docs:** [`spec.md`](spec.md) (v1, the linter), [`spec-v8.md`](spec-v8.md) (Reach — the headless CLI this rides on; `diff`/`compare`/`compare-coherence` are its sibling subcommands), [`spec-v11.md`](spec-v11.md) (Posture Movement — **the trajectory idea, one document; this is its cross-document, multi-round cousin**), [`spec-v12.md`](spec-v12.md) (Posture Coherence — the artifact's payload), [`spec-v13.md`](spec-v13.md) (Cross-Document Posture Movement — **the pairwise diff this accumulates; `classifyFloorMovement` is shared from here**), [`spec-v14.md`](spec-v14.md) (Saved Coherence Baselines — the artifact this consumes), [`spec-v15.md`](spec-v15.md) (Ladder-Pinned Coherence Baselines — **the cross-ladder guard, now run across the whole sequence**), [`spec-v16.md`](spec-v16.md) (Document-Free Coherence Movement — **the two-artifact command this generalizes to N; v16 Part XVI deferred exactly this sequence walker**). Progress in [`BUILD_PROGRESS.md`](../BUILD_PROGRESS.md).

---

# Part 0 — Intent

## §1. Why we're doing this

v16's Part XVI deferred this command by name — "Accept a directory/glob of coherence artifacts and diff a sequence … a multi-round trend (`round1 → round2 → round3`) is a dashboard concern that can call `compare-coherence` pairwise." That deferral is correct about the *mechanism* (you can call the pairwise command N−1 times) but wrong about the *signal*. Calling `compare-coherence` pairwise gives a consumer N−1 independent verdicts; it does **not** give the two things that only exist at the level of the whole sequence:

1. **The net direction.** Did the binding floor on the cap end the negotiation better or worse than it started? A consumer can get this by diffing the first and last artifacts — but then it has thrown away every round in between.
2. **The path — the whipsaw.** Did the floor on the cap *dip below floor in round 3 and recover by round 5*? A first-vs-last diff reports `unchanged` and hides it. N−1 independent pairwise diffs each report a single step but never say "this front moved in both directions across the deal." A deal lead reads a recovered dip as a real signal: it tells you where the counterparty was willing to push, even though they walked it back.

This is the exact relationship v11 has to v10. v10 scores a single version; you *can* score every version independently, but the *trajectory* — improving, regressing, or oscillating across the whole history — is a signal that only exists when you look at the sequence as one object. v11 built that for one document across versions. v17 builds it for a bundle's binding floor across negotiation rounds, from the archived artifacts alone.

The composition is small because everything it needs already exists and is already tested: `parsePostureCoherenceJson` (v14) verifies each artifact and surfaces its ladder pin; the v16 cross-ladder guard generalizes from "between two pins" to "across all pins"; `classifyFloorMovement` (the v11/v13 floor classifier, now exported from `coherence-movement.ts`) classifies each consecutive step; and a tiny pure reducer rolls the per-step classifications into a per-front trajectory. v17 adds **no** posture math — it applies the existing classifier consecutively and counts the results.

## §2. What v17 is and is not

**It is:**
- A **document-free trajectory command.** `coherence-trend <r1.coherence.json> <r2.coherence.json> … <rN.coherence.json>` reads N ≥ 2 saved coherence artifacts in round order, verifies each, runs the cross-ladder guard across all of them, and prints, per negotiation front, the floor at each round, the consecutive steps, the **net** floor movement (round 1 → round N), and a **trajectory** classification — `steady-improvement`, `steady-regression`, `whipsaw`, or `flat`. Markdown (default) or `--format json`. No documents are read; the engine is never run.
- A **CI gate primitive over a whole negotiation.** `--fail-on-coherence-regression` exits 2 when any front's binding floor regressed at **any step** of the sequence — strictly stronger than a first-vs-last diff, and deliberately so: it catches a transient below-floor dip even when the front recovered by the final round. (A consumer that wants the weaker net-only gate reads `net_counts.regressed` from the JSON.)
- A **whole-sequence-verified input.** Every artifact's `coherence_hash` is re-derived and checked on load (a tampered/corrupt round is a hard error, errors prefixed `round N:`). The v15/v16 cross-ladder guard runs across the sequence: if two or more artifacts are ladder-pinned (`v2`) and any two pins differ, the trend is refused (exit 1); an unpinned (`v1`) artifact anywhere proceeds with a note.

**It is not:**
- **Not a new diff, predicate, classifier, or artifact format.** `classifyFloorMovement`, `parsePostureCoherenceJson`, the `v1`/`v2` coherence schema, and `TIER_RANK` are all unchanged; `compareCoherence` itself is unchanged (the trajectory shares its classifier, not its shape). v17 is a subcommand plus one pure reducer (`compareCoherenceTrajectory`) that composes them.
- **Not a movement/trajectory artifact.** v17 does not introduce a new on-disk format; the trajectory is *derived*, recomputed on demand from the N auditable coherence inputs — the same "keep the derived thing derived" discipline v14/v15/v16 hold.
- **Not a sequence the command discovers.** It does not glob a directory or sort filenames; the caller passes the artifacts **in round order** on the argv, exactly as `compare-coherence` takes base then revised. Round order is the caller's contract (a directory walker that infers order from filenames is a dashboard concern; Part XVI).
- **Not a browser surface.** The browser does an in-session two-round comparison (v13 Thrust B); an N-round trend of uploaded artifacts is a larger UI surface with no demonstrated need (Part XVI).

## §3. The posture filter (unchanged)

1. **Deterministic** — `compareCoherenceTrajectory` over N `PostureCoherence` objects is pure; identical artifacts in identical order → identical `trajectory_hash` on any machine. Fronts are pinned by `localeCompare(_, "en")`; the round order is the caller's. The N parses and the ladder compare add no nondeterminism.
2. **Honest about unstated data** — a `newly-stated` or `now-unstated` step is **never** counted as an improvement or a regression (the v11/v13 §3 contract, carried by the shared `classifyFloorMovement`); a front that round-trips through unstated is `flat`, never `whipsaw`. An unstated front round-trips as unstated.
3. **Advisory** — the command prints a trajectory and, optionally, gates on a regression. It asserts no legal conclusion.
4. **No server** — N local files in, one summary out. No socket, no engine run.
5. **Additive** — a brand-new subcommand and one new pure module. Every existing command (`analyze`, `diff`, `compare`, `compare-coherence`, `verify`) is byte-for-byte unchanged, every golden is unchanged, and `coherence-movement.ts` changes only by *exporting* an existing private function (`classifyFloorMovement`) — no behavior moves.

---

# Part I — The classifier (pure)

`src/report/coherence-trajectory.ts` (a new sibling to `coherence-movement.ts`):

- **`FloorTrajectoryKind`** — how a front's binding floor moved across the *whole* sequence:
  - `steady-improvement` — at least one step improved and **no** step regressed.
  - `steady-regression` — at least one step regressed and **no** step improved.
  - `whipsaw` — at least one step improved **and** at least one step regressed (the floor moved in both directions; the signal a first-vs-last diff hides).
  - `flat` — no *ranked* movement at any step (only `unchanged` / `newly-stated` / `now-unstated` steps). A front that only ever appeared or dropped, never moving between two stated rungs, is `flat` — honest, never a false whipsaw.
- **`compareCoherenceTrajectory(rounds: PostureCoherence[])`** — the pure, IO-free core. Matches fronts by dimension across the union of all rounds (pinned by `localeCompare`); for each front builds the floor at each round (`null` = unstated that round) and the coherence kind at each round, classifies each consecutive step with the shared `classifyFloorMovement`, computes the **net** movement as `classifyFloorMovement(floors[0], floors[N−1])`, reduces the steps to a `FloorTrajectoryKind`, and returns the per-front set plus `trajectory_counts`, `net_counts`, and a `trajectory_hash` (SHA-256 over the canonical per-front set, namespaced apart from every `coherence_hash`/`movement_hash`).
- **`trajectoryRegressed(t)`** — the CI gate predicate: true when any front's trajectory is `steady-regression` or `whipsaw` (i.e. the floor regressed at *some* step). The faithful generalization of v13's `coherenceRegressed` (any front whose floor regressed) from one step to the whole sequence.
- **`buildCoherenceTrajectoryJson(t)`** / **`renderCoherenceTrajectorySummary(t)`** — the JSON (`schema: vaulytica.posture-trajectory.v1`) and human-readable renderers, beside their movement-module siblings.

`classifyFloorMovement` was a private helper in `coherence-movement.ts`; v17 **exports** it (no behavior change) so the trajectory reuses the one §3-honest floor classifier rather than re-deriving it.

# Part II — The command (headless)

`tools/cli/coherence-trend.ts` (a new sibling to `compare-coherence.ts`):

- **`compareCoherenceTrendArtifacts(texts, format?)`** — the pure CLI core. Parses + verifies all N artifacts via `parsePostureCoherenceJson`; on any malformed/tampered round returns `{ ok: false, errors }` with each error prefixed `round N:` (1-indexed). Runs the cross-ladder guard across all pinned artifacts (any two differing pins → `{ ok: false }` with a `ladder mismatch` error naming the two rounds; any unpinned artifact → `{ ok: true }` with a `ladderNote`). Then `compareCoherenceTrajectory(rounds)` and renders (markdown summary or JSON), returning `{ ok: true, output, regressed, ladderNote }`.
- **`runCoherenceTrend(argv)`** — the CLI handler: reads the N files, calls the core, writes the `ladderNote` (if any) to stderr, prints the trajectory to stdout, and — under `--fail-on-coherence-regression` — exits 2 on a regression. A malformed/tampered/cross-ladder input is a hard exit-1 error. Requires ≥ 2 positionals (a single artifact has no trajectory).

`tools/cli/run.ts` (the dispatcher) gains a `coherence-trend` case and a `USAGE` entry.

```
# Each round, archive its coherence (kilobytes, no clause text):
vaulytica analyze 'round1/*.docx' --playbook-file team.playbook.json --posture --emit-coherence round1.coherence.json
vaulytica analyze 'round2/*.docx' --playbook-file team.playbook.json --posture --emit-coherence round2.coherence.json
vaulytica analyze 'round3/*.docx' --playbook-file team.playbook.json --posture --emit-coherence round3.coherence.json

# Later — show/gate the whole-deal arc from the archive alone, no documents:
vaulytica coherence-trend round1.coherence.json round2.coherence.json round3.coherence.json \
  --fail-on-coherence-regression
```

---

# Part XV — Build plan

Continuing the global numbering after v16's Step 196. Verification gate for every step: `npm run typecheck && lint && test && build` green; the v7 coverage/parity/property gates, the v8 fuzz + citation gates, the v9 no-wall-clock gate, and the responsiveness e2e stay green.

Status legend: **✅ shipped** · ⬜ proposed.

| # | Step | Output | Tier |
|---|------|--------|------|
| 197 ✅ | `coherence-trend` trajectory | `src/report/coherence-trajectory.ts` — `FloorTrajectoryKind`, pure `compareCoherenceTrajectory` (per-front floors/coherences/steps + net + trajectory, `trajectory_hash`), `trajectoryRegressed` predicate, JSON + markdown renderers; `classifyFloorMovement` exported from `coherence-movement.ts` (no behavior change). `tools/cli/coherence-trend.ts` — `compareCoherenceTrendArtifacts` (pure: verify all N, cross-ladder guard across the sequence, trajectory, render) + `runCoherenceTrend` (file IO + exit codes); dispatcher + `USAGE` wired. Tests: trajectory identity disk-vs-in-memory, whipsaw detection (dip-and-recover trips the gate but reports net unchanged/improved), steady-improvement/regression, flat on appear-only, ≥2-artifact requirement, cross-ladder refusal across the sequence (naming the two rounds), unpinned-v1 note, tamper rejection (round-prefixed), gate-predicate parity. | Reach |

Total work shipped this spec: **1 build step (197).** Purely additive — a new subcommand and one pure module; every existing command and golden is unchanged.

---

# Part XVI — Principled deferrals

- **A directory/glob walker that infers round order.** ⬜ Not built. The command takes artifacts in round order on the argv (the caller's contract, mirroring `compare-coherence`'s base-then-revised). Inferring order from filenames (`round1` < `round10` < `round2` lexically?) is a dashboard concern with its own ordering policy; the primitive takes an explicit ordered list. Noted, not built.
- **A standalone trajectory artifact (`--emit-trajectory`).** ⬜ Deferred, for the same reason v14/v15/v16 keep the movement derived: the trajectory is cheaply recomputable from the N coherence artifacts on demand, which keeps the auditable inputs (each ladder-pinned, hash-verified) as the source of truth rather than a derived, separately-stored object.
- **A net-only gate flag (`--fail-on-net-regression`).** ⬜ Not built. The default gate fires on any-step regression (the stronger, whipsaw-catching signal); a consumer wanting the weaker first-vs-last gate reads `net_counts.regressed` from the JSON. A second gate flag is more surface than the one-predicate primitive needs until a team asks for it.
- **A browser surface for an N-round trend.** ⬜ Deferred (v16 Part XVI). The browser does an in-session two-round comparison; an N-artifact trend is a CI/dashboard concern, which is what this command serves.

---

# Part XVII — Open questions for the maintainer

1. **Gate on whipsaw separately from steady regression?** Today `--fail-on-coherence-regression` fires on both (any step regressed). A team might want "fail only if it *ended* worse" (net) or "fail only on an *unrecovered* regression." Recommendation: **keep the single any-step gate** — it is the faithful generalization of v13's predicate and the strongest safe default; the JSON carries `net_counts` and per-front `trajectory` for a consumer that wants a narrower gate.
2. **Report the coherence-kind trajectory (fracture/reconcile path) too?** v13 reports a per-step `coherence_shift`; v17 carries each round's coherence kind but classifies the trajectory on the binding floor only. A "this front fractured in round 3 and reconciled by round 5" path is the advisory companion to the floor whipsaw. Recommendation: **defer** — the floor is the exposure-governing signal and the per-round coherence kinds are in the JSON for a consumer to walk; add a coherence-shift trajectory if a team asks.

---

# Part XVIII — What this gives the user

- **Read the whole negotiation's arc from the archive alone.** Archive each round's kilobyte coherence artifact as you go; `coherence-trend` shows, per front, whether the binding floor climbed steadily, eroded steadily, or whipsawed through a below-floor dip — across the entire deal, with no clause text checked out and no re-analysis run for any round. The trajectory a deal lead reconstructs by eye across a stack of rounds, computed deterministically from N small, verifiable files.
- **A gate that catches the dip, not just the endpoints.** `--fail-on-coherence-regression` fires when the floor regressed at *any* step — so a front that fell below floor in round 3 and recovered by round 5 still trips the gate, where a first-vs-last diff would call it unchanged and wave it through. The most useful round-over-round signal (*did my exposure ever get worse, even transiently*) enforced in CI from the archive.
- **The same five promises.** Deterministic, no AI, no server, citable, never drafts — every line of v17 passes the §3 gate. It composes v13's floor classifier, v14's verifying parser, and v15/v16's ladder guard into one headless command; it adds no posture math and no on-disk format, and it leaves every existing surface byte-for-byte unchanged.
