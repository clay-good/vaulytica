# Vaulytica v20 — Document-Free Posture Exposure (Whole-Deal Low-Water Mark)

> **Status:** **Shipped (9.17.0).** Every posture command from v10 to v19 reports **movement** — how a rung, a binding floor, or a coherence kind *changed* between rounds. v17 walks N coherence artifacts on the floor axis (`coherence-trend`); v18 the agreement axis (`coherence-shift-trend`); v19 joins both (`coherence-arc`). But a change-only view has a structural blind spot: a front that sat at `below-acceptable` in **every** round never *moved*, so v17 calls it `flat`, v18 calls it `stable`, every trend/arc summary omits it, and every movement gate waves it through — a floor only "regresses" when it changes to a *worse* rung, and a floor that was always below the team's acceptable minimum never changed. Yet that is the single most exposed front in the deal. v20 reads the same N artifacts on the orthogonal **level** axis: `coherence-exposure` reports, per front, the *worst* binding floor it ever reached across the whole deal (its low-water mark), the round it first reached it, and whether that worst rung is below the team's acceptable floor — plus one deal-level gate that trips when any front ever fell below floor at any round. It continues the global step numbering after v19's Step 199, beginning at **Step 200**. One new subcommand, one pure module, **zero** change to any existing source file.
> **Scope:** one idea — the *level* axis the movement family never read. v17/v18/v19 answer *which way did it move*; v20 answers *how low did it ever get*. It is the complement to the whole row v16–v19 built on the *movement* axis, and it closes the one question that axis cannot pose: a front never improves *or* regresses, holding steady below the floor for the life of the negotiation. The use case is the same dashboard or audit log that archived every round's kilobyte coherence artifact and now wants the deal's worst exposure — not "did it get worse" but "how bad did it ever get, and is anything sitting below our floor right now and all along?"
> **Posture (unchanged, non-negotiable):** deterministic (the exposure is a pure minimum over the same `TIER_RANK` v11/v13 use, taken over the binding floors v12 already derived; same artifacts → identical `exposure_hash`, on any machine, forever), no AI / no probabilistic path, no server (N local files in, one report out; no socket), citable (the artifacts carry the same per-front, per-document binding floors v12 derived from each document's own clause and the team's own playbook — v20 adds no new claim), lints / references / positions — but never drafts, and never renders a legal conclusion. The command is **advisory and verifiable**: every artifact is hash-verified (a tampered round is a hard error, side-labeled by round index), and the ladders are checked for a match across the *whole* sequence (any cross-ladder pair is refused) via the same `verifyCoherenceSequence` loader the three trend commands use, unchanged. Every step passes the §3 filter or it does not ship.
> **Cousin docs:** [`spec.md`](spec.md) (v1, the linter), [`spec-v8.md`](spec-v8.md) (Reach — the headless CLI this rides on; `diff`/`compare`/`compare-coherence`/`coherence-trend`/`coherence-shift-trend`/`coherence-arc` are its sibling subcommands), [`spec-v10.md`](spec-v10.md) (Negotiation Posture — the **rung ladder** and the `below-acceptable` floor this reads), [`spec-v12.md`](spec-v12.md) (Posture Coherence — the artifact's payload and the **binding floor** `weakest_tier`), [`spec-v14.md`](spec-v14.md) (Saved Coherence Baselines — the artifact this consumes), [`spec-v15.md`](spec-v15.md) (Ladder-Pinned Coherence Baselines — the cross-ladder guard), [`spec-v17.md`](spec-v17.md) (Document-Free Coherence Trajectory — **the movement-axis sibling whose `flat` classification this complements; the shared sequence loader is reused unchanged**), [`spec-v18.md`](spec-v18.md) (Document-Free Coherence-Shift Trajectory), [`spec-v19.md`](spec-v19.md) (Document-Free Combined Posture Arc — the last cell of the *movement* row). Progress in [`BUILD_PROGRESS.md`](../BUILD_PROGRESS.md).

---

# Part 0 — Intent

## §1. Why we're doing this

The posture lineage has been, end to end, a study of *change*. v11 diffs two versions of one document; v13 diffs two rounds of a bundle; v17/v18/v19 walk N rounds and classify the *path* the floor, the coherence kind, or both traced. Each is a faithful answer to "what moved, and which way." But "what moved" is not the only question a deal lead asks at the close of a negotiation. The other is: **where do I stand right now, and where did I stand at my worst?** A floor that has been sitting below the team's acceptable minimum since round one is the most dangerous position in the deal — and it is precisely the position the movement axis cannot see.

Concretely: `coherence-trend` classifies a front by reducing its consecutive floor *steps* to `steady-improvement` / `steady-regression` / `whipsaw` / `flat`. A front whose floor is `below-acceptable` in round 1 and `below-acceptable` in every subsequent round produces only `unchanged` steps, so it is `flat`. The summary omits `flat` fronts (it "surfaces only what moved"), and `--fail-on-coherence-regression` never fires (there was no regression — the floor never *changed* to a worse rung; it was born at the bottom). The same front is `stable` under `coherence-shift-trend` and omitted from `coherence-arc`. From the archive alone, across four commands, the most exposed front in the deal is invisible and ungated.

This is not a bug in those commands — they correctly classify *movement*, and a floor that never moved genuinely has no trajectory. It is a missing **axis**. v20 supplies it: read the same artifacts not for the *direction* of the floor but for its *worst level*. The minimum binding floor each front reached across the deal — its low-water mark — is the level a deal lead and a CI gate both want, and it is cheaply derivable from data already in every artifact.

## §2. What v20 is and is not

**It is:**
- A **document-free exposure command.** `coherence-exposure <r1.coherence.json> … <rN.coherence.json>` reads N ≥ 2 saved coherence artifacts in round order, verifies each, runs the cross-ladder guard across all of them, and prints, per negotiation front, the binding floor at every round, the **worst** floor reached (`ideal` / `acceptable` / `below-acceptable`, or `unstated` when no round stated it), the **round** it first reached that worst floor, how many rounds stated it, and whether that worst floor is **below the acceptable floor**. Markdown (default) or `--format json`. No documents are read; the engine is never run.
- A **single level gate over a whole negotiation.** `--fail-on-exposure` exits 2 when any front's worst binding floor is `below-acceptable` at any round — the deal-level "is anything sitting below our floor, ever" verdict. This is the *level* counterpart to v17's *movement* gate: where `--fail-on-coherence-regression` fires only on a floor that *changed* to a worse rung, `--fail-on-exposure` fires on a floor that *sat* below acceptable, so a front pinned below floor for the whole deal — invisible to every movement gate — trips it.
- A **whole-sequence-verified input, sharing the v17/v18/v19 front end.** Every artifact's `coherence_hash` is re-derived and checked on load (a tampered/corrupt round is a hard error, errors prefixed `round N:`). The v15/v16 cross-ladder guard runs across the sequence via the same `verifyCoherenceSequence` loader the three trend commands use, with no change to it.
- A **derived report carrying its own fingerprint.** The exposure carries an `exposure_hash` (a stable SHA-256 over the canonical per-front set), namespaced apart from every `coherence_hash`, `movement_hash`, `trajectory_hash`, `shift_trajectory_hash`, and `arc_hash`, so the same N artifacts in the same order always reproduce the same report.

**It is not:**
- **Not a new diff, classifier, predicate, or artifact format.** It reuses the `weakest_tier` binding floor v12 derives and the `TIER_RANK` v11/v13 order; v20 is a subcommand plus one pure module (`compareCoherenceExposure`) whose only new math is a minimum over ranks per front. `parsePostureCoherenceJson`, the coherence schema, and every trajectory function are unchanged.
- **Not a movement command.** It deliberately does *not* classify direction; it reports a level. A team that wants the floor's *path* still runs `coherence-trend` (or `coherence-arc` for both axes). The two are complementary: a front can be `flat` and `exposed` (pinned below floor), or `steady-regression` and not-yet-`exposed` (eroding from ideal toward, but not past, acceptable).
- **Not a replacement for the per-round divergence check.** v12's `analyze --posture --fail-on-divergence` reads a *single* round's documents; v20 reads the worst floor across N archived rounds, with no documents on any side.
- **Not an exposure artifact.** v20 introduces no new on-disk format; the exposure is *derived*, recomputed on demand from the N auditable coherence inputs — the same "keep the derived thing derived" discipline v14–v19 hold.
- **Not a sequence the command discovers.** It does not glob a directory or sort filenames; the caller passes the artifacts **in round order** on the argv, exactly as the three trend commands do.
- **Not a browser surface.** An N-round exposure of uploaded artifacts is a CI/dashboard concern, which is what this command serves (mirroring v16–v19).

## §3. The posture filter (unchanged)

1. **Deterministic** — `compareCoherenceExposure` over N `PostureCoherence` objects is pure: it takes a minimum over `TIER_RANK` per front and reduces to a low-water mark. Fronts are pinned by `localeCompare(_, "en")` — the same order the trajectory functions use. Identical artifacts in identical order → identical `exposure_hash` on any machine.
2. **Honest about unstated data** — a front no document states in *any* round has a `null` worst floor and is reported as `unstated`, never as exposed: "not stated" is not a point on the ideal→floor axis, so silence is never a false exposure (the §3 contract that keeps `newly-stated`/`now-unstated` unranked in v11/v13). Only a *stated* floor of `below-acceptable` is exposure. A front stated in only some rounds takes its worst over the rounds that stated it.
3. **Advisory** — the command names the worst rung each front reached on the team's own ladder. It asserts no legal conclusion.
4. **No server** — N local files in, one report out. No socket, no engine run.
5. **Additive** — a brand-new subcommand and one new pure module. Every existing command (`analyze`, `diff`, `compare`, `compare-coherence`, `coherence-trend`, `coherence-shift-trend`, `coherence-arc`, `verify`) is byte-for-byte unchanged in *output and goldens*; `coherence-sequence.ts` is imported and reused **without modification** (v20 needs nothing exported that was not already public — like v19, it touches no existing source file's behavior at all).

---

# Part I — The low-water mark (pure)

`src/report/coherence-exposure.ts` (a new sibling to `coherence-trajectory.ts`):

- **`ExposureLevel`** — the worst level a front reached: `ideal` / `acceptable` / `below-acceptable` / `unstated` (the binding floor is always a stated, ranked rung, so a front's worst level is one of the three rungs, or `unstated` when never stated).
- **`CoherenceExposureFront`** — one front's whole-sequence low-water mark: the `floors[]` sequence (shared with v17), the `worst_floor` (lowest-ranked stated floor, or `null` when never stated), the `worst_round` (1-based index it first reached that floor, `null` when never stated), `rounds_stated` (how many rounds carried a stated floor), and `exposed` (`worst_floor === "below-acceptable"`).
- **`compareCoherenceExposure(rounds: PostureCoherence[])`** — the pure, IO-free core. Matches fronts by dimension, pins them by `localeCompare`, takes the minimum `TIER_RANK` per front (first round to hit it wins the `worst_round` tiebreak — earliest exposure), tallies `worst_counts` by level, counts `exposed` fronts, and returns the set with an `exposure_hash`. Requires ≥ 2 rounds.
- **`exposureBreached(exposure)`** — the CI gate predicate: `exposed_count > 0`. The single deal-level verdict no movement command exposes.
- **`buildCoherenceExposureJson(exposure)`** / **`renderCoherenceExposureSummary(exposure)`** — the JSON (`schema: vaulytica.posture-exposure.v1`) and human-readable renderers. The summary prints the worst-level tally and the exposed-front count, then one line per **exposed** front (worst floor below acceptable — an `unstated` front is counted but never flagged), showing the floor path and the round the floor first fell below acceptable, and the `exposure_hash`.

v20 imports only already-public functions (`TIER_RANK`, `weakest_tier`); no existing source file changes.

# Part II — The command (headless)

`tools/cli/coherence-exposure.ts` (a new sibling to `coherence-arc.ts`):

- **`compareCoherenceExposureArtifacts(texts, format?)`** — the pure CLI core. Verifies all N artifacts and runs the cross-ladder guard via the shared `verifyCoherenceSequence` loader (unchanged from v18/v19); on any malformed/tampered round returns `{ ok: false, errors }` (each prefixed `round N:`); on a cross-ladder pair returns `{ ok: false }` naming the two rounds; an unpinned artifact yields `{ ok: true }` with a `ladderNote`. Then `compareCoherenceExposure(rounds)` and renders (markdown summary or JSON), returning `{ ok: true, output, breached, ladderNote }`.
- **`runCoherenceExposure(argv)`** — the CLI handler: reads the N files, calls the core, writes the `ladderNote` (if any) to stderr, prints the exposure to stdout, and — under `--fail-on-exposure` — exits 2 on a breach. A malformed/tampered/cross-ladder input is a hard exit-1 error. Requires ≥ 2 positionals.

`tools/cli/run.ts` (the dispatcher) gains a `coherence-exposure` case and a `USAGE` entry.

```
# Each round, archive its coherence (kilobytes, no clause text):
vaulytica analyze 'round1/*.docx' --playbook-file team.playbook.json --posture --emit-coherence round1.coherence.json
vaulytica analyze 'round2/*.docx' --playbook-file team.playbook.json --posture --emit-coherence round2.coherence.json
vaulytica analyze 'round3/*.docx' --playbook-file team.playbook.json --posture --emit-coherence round3.coherence.json

# Later — read/gate the whole-deal worst binding floor from the archive alone, no documents:
vaulytica coherence-exposure round1.coherence.json round2.coherence.json round3.coherence.json \
  --fail-on-exposure
```

---

# Part XV — Build plan

Continuing the global numbering after v19's Step 199. Verification gate for every step: `npm run typecheck && lint && test && build` green; the v7 coverage/parity/property gates, the v8 fuzz + citation gates, the v9 no-wall-clock gate, and the responsiveness e2e stay green.

Status legend: **✅ shipped** · ⬜ proposed.

| # | Step | Output | Tier |
|---|------|--------|------|
| 200 ✅ | `coherence-exposure` low-water mark | `src/report/coherence-exposure.ts` — `ExposureLevel`, `CoherenceExposureFront`, pure `compareCoherenceExposure` (per-front minimum over `TIER_RANK`: worst floor, first round, rounds-stated, exposed flag; `worst_counts` tally; namespaced `exposure_hash`), `exposureBreached` predicate (= `exposed_count > 0`), JSON + markdown renderers. `tools/cli/coherence-exposure.ts` — `compareCoherenceExposureArtifacts` (pure, reusing `verifyCoherenceSequence` unchanged) + `runCoherenceExposure` (file IO + exit codes); dispatcher + `USAGE` wired. Tests: exposure identity disk-vs-in-memory, worst-floor + first-round + rounds-stated, the below-floor-the-whole-deal front that `coherence-trend` calls `flat`/never-regressed (the blind spot this fills), unstated-is-never-exposed (§3), partially-stated front, worst-level tally + exposed count, determinism, ≥2-artifact requirement, cross-ladder refusal across the sequence (naming the two rounds), unpinned-v1 note, tamper rejection (round-prefixed), gate parity, flat-non-exposed front omitted from the summary; every existing command's suite passes unchanged. | Reach |

Total work shipped this spec: **1 build step (200).** Purely additive — a new subcommand and one pure module that reads the binding floor already in every artifact; **no existing source file's behavior changes** (v20 needs nothing newly exported), and every existing command's output and golden is unchanged.

---

# Part XVI — Principled deferrals

- **A `coherence-trend --worst-floor` flag.** ⬜ Not built — and deliberately not, mirroring v18/v19 Part XVI. v20 is a separate command, not a flag on a single-axis command, so each command keeps exactly one gate and one hash.
- **A standalone exposure artifact (`--emit-exposure`).** ⬜ Deferred, for the same reason v14–v19 keep the derived thing derived: the exposure is cheaply recomputable from the N coherence artifacts on demand, keeping the auditable inputs (each ladder-pinned, hash-verified) as the source of truth.
- **A configurable exposure floor (`--fail-below acceptable|ideal`).** ⬜ Not built. The gate fires on the team's own acceptable floor (`below-acceptable`), the one rung whose name means "below what we will accept." A team wanting to gate on "never reached ideal" reads `worst_counts` from the JSON. (The ladder defines what acceptable *means* per dimension via v10's predicates; `below-acceptable` is the universal floor across all of them.)
- **A "current floor" (last-round-only) view.** ⬜ Not built. `compare-coherence` already diffs the last two rounds, and a single round's floor is `analyze --posture`; v20's value is precisely the *worst across the whole deal*, which neither of those surfaces.
- **A directory/glob walker that infers round order.** ⬜ Not built. The command takes artifacts in round order on the argv (the caller's contract, mirroring the three trend commands).
- **A browser surface for an N-round exposure.** ⬜ Deferred (v16/v17/v18/v19 Part XVI). The browser does an in-session two-round comparison; an N-artifact exposure is a CI/dashboard concern.

---

# Part XVII — Open questions for the maintainer

1. **Fold exposure into the arc (`coherence-arc` carries a third, level axis)?** Today `coherence-arc` joins the two *movement* trajectories; exposure is a separate *level* command. A dashboard wanting movement-and-level in one report would run both and join on `dimension`. Recommendation: **keep them split at the command layer** — the arc's two axes are both *movement* and share one gate predicate shape (`trajectoryRegressed || shiftTrajectoryFractured`); exposure is a categorically different (level) gate, so bolting it onto the arc would give that command two unlike gates. If a dashboard asks for the combined view, add an `coherence-exposure` consumer the same way v19 joined v17 and v18 — as its own composing command, not a flag.
2. **Report the *deepest* front deal-wide (a single headline "worst exposure")?** The exposure reports every front's worst floor and a tally; it does not name "the single most exposed front in the deal." Recommendation: **defer** — `exposed_count` and the per-front rows already let a consumer pick it (lowest worst rank, earliest `worst_round` tiebreak), and a single headline has no consumer yet; add it if a dashboard asks to pin one.

---

# Part XVIII — What this gives the user

- **The worst floor of the whole deal, from the archive alone.** Archive each round's kilobyte coherence artifact as you go; `coherence-exposure` shows, per front, the lowest binding floor it ever reached and the round it first fell there — across the entire negotiation, with no clause text checked out and no re-analysis run. The level question a deal lead asks at the close, answered deterministically from N small, verifiable files.
- **A gate that catches the front every movement gate misses.** `--fail-on-exposure` fires when any front ever sat below the acceptable floor — including a front pinned at `below-acceptable` since round one, which never *regressed* (so `coherence-trend` calls it `flat` and waves it through) yet has been below the team's floor the entire deal. The level gate the movement axis structurally cannot pose.
- **The same five promises.** Deterministic, no AI, no server, citable, never drafts — every line of v20 passes the §3 gate. It reads the binding floor v12 already derives and the ladder order v11/v13 already define, through the loader v18/v19 already share; it adds one minimum over ranks, no on-disk format, and no change to any existing source file's behavior — every existing surface is byte-for-byte unchanged.
