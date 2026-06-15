# Vaulytica v19 — Document-Free Combined Posture Arc

> **Status:** **Shipped (9.16.0).** v17 read N archived coherence artifacts on the binding-*floor* axis (`coherence-trend`); v18 read the same N on the agreement axis (`coherence-shift-trend`). But v13 — the two-round movement both descend from — never split those axes: it reports *both* `floor_movement` *and* `coherence_shift` per front, in one object, because a deal lead reconciling a package reads them together. *Did this front erode, and did it also fracture? Did the floor hold while the package quietly split? Did anything at all go wrong on either axis?* v19 restores that combined view for the N-round, document-free case: `coherence-arc` walks the same N artifacts once and reports, per front, the floor trajectory **and** the shift trajectory joined, plus one deal-level gate that trips when the floor regressed **or** the package fractured at any step. It continues the global step numbering after v18's Step 198, beginning at **Step 199**. One new subcommand, **zero** new posture math: it runs the two existing pure trajectory functions and joins their per-front results positionally on `dimension`.
> **Scope:** one idea — the v13 per-front *combined* view, generalized to N rounds and read from the archive alone. This closes the posture matrix's document-free row: v16 the two-round movement (floor + shift in one object), v17 the N-round *floor* trajectory, v18 the N-round *shift* trajectory, **v19 the N-round floor + shift trajectory joined**. It is to v17/v18 what v13 is to a single-axis pairwise diff: the object that reports both exposure and agreement at once, with a single combined gate. The use case is the same dashboard or audit log that archived every round's kilobyte coherence artifact and now wants one whole-deal posture report — not two JSON files it must join by hand and gate on by `||`-ing two exit codes.
> **Posture (unchanged, non-negotiable):** deterministic (the arc is a pure positional join of `compareCoherenceTrajectory` and `compareCoherenceShiftTrajectory` over the same N `PostureCoherence` objects; same artifacts → identical `arc_hash`, on any machine, forever), no AI / no probabilistic path, no server (N local files in, one report out; no socket), citable (the artifacts carry the same per-front, per-document floors and coherence kinds v12 derived from each document's own clause and the team's own playbook — v19 adds no new claim), lints / references / positions — but never drafts, and never renders a legal conclusion. The command is **advisory and verifiable**: every artifact is hash-verified (a tampered round is a hard error, side-labeled by round index), the ladders are checked for a match across the *whole* sequence (any cross-ladder pair is refused), and the two component fingerprints it carries (`trajectory_hash`, `shift_trajectory_hash`) are **byte-identical** to what `coherence-trend` and `coherence-shift-trend` emit on the same inputs — so an arc is independently cross-checkable against the two single-axis commands. Every step passes the §3 filter or it does not ship.
> **Cousin docs:** [`spec.md`](spec.md) (v1, the linter), [`spec-v8.md`](spec-v8.md) (Reach — the headless CLI this rides on; `diff`/`compare`/`compare-coherence`/`coherence-trend`/`coherence-shift-trend` are its sibling subcommands), [`spec-v12.md`](spec-v12.md) (Posture Coherence — the artifact's payload), [`spec-v13.md`](spec-v13.md) (Cross-Document Posture Movement — **the per-front combined floor + shift object this generalizes**), [`spec-v14.md`](spec-v14.md) (Saved Coherence Baselines — the artifact this consumes), [`spec-v15.md`](spec-v15.md) (Ladder-Pinned Coherence Baselines — the cross-ladder guard), [`spec-v16.md`](spec-v16.md) (Document-Free Coherence Movement — the two-artifact command), [`spec-v17.md`](spec-v17.md) (Document-Free Coherence Trajectory — **the floor trajectory this joins; its `trajectory_hash` is carried verbatim**), [`spec-v18.md`](spec-v18.md) (Document-Free Coherence-Shift Trajectory — **the shift trajectory this joins; its `shift_trajectory_hash` is carried verbatim, and its Part XVII open question #2 named exactly this combined view; the shared sequence loader is reused unchanged**). Progress in [`BUILD_PROGRESS.md`](../BUILD_PROGRESS.md).

---

# Part 0 — Intent

## §1. Why we're doing this

v18's Part XVII open question #2 named this command and recommended deferring it: "Fold the floor and shift trajectories into one combined report? v13 reports both axes per front in one object; v17/v18 split them across two commands so each has a single gate predicate and a single hash. Recommendation: keep them split at the command layer, and let a dashboard that wants the v13-style combined per-front view join the two JSON outputs on `dimension`." That recommendation was right about one thing and incomplete about another. It was right that the two **single-axis** commands should stay single-axis — `coherence-trend` must keep its one floor gate and one `trajectory_hash`; `coherence-shift-trend` must keep its one fracture gate and one `shift_trajectory_hash`. v19 changes neither: both ship byte-for-byte unchanged.

What it was incomplete about is that "let a dashboard join the two JSON outputs" is exactly the kind of compose-it-yourself deferral this lineage has repeatedly promoted into a first-class command — and for good reason. v16 turned "you can call `compareCoherence` yourself" into `compare-coherence`. v17 turned "you can diff the rounds pairwise" into `coherence-trend`. The reason is always the same: doing the composition *correctly* is where consumers slip. The positional join is easy to get wrong (a dashboard that sorts fronts differently than `localeCompare` mis-aligns the two files); the combined gate is easy to get wrong (`||`-ing two exit codes works but gives no single fingerprint, and re-reads the N artifacts twice); and there is **no** combined `arc_hash` for an auditor to pin "this is the whole-deal posture report I reviewed." v19 supplies all three: the join is done where the two arrays are provably aligned, the gate is one predicate, and the report carries its own hash derived purely from the two component hashes.

Critically, v19 is **not** the `coherence-trend --with-shift` flag that v18 Part XVI deferred. That deferral was right: bolting a second axis onto a single-purpose command would give *that* command two gates and two hashes — exactly the muddiness v17/v18 avoid. v19 keeps the single-purpose discipline by being a **third, distinct command whose single purpose is the combined view**, with its own single gate (`--fail-on-regression-or-fracture`) and its own single hash (`arc_hash`). One command, one question, one gate, one fingerprint — the same discipline, applied to the v13 question that genuinely has no home today.

## §2. What v19 is and is not

**It is:**
- A **document-free combined-arc command.** `coherence-arc <r1.coherence.json> <r2.coherence.json> … <rN.coherence.json>` reads N ≥ 2 saved coherence artifacts in round order, verifies each, runs the cross-ladder guard across all of them, and prints, per negotiation front, **both** the binding-floor trajectory (v17: `steady-improvement` / `steady-regression` / `whipsaw` / `flat`, with the floor path and net) **and** the coherence-shift trajectory (v18: `steady-fracture` / `steady-reconcile` / `oscillating` / `stable`, with the coherence path and net). Markdown (default) or `--format json`. No documents are read; the engine is never run.
- A **single combined CI gate over a whole negotiation.** `--fail-on-regression-or-fracture` exits 2 when the binding floor regressed at any step **or** the package fractured at any step — the deal-level "did anything go wrong on either axis" verdict that is exactly `trajectoryRegressed(floor) || shiftTrajectoryFractured(shift)`, computed from one read of the N artifacts. (A consumer wanting one axis only still runs `coherence-trend` or `coherence-shift-trend`.)
- A **cross-checkable join.** The arc carries `trajectory_hash` and `shift_trajectory_hash` verbatim — byte-identical to what the two single-axis commands emit on the same inputs — plus an `arc_hash` derived purely from that pair. An auditor can reproduce all three and confirm the combined report is exactly the join of the two single-axis reports.
- A **whole-sequence-verified input, sharing the v17/v18 front end.** Every artifact's `coherence_hash` is re-derived and checked on load (a tampered/corrupt round is a hard error, errors prefixed `round N:`). The v15/v16 cross-ladder guard runs across the sequence via the same `verifyCoherenceSequence` loader the two trend commands use, with no change to it.

**It is not:**
- **Not a new diff, predicate, classifier, or artifact format.** `compareCoherenceTrajectory`, `compareCoherenceShiftTrajectory`, `classifyFloorMovement`, `classifyShift`, `parsePostureCoherenceJson`, and the coherence schema are all unchanged. v19 is a subcommand plus one pure module (`compareCoherenceArc`) that **composes** the two existing trajectory functions; it adds no posture math of its own.
- **Not a flag on `coherence-trend`.** v18 Part XVI deferred `coherence-trend --with-shift` precisely to keep that command single-purpose. v19 honors that: it is a separate command, and the two single-axis commands are byte-for-byte unchanged in output and goldens.
- **Not a replacement for the two single-axis commands.** A team that wants to gate on the floor *only*, or the shift *only*, still runs the dedicated command — each keeps its own narrow gate. The arc is for the consumer who wants both axes and the combined verdict in one report.
- **Not an arc artifact.** v19 introduces no new on-disk format; the arc is *derived*, recomputed on demand from the N auditable coherence inputs — the same "keep the derived thing derived" discipline v14–v18 hold.
- **Not a sequence the command discovers.** It does not glob a directory or sort filenames; the caller passes the artifacts **in round order** on the argv, exactly as the two trend commands do.
- **Not a browser surface.** An N-round arc of uploaded artifacts is a CI/dashboard concern, which is what this command serves.

## §3. The posture filter (unchanged)

1. **Deterministic** — `compareCoherenceArc` over N `PostureCoherence` objects is pure; it runs the two pure trajectory functions and joins their results. Identical artifacts in identical order → identical `arc_hash` on any machine. Both component functions pin fronts by `localeCompare(_, "en")` over the same union of dimensions, so the two `fronts` arrays are identical in order and length and the join is positional; a defensive dimension-equality check makes a broken join loud, never silent.
2. **Honest about absent fronts** — every absent-side defense from v17/v18 flows through unchanged: a `newly-stated`/`now-unstated` floor step is never a regression, an appear/disappear or realign-only coherence step is never a fracture. The arc invents no movement that the two component functions did not already classify.
3. **Advisory** — the command prints an arc and, optionally, gates on a regression-or-fracture. It asserts no legal conclusion.
4. **No server** — N local files in, one report out. No socket, no engine run.
5. **Additive** — a brand-new subcommand and one new pure module. Every existing command (`analyze`, `diff`, `compare`, `compare-coherence`, `coherence-trend`, `coherence-shift-trend`, `verify`) is byte-for-byte unchanged in *output and goldens*; `coherence-trajectory.ts`, `coherence-shift-trajectory.ts`, and `coherence-sequence.ts` are imported and reused **without modification** (v19 needs nothing exported that was not already public — unlike v17/v18, it touches no existing source file's behavior at all).

---

# Part I — The join (pure)

`src/report/coherence-arc.ts` (a new sibling to `coherence-trajectory.ts` and `coherence-shift-trajectory.ts`):

- **`CoherenceArcFront`** — one front's whole-sequence arc on **both** axes: the floor fields from v17 (`floors`, `steps`, `net_floor_movement`, `trajectory`) and the shift fields from v18 (`shifts`, `net_shift`, `shift_trajectory`), plus the `coherences[]` sequence the two axes share (carried once).
- **`compareCoherenceArc(rounds: PostureCoherence[])`** — the pure, IO-free core. Runs `compareCoherenceTrajectory(rounds)` (v17) and `compareCoherenceShiftTrajectory(rounds)` (v18) and joins their `fronts` arrays positionally (guarded by a per-index dimension-equality check). Returns the per-front combined set, all four count objects (the two floor tallies from v17, the two shift tallies from v18), the two component hashes carried verbatim, and an `arc_hash` = SHA-256 over `{ trajectory_hash, shift_trajectory_hash }` (namespaced apart from every `coherence_hash`/`movement_hash`/`trajectory_hash`/`shift_trajectory_hash`). Requires ≥ 2 rounds (both component functions enforce this).
- **`arcRegressedOrFractured(arc)`** — the combined CI gate predicate: `trajectoryRegressed(floor) || shiftTrajectoryFractured(shift)`, read off the arc's count objects. The single deal-level verdict neither single-axis command exposes.
- **`buildCoherenceArcJson(arc)`** / **`renderCoherenceArcSummary(arc)`** — the JSON (`schema: vaulytica.posture-arc.v1`) and human-readable renderers. The summary prints the floor and shift trajectory blocks, then one line per front that moved on **either** axis (a front that is `flat` *and* `stable` is omitted), showing both paths and both nets, and all three hashes.

v19 imports only already-public functions from the two trajectory modules; no existing source file changes.

# Part II — The command (headless)

`tools/cli/coherence-arc.ts` (a new sibling to `coherence-trend.ts` / `coherence-shift-trend.ts`):

- **`compareCoherenceArcArtifacts(texts, format?)`** — the pure CLI core. Verifies all N artifacts and runs the cross-ladder guard via the shared `verifyCoherenceSequence` loader (unchanged from v18); on any malformed/tampered round returns `{ ok: false, errors }` (each prefixed `round N:`); on a cross-ladder pair returns `{ ok: false }` naming the two rounds; an unpinned artifact yields `{ ok: true }` with a `ladderNote`. Then `compareCoherenceArc(rounds)` and renders (markdown summary or JSON), returning `{ ok: true, output, regressedOrFractured, ladderNote }`.
- **`runCoherenceArc(argv)`** — the CLI handler: reads the N files, calls the core, writes the `ladderNote` (if any) to stderr, prints the arc to stdout, and — under `--fail-on-regression-or-fracture` — exits 2 on a regression-or-fracture. A malformed/tampered/cross-ladder input is a hard exit-1 error. Requires ≥ 2 positionals.

`tools/cli/run.ts` (the dispatcher) gains a `coherence-arc` case and a `USAGE` entry.

```
# Each round, archive its coherence (kilobytes, no clause text):
vaulytica analyze 'round1/*.docx' --playbook-file team.playbook.json --posture --emit-coherence round1.coherence.json
vaulytica analyze 'round2/*.docx' --playbook-file team.playbook.json --posture --emit-coherence round2.coherence.json
vaulytica analyze 'round3/*.docx' --playbook-file team.playbook.json --posture --emit-coherence round3.coherence.json

# Later — read/gate the whole-deal posture arc (floor + shift) from the archive alone, no documents:
vaulytica coherence-arc round1.coherence.json round2.coherence.json round3.coherence.json \
  --fail-on-regression-or-fracture
```

---

# Part XV — Build plan

Continuing the global numbering after v18's Step 198. Verification gate for every step: `npm run typecheck && lint && test && build` green; the v7 coverage/parity/property gates, the v8 fuzz + citation gates, the v9 no-wall-clock gate, and the responsiveness e2e stay green.

Status legend: **✅ shipped** · ⬜ proposed.

| # | Step | Output | Tier |
|---|------|--------|------|
| 199 ✅ | `coherence-arc` combined report | `src/report/coherence-arc.ts` — `CoherenceArcFront`, pure `compareCoherenceArc` (positional join of v17's `compareCoherenceTrajectory` and v18's `compareCoherenceShiftTrajectory`; per-front floor + shift fields, four count objects, the two component hashes verbatim, namespaced `arc_hash`), `arcRegressedOrFractured` predicate (= `trajectoryRegressed || shiftTrajectoryFractured`), JSON + markdown renderers. `tools/cli/coherence-arc.ts` — `compareCoherenceArcArtifacts` (pure, reusing `verifyCoherenceSequence` unchanged) + `runCoherenceArc` (file IO + exit codes); dispatcher + `USAGE` wired. Tests: arc identity disk-vs-in-memory, front-for-front join against the two single-axis trajectories, component-hash equality (the arc's `trajectory_hash`/`shift_trajectory_hash` equal the two commands' output byte-for-byte), combined-gate parity (`= trajectoryRegressed || shiftTrajectoryFractured`), floor-only trip (regress while stable), shift-only trip (fracture while floor flat), both-quiet no-trip, determinism, ≥2-artifact requirement, cross-ladder refusal across the sequence (naming the two rounds), unpinned-v1 note, tamper rejection (round-prefixed), flat-and-stable front omitted from the summary; every existing command's suite passes unchanged. | Reach |

Total work shipped this spec: **1 build step (199).** Purely additive — a new subcommand and one pure module that composes two existing pure functions; **no existing source file's behavior changes** (v19 needs nothing newly exported), and every existing command's output and golden is unchanged.

---

# Part XVI — Principled deferrals

- **A `coherence-trend --with-shift` flag.** ⬜ Not built — and deliberately not, mirroring v18 Part XVI. v19 is a separate command, not a flag on a single-axis command, so each of the three commands keeps exactly one gate and one hash.
- **A standalone arc artifact (`--emit-arc`).** ⬜ Deferred, for the same reason v14–v18 keep the derived thing derived: the arc is cheaply recomputable from the N coherence artifacts on demand, keeping the auditable inputs (each ladder-pinned, hash-verified) as the source of truth.
- **A net-only combined gate (`--fail-on-net-regression-or-fracture`).** ⬜ Not built. The default gate fires on any-step regression-or-fracture (the stronger, oscillation/whipsaw-catching signal, inherited from both component predicates); a consumer wanting the weaker first-vs-last gate reads `net_counts.regressed` and `net_shift_counts.fractured` from the JSON.
- **A directory/glob walker that infers round order.** ⬜ Not built. The command takes artifacts in round order on the argv (the caller's contract, mirroring the two trend commands).
- **A browser surface for an N-round arc.** ⬜ Deferred (v16/v17/v18 Part XVI). The browser does an in-session two-round comparison; an N-artifact arc is a CI/dashboard concern.

---

# Part XVII — Open questions for the maintainer

1. **Weight the combined gate by axis?** Today `--fail-on-regression-or-fracture` treats a floor regression and a fracture as equally gate-worthy (either trips it). A team might consider the floor (exposure) strictly more serious than a fracture (advisory agreement). Recommendation: **keep the equal-OR gate** — it is the faithful union of the two component predicates and the strongest safe default; a team that wants the floor to gate but the fracture only to *report* runs `coherence-trend --fail-on-coherence-regression` and reads the arc (or `coherence-shift-trend`) without its gate.
2. **Emit a per-front combined `front_hash`?** The arc fingerprints the whole report (`arc_hash`) and each axis (`trajectory_hash`, `shift_trajectory_hash`), but not each front's combined row. Recommendation: **defer** — the two component hashes already pin every per-front floor and shift value, and a per-front combined hash has no consumer yet; add it if a dashboard asks to pin one front's arc independently.

---

# Part XVIII — What this gives the user

- **One whole-deal posture report from the archive alone.** Archive each round's kilobyte coherence artifact as you go; `coherence-arc` shows, per front, the floor arc *and* the agreement arc side by side — did the cap erode, and did it also fracture? did the floor hold while the package quietly split? — across the entire deal, with no clause text checked out and no re-analysis run. The v13 per-front combined view a deal lead reads at a glance, generalized to N rounds and computed deterministically from N small, verifiable files.
- **One gate for "did anything go wrong."** `--fail-on-regression-or-fracture` fires when the floor regressed at any step *or* the package fractured at any step — the single CI verdict over both axes, computed from one read of the artifacts instead of `||`-ing two commands' exit codes (and with a single `arc_hash` to pin the report an auditor reviewed).
- **A join you can trust.** The arc carries the two single-axis commands' fingerprints verbatim and its own `arc_hash` derived from them, so the combined report is provably exactly the join of `coherence-trend` and `coherence-shift-trend` on the same inputs — no silent mis-alignment, no recomputation a consumer must re-verify.
- **The same five promises.** Deterministic, no AI, no server, citable, never drafts — every line of v19 passes the §3 gate. It composes v17's floor trajectory and v18's shift trajectory (each itself composing v13's classifiers, v14's verifying parser, and v15/v16's ladder guard) into one headless command; it adds no posture math and no on-disk format, and it changes no existing source file's behavior — every existing surface is byte-for-byte unchanged.
