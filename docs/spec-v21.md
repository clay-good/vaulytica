# Vaulytica v21 — Document-Free Exposure Persistence (Chronicity & Current Standing)

> **Status:** **Shipped (9.18.0).** v20 read the posture archive on the **level** axis: per front, the *worst* binding floor it ever reached across the whole deal (its low-water mark), and one deal-level gate (`--fail-on-exposure`) that trips if any front *ever* fell below the team's acceptable floor. That answers "how low did it get." But a low-water mark is a single extreme with no memory of time: a front that dipped to `below-acceptable` in round 2 and **recovered** to `acceptable` by round 5 carries the exact same `worst_floor = below-acceptable` / `exposed = true` as a front **still** sitting at `below-acceptable` in round 5 — v20 reports them identically, and `--fail-on-exposure` fires on both. A deal team that *resolved* a dip has no way to make that gate go green, and no command tells it whether an exposure is a closed wound or an open one. v21 reads the same N artifacts on the orthogonal **duration** axis: per front, *how many* rounds it spent below the floor, the *span* of rounds it was down (first→last), whether its **latest stated** floor is still below acceptable (its current standing), and a `persistence` class (`open` / `resolved` / `none` / `unstated`) — plus one deal-level gate that trips only on a front **still** below floor at the latest round it was stated. It continues the global step numbering after v20's Step 200, beginning at **Step 201**. One new subcommand, one pure module, **zero** change to any existing source file.
> **Scope:** one idea — the *time* axis the level family never read. v17/v18/v19 answer *which way did it move*; v20 answers *how low did it ever get*; v21 answers *how long was it down, and is it still down now?* It is the complement to v20 on the same below-floor data: where v20 reduces a front's history to a single worst point, v21 reduces it to a duration and a current standing. The use case is the same dashboard or audit log that archived every round's kilobyte coherence artifact: v20 says "this front fell below floor at some point"; v21 says "and it was below floor for three of five rounds and is **still** below floor" — or, conversely, "but it recovered two rounds ago, so the gate is clear."
> **Posture (unchanged, non-negotiable):** deterministic (the persistence is a pure scan over the same `below-acceptable` rung v10 defines, taken over the binding floors v12 already derived and v20 already reads; same artifacts → identical `persistence_hash`, on any machine, forever), no AI / no probabilistic path, no server (N local files in, one report out; no socket), citable (the artifacts carry the same per-front binding floors v12 derived from each document's own clause and the team's own playbook — v21 adds no new claim), lints / references / positions — but never drafts, and never renders a legal conclusion. The command is **advisory and verifiable**: every artifact is hash-verified (a tampered round is a hard error, side-labeled by round index), and the ladders are checked for a match across the *whole* sequence (any cross-ladder pair is refused) via the same `verifyCoherenceSequence` loader the four trend/exposure commands use, unchanged. Every step passes the §3 filter or it does not ship.
> **Cousin docs:** [`spec.md`](spec.md) (v1, the linter), [`spec-v8.md`](spec-v8.md) (Reach — the headless CLI this rides on; `diff`/`compare`/`compare-coherence`/`coherence-trend`/`coherence-shift-trend`/`coherence-arc`/`coherence-exposure` are its sibling subcommands), [`spec-v10.md`](spec-v10.md) (Negotiation Posture — the **rung ladder** and the `below-acceptable` floor this reads), [`spec-v12.md`](spec-v12.md) (Posture Coherence — the artifact's payload and the **binding floor** `weakest_tier`), [`spec-v14.md`](spec-v14.md) (Saved Coherence Baselines — the artifact this consumes), [`spec-v15.md`](spec-v15.md) (Ladder-Pinned Coherence Baselines — the cross-ladder guard), [`spec-v17.md`](spec-v17.md) (Document-Free Coherence Trajectory — a movement-axis sibling; the shared sequence loader is reused unchanged), [`spec-v20.md`](spec-v20.md) (Document-Free Posture Exposure — **the level-axis sibling whose single worst-point view this complements with duration and current standing**). Progress in [`BUILD_PROGRESS.md`](../BUILD_PROGRESS.md).

---

# Part 0 — Intent

## §1. Why we're doing this

v20 gave the posture archive a level axis: the worst binding floor each front ever reached. That is the right answer to "how exposed did we get at our worst." But "the worst point" is, by construction, a single value with no duration — it cannot tell a closed wound from an open one. Two histories collapse to the same v20 row:

- **The resolved dip.** A front sits at `ideal`, slips to `below-acceptable` in round 2 when one document undercuts it, and the team fixes that document so the front climbs back to `acceptable` by round 4 and holds. The exposure is *over*. Yet v20 reports `worst_floor = below-acceptable`, `exposed = true`, and `--fail-on-exposure` exits 2 — forever, because the worst point never changes once it has happened.
- **The open wound.** A front slips to `below-acceptable` in round 2 and is *still* `below-acceptable` in the latest round. v20 reports exactly the same row.

A deal lead reading v20 cannot distinguish "we had a scare and closed it" from "we are below our floor right now and have been for three rounds." Worse, the team that resolved its dip is stuck with a red gate it cannot clear without re-litigating history. This is not a bug in v20 — a low-water mark is *supposed* to be a single extreme. It is a missing **axis**: the *time* dimension of the same below-floor data.

v21 supplies it. Read the same artifacts not for the worst floor but for the *persistence* of the below-floor condition: how many rounds was each front below acceptable, over what span, and — the question that distinguishes the two histories above — is it **still** below acceptable at the latest round that stated it? The gate follows: `--fail-on-open-exposure` fires only on a front whose current standing is below floor, so the resolved dip clears it and the open wound trips it. All of this is cheaply derivable from data already in every artifact.

## §2. What v21 is and is not

**It is:**
- A **document-free persistence command.** `coherence-persistence <r1.coherence.json> … <rN.coherence.json>` reads N ≥ 2 saved coherence artifacts in round order, verifies each, runs the cross-ladder guard across all of them, and prints, per negotiation front, the binding floor at every round, how many rounds it was **below acceptable** (`rounds_below`), the **span** it was down (`first_below_round`→`last_below_round`), its **current standing** (`currently_below` — is the latest *stated* floor below acceptable), and a `persistence` class. Markdown (default) or `--format json`. No documents are read; the engine is never run.
- A **single current-standing gate over a whole negotiation.** `--fail-on-open-exposure` exits 2 when any front's `persistence` is `open` — its latest stated binding floor is below the acceptable floor. This is the *current-standing* counterpart to v20's *ever* gate: where `--fail-on-exposure` fires on a floor that was below acceptable at *any* round (and stays red after a recovery), `--fail-on-open-exposure` fires only on a front below floor *now*, so a resolved dip clears the gate and an open wound trips it.
- A **whole-sequence-verified input, sharing the v17–v20 front end.** Every artifact's `coherence_hash` is re-derived and checked on load (a tampered/corrupt round is a hard error, errors prefixed `round N:`). The v15/v16 cross-ladder guard runs across the sequence via the same `verifyCoherenceSequence` loader the four trend/exposure commands use, with no change to it.
- A **derived report carrying its own fingerprint.** The persistence carries a `persistence_hash` (a stable SHA-256 over the canonical per-front set), namespaced apart from every `coherence_hash`, `movement_hash`, `trajectory_hash`, `shift_trajectory_hash`, `arc_hash`, and `exposure_hash`, so the same N artifacts in the same order always reproduce the same report.

**It is not:**
- **Not a new diff, classifier, predicate, or artifact format.** It reuses the `weakest_tier` binding floor v12 derives and the `below-acceptable` rung v10 defines; v21 is a subcommand plus one pure module (`computeCoherencePersistence`) whose only new logic is a count and a last-stated lookup per front. `parsePostureCoherenceJson`, the coherence schema, and every trajectory/exposure function are unchanged.
- **Not a movement command, and not the level command.** It deliberately does *not* classify direction (v17/v18/v19) or report a worst point (v20); it reports a *duration* and a *current standing*. The three axes are complementary: a front can be `flat`+`exposed`+`open` (pinned below floor all deal), `steady-improvement`+`exposed`+`resolved` (dipped, then climbed back above floor), or `whipsaw`+`exposed`+`open` (oscillating, currently down).
- **Not a configurable-threshold "chronic" classifier.** v21 does not take a `--chronic-after N` knob; the gate fires on current standing (`open`), the one condition whose meaning ("we are below our floor right now") needs no tuning. A team wanting to gate on a *count* of below-floor rounds reads `rounds_below` from the JSON. (v20 Part XVI made the same call against a configurable floor; v21 makes it against a configurable duration.)
- **Not a replacement for the per-round divergence check or the two-round compare.** `analyze --posture` reads one round's documents; `compare-coherence` diffs the last two rounds; v21 reads the *whole-deal* persistence and current standing across N archived rounds, with no documents on any side. `compare-coherence` could show the last two rounds recovered, but it cannot see how many of the earlier N rounds the front was down.
- **Not a persistence artifact.** v21 introduces no new on-disk format; the persistence is *derived*, recomputed on demand from the N auditable coherence inputs — the same "keep the derived thing derived" discipline v14–v20 hold.
- **Not a sequence the command discovers.** It does not glob a directory or sort filenames; the caller passes the artifacts **in round order** on the argv, exactly as the four trend/exposure commands do.
- **Not a browser surface.** An N-round persistence of uploaded artifacts is a CI/dashboard concern, which is what this command serves (mirroring v16–v20).

## §3. The posture filter (unchanged)

1. **Deterministic** — `computeCoherencePersistence` over N `PostureCoherence` objects is pure: it scans each front's binding floors for the `below-acceptable` rung and reads the latest stated floor. Fronts are pinned by `localeCompare(_, "en")` — the same order the trajectory/exposure functions use. Identical artifacts in identical order → identical `persistence_hash` on any machine.
2. **Honest about unstated data** — a front no document states in *any* round has a `persistence` of `unstated`, never `open` or `resolved`: "not stated" is not a point on the ideal→floor axis, so silence is never a false exposure (the §3 contract that keeps `newly-stated`/`now-unstated` unranked in v11/v13 and `unstated` never-flagged in v20). **Current standing reads the latest round that *stated* the front**, not the latest round overall: a front below floor in round 3 then unstated in rounds 4–5 keeps its last *known* standing (`below-acceptable` → `open`) — silence after an exposure is neither a recovery (we do not invent an improvement no document made) nor a fresh exposure. `rounds_below` counts only rounds that *stated* a below-floor rung.
3. **Advisory** — the command names how long each front sat below the team's own floor and where it stands now. It asserts no legal conclusion.
4. **No server** — N local files in, one report out. No socket, no engine run.
5. **Additive** — a brand-new subcommand and one new pure module. Every existing command (`analyze`, `diff`, `compare`, `compare-coherence`, `coherence-trend`, `coherence-shift-trend`, `coherence-arc`, `coherence-exposure`, `verify`) is byte-for-byte unchanged in *output and goldens*; `coherence-sequence.ts` is imported and reused **without modification** (v21 needs nothing exported that was not already public — like v19/v20, it touches no existing source file's behavior at all).

---

# Part I — The persistence (pure)

`src/report/coherence-persistence.ts` (a new sibling to `coherence-exposure.ts`):

- **`PersistenceClass`** — a front's below-floor history class: `open` (latest stated floor is below acceptable — still down), `resolved` (was below floor at some round but the latest stated floor is at/above acceptable — recovered), `none` (stated, but never below floor), `unstated` (no document ever stated the front).
- **`CoherencePersistenceFront`** — one front's whole-sequence below-floor duration: the `floors[]` sequence (shared with v17/v20), `rounds_below` (count of rounds whose stated floor is `below-acceptable`), `first_below_round` / `last_below_round` (1-based span of the below-floor window, `null` when never below floor), `last_stated_round` (1-based latest round that stated a floor, `null` when never stated), `currently_below` (the floor at `last_stated_round` is `below-acceptable`), and `persistence` (the class above).
- **`computeCoherencePersistence(rounds: PostureCoherence[])`** — the pure, IO-free core. Matches fronts by dimension, pins them by `localeCompare`, scans each front's floors for the below-floor rung (count + first/last), reads the latest stated floor for current standing, classifies, tallies `class_counts`, counts `open` fronts (`open_count`), and returns the set with a `persistence_hash`. Requires ≥ 2 rounds.
- **`exposureOpen(persistence)`** — the CI gate predicate: `open_count > 0`. The current-standing verdict no other command exposes (v20's gate stays red after a recovery; this one clears).
- **`buildCoherencePersistenceJson(persistence)`** / **`renderCoherencePersistenceSummary(persistence)`** — the JSON (`schema: vaulytica.posture-persistence.v1`) and human-readable renderers. The summary prints the class tally and the open-front count, then one line per **open** front (still below floor — showing the floor path, how many rounds it was down, and the span), then one line per **resolved** front (recovered — showing when it was down and that it is now back above floor); an `unstated` or `none` front is counted but never listed.

v21 imports only already-public functions (`TIER_RANK` for the floor comparison; the `below-acceptable` literal is a plain `NegotiationTier`); no existing source file changes.

# Part II — The command (headless)

`tools/cli/coherence-persistence.ts` (a new sibling to `coherence-exposure.ts`):

- **`computeCoherencePersistenceArtifacts(texts, format?)`** — the pure CLI core. Verifies all N artifacts and runs the cross-ladder guard via the shared `verifyCoherenceSequence` loader (unchanged from v18–v20); on any malformed/tampered round returns `{ ok: false, errors }` (each prefixed `round N:`); on a cross-ladder pair returns `{ ok: false }` naming the two rounds; an unpinned artifact yields `{ ok: true }` with a `ladderNote`. Then `computeCoherencePersistence(rounds)` and renders (markdown summary or JSON), returning `{ ok: true, output, open, ladderNote }`.
- **`runCoherencePersistence(argv)`** — the CLI handler: reads the N files, calls the core, writes the `ladderNote` (if any) to stderr, prints the persistence to stdout, and — under `--fail-on-open-exposure` — exits 2 when any front is `open`. A malformed/tampered/cross-ladder input is a hard exit-1 error. Requires ≥ 2 positionals.

`tools/cli/run.ts` (the dispatcher) gains a `coherence-persistence` case and a `USAGE` entry.

```
# Each round, archive its coherence (kilobytes, no clause text):
vaulytica analyze 'round1/*.docx' --playbook-file team.playbook.json --posture --emit-coherence round1.coherence.json
vaulytica analyze 'round2/*.docx' --playbook-file team.playbook.json --posture --emit-coherence round2.coherence.json
vaulytica analyze 'round3/*.docx' --playbook-file team.playbook.json --posture --emit-coherence round3.coherence.json

# Later — read/gate whether any front is STILL below floor (not merely ever was), from the archive alone:
vaulytica coherence-persistence round1.coherence.json round2.coherence.json round3.coherence.json \
  --fail-on-open-exposure
```

---

# Part XV — Build plan

Continuing the global numbering after v20's Step 200. Verification gate for every step: `npm run typecheck && lint && test && build` green; the v7 coverage/parity/property gates, the v8 fuzz + citation gates, the v9 no-wall-clock gate, and the responsiveness e2e stay green.

Status legend: **✅ shipped** · ⬜ proposed.

| # | Step | Output | Tier |
|---|------|--------|------|
| 201 ✅ | `coherence-persistence` below-floor duration & current standing | `src/report/coherence-persistence.ts` — `PersistenceClass`, `CoherencePersistenceFront`, pure `computeCoherencePersistence` (per-front below-floor count + span + latest-stated current standing → `open`/`resolved`/`none`/`unstated`; `class_counts` tally; namespaced `persistence_hash`), `exposureOpen` predicate (= `open_count > 0`), JSON + markdown renderers. `tools/cli/coherence-persistence.ts` — `computeCoherencePersistenceArtifacts` (pure, reusing `verifyCoherenceSequence` unchanged) + `runCoherencePersistence` (file IO + exit codes); dispatcher + `USAGE` wired. Tests: persistence identity disk-vs-in-memory, rounds-below + span + current standing, the resolved-dip front that v20 calls `exposed` forever but is now recovered (the blind spot this fills — `--fail-on-open-exposure` clears while `--fail-on-exposure` stays red), the open-wound front (still below floor → `open`, gate trips), unstated-is-never-open/resolved (§3), silence-after-exposure keeps the last known standing (§3), partially-stated front, class tally + open count, determinism, ≥2-artifact requirement, cross-ladder refusal across the sequence (naming the two rounds), unpinned-v1 note, tamper rejection (round-prefixed), gate parity, none/unstated fronts omitted from the summary; every existing command's suite passes unchanged. | Reach |

Total work shipped this spec: **1 build step (201).** Purely additive — a new subcommand and one pure module that reads the binding floor already in every artifact; **no existing source file's behavior changes** (v21 needs nothing newly exported), and every existing command's output and golden is unchanged.

---

# Part XVI — Principled deferrals

- **A `coherence-exposure --persistence` flag.** ⬜ Not built — and deliberately not, mirroring v18/v19/v20 Part XVI. v21 is a separate command, not a flag on the level command, so each command keeps exactly one gate and one hash.
- **A configurable "chronic-after N rounds" gate (`--fail-after N`).** ⬜ Not built. The gate fires on current standing (`open`), the one condition whose meaning needs no tuning. `rounds_below` is in the JSON for a consumer that wants to threshold on count.
- **A standalone persistence artifact (`--emit-persistence`).** ⬜ Deferred, for the same reason v14–v20 keep the derived thing derived: the persistence is cheaply recomputable from the N coherence artifacts on demand, keeping the auditable inputs (each ladder-pinned, hash-verified) as the source of truth.
- **A "consecutive vs. total" below-floor distinction.** ⬜ Not built. `rounds_below` is a total count; `first_below_round`/`last_below_round` give the span, from which a consumer can see whether the window was contiguous (`rounds_below === last − first + 1`). A dedicated longest-consecutive-run metric has no consumer yet.
- **A directory/glob walker that infers round order.** ⬜ Not built. The command takes artifacts in round order on the argv (the caller's contract, mirroring the trend/exposure commands).
- **A browser surface for an N-round persistence.** ⬜ Deferred (v16–v20 Part XVI). The browser does an in-session two-round comparison; an N-artifact persistence is a CI/dashboard concern.

---

# Part XVII — Open questions for the maintainer

1. **Fold persistence into exposure (a single command reports worst-point *and* duration)?** Today `coherence-exposure` reports the level extreme and `coherence-persistence` the duration + current standing. A dashboard wanting both runs both and joins on `dimension`. Recommendation: **keep them split at the command layer** — they carry categorically different gates (`--fail-on-exposure` = ever-below; `--fail-on-open-exposure` = still-below) and different hashes; bolting one onto the other would give that command two unlike gates. If a dashboard asks for the combined view, add a consumer the same way v19 joined v17 and v18 — as its own composing command, not a flag.
2. **Report the *longest-running* open front deal-wide (a single headline)?** The persistence reports every front's `rounds_below` and a class tally; it does not name "the front that has been down longest." Recommendation: **defer** — `open_count` and the per-front rows already let a consumer pick it (max `rounds_below`, earliest `first_below_round` tiebreak), and a single headline has no consumer yet; add it if a dashboard asks to pin one.

---

# Part XVIII — What this gives the user

- **Whether an exposure is open or closed, from the archive alone.** Archive each round's kilobyte coherence artifact as you go; `coherence-persistence` shows, per front, how many rounds it spent below the floor, the span it was down, and whether its latest stated floor is *still* below acceptable — across the entire negotiation, with no clause text checked out and no re-analysis run. The "are we still down, and how long have we been down" question a deal lead asks at the close, answered deterministically from N small, verifiable files.
- **A gate that clears when the team fixes the problem.** `--fail-on-open-exposure` fires when any front is below floor *now* — but goes green the moment that front recovers above floor, unlike `--fail-on-exposure`, which stays red forever once a dip has happened. The current-standing gate the level axis structurally cannot pose: it rewards the resolution v20 cannot see.
- **The same five promises.** Deterministic, no AI, no server, citable, never drafts — every line of v21 passes the §3 gate. It reads the binding floor v12 already derives and the `below-acceptable` rung v10 already defines, through the loader v18–v20 already share; it adds one count and one last-stated lookup, no on-disk format, and no change to any existing source file's behavior — every existing surface is byte-for-byte unchanged.
