# Vaulytica v23 — Document-Free Exposure Recurrence (Per-Front Below-Floor Episodes)

> **Status:** **Shipped (9.20.0).** v21 gave the posture archive a *duration* axis: per front, how many rounds it sat below the acceptable floor and whether it is *still* below floor now. But duration is a **sum** — it adds up every below-floor round and forgets their *shape*. A front whose binding floor reads `below → below → below` (one steady descent) and a front that reads `below → acceptable → below` (it fell, **recovered**, and fell **again**) both report `rounds_below = 2` and `currently_below = true` / `persistence = open` in v21: the same duration, the same standing, the same gate. Yet the second front is categorically worse — a concession the team *won back* and then *lost again*. v21 cannot see it, because it collapses the floor path into one number; v17 cannot (its net first-vs-last is `unchanged`); v20 cannot (its worst point is the same); v22 cannot (its per-round count is blind to which front recurred). That is a missing **axis**: not *how low* (v20), not *how long* (v21), not *how broad* (v22), but **how many separate times** a front went below floor. v23 supplies it: read the same N artifacts per front and count the **maximal contiguous below-floor episodes** (`below_runs`) — one descent is one episode; a recover-then-relapse is two. It names the deal's **most recurrent front** and gates, with no tuning, on any front that fell below floor in **two or more** episodes (it recovered and relapsed). It continues the global step numbering after v22's Step 202, beginning at **Step 203**. One new subcommand, one pure module, **zero** change to any existing source file.
> **Scope:** one idea — the *episode-count* reduction the duration axis sums away. v17/v18/v19 answer *which way did a front move*; v20 answers *how low did a front ever get*; v21 answers *how long was a front down, and is it still down*; v22 answers *how broad was the deal each round*; v23 answers *how many separate times did a front fall below floor* — a count of below-floor **runs**, not their total length. The use case is the same archive of per-round coherence artifacts: v21 says "the Cap front has been below floor two rounds and is still down"; v23 says "and those two rounds were **not** consecutive — Cap fell, recovered in round 2, and fell again, so this is a recurring concession, not a single open wound."
> **Posture (unchanged, non-negotiable):** deterministic (the episode count is a pure per-front run-length scan over the same `below-acceptable` rung v10 defines, taken over the binding floors v12 already derived and v20/v21 already read; same artifacts → identical `recurrence_hash`, on any machine, forever), no AI / no probabilistic path, no server (N local files in, one report out; no socket), citable (the artifacts carry the same per-front binding floors v12 derived from each document's own clause and the team's own playbook — v23 adds no new claim), lints / references / positions — but never drafts, and never renders a legal conclusion. The command is **advisory and verifiable**: every artifact is hash-verified (a tampered round is a hard error, side-labeled by round index), and the ladders are checked for a match across the *whole* sequence (any cross-ladder pair is refused) via the same `verifyCoherenceSequence` loader the six trend/exposure/persistence/breadth commands use, unchanged. Every step passes the §3 filter or it does not ship.
> **Cousin docs:** [`spec.md`](spec.md) (v1, the linter), [`spec-v8.md`](spec-v8.md) (Reach — the headless CLI this rides on; `diff`/`compare`/`compare-coherence`/`coherence-trend`/`coherence-shift-trend`/`coherence-arc`/`coherence-exposure`/`coherence-persistence`/`coherence-breadth` are its sibling subcommands), [`spec-v10.md`](spec-v10.md) (Negotiation Posture — the **rung ladder** and the `below-acceptable` floor this reads), [`spec-v12.md`](spec-v12.md) (Posture Coherence — the artifact's payload and the **binding floor** `weakest_tier`), [`spec-v14.md`](spec-v14.md) (Saved Coherence Baselines — the artifact this consumes), [`spec-v15.md`](spec-v15.md) (Ladder-Pinned Coherence Baselines — the cross-ladder guard), [`spec-v17.md`](spec-v17.md) (Document-Free Coherence Trajectory — a movement-axis sibling; the shared sequence loader is reused unchanged), [`spec-v20.md`](spec-v20.md) (Document-Free Posture Exposure — the level-axis sibling), [`spec-v21.md`](spec-v21.md) (Document-Free Exposure Persistence — **the duration-axis sibling whose summed `rounds_below` this decomposes into episodes**), [`spec-v22.md`](spec-v22.md) (Document-Free Exposure Breadth — the per-round transpose). Progress in [`BUILD_PROGRESS.md`](../BUILD_PROGRESS.md).

---

# Part 0 — Intent

## §1. Why we're doing this

v21 gave the posture archive a duration axis — per front, the *count* of rounds it sat below the acceptable floor, and whether its latest stated floor is still below. That is the right shape for "how long has the Cap front been exposed, and is it still open?" But a deal lead reconciling a long negotiation asks a second, categorically different question that duration cannot answer: **did this front fall below floor *once*, or did we win it back and lose it again?**

v21 cannot answer it, because `rounds_below` is a **sum**. It adds every below-floor round and discards the order. Two fronts the archive holds as completely different deals report identically:

- **The steady descent.** Cap's binding floor reads `below-acceptable → below-acceptable → below-acceptable`. It fell in round 1 and stayed down. `rounds_below = 3`, `persistence = open` — one continuous wound.
- **The recurring concession.** Cap's binding floor reads `below-acceptable → acceptable → below-acceptable`. It fell in round 1, the team **recovered** it to `acceptable` in round 2, and it fell **again** in round 3. `rounds_below = 2`, `persistence = open` — but this is a concession won back and then lost, the kind of churn that signals an unstable front the other side keeps re-opening.

To v21 (and v20, and v17, and v22) these are the same or near-same: same `open` standing, same worst point, `unchanged` net movement, same per-round contribution. None of the existing commands reports the one fact that distinguishes them — that the second front's below-floor rounds came in **two separate episodes** with a recovery between, while the first's came in one. To learn it from v21 a consumer must pull each front's `floors[]` array and hand-scan it for recover-then-relapse, reconstructing the episode structure the archive never reports.

This is not a bug in v21 — a duration is *supposed* to sum. It is a missing **axis**: the *episode-count* dimension of the same below-floor data. Where v21 measures the **total length** of the below-floor stretches, v23 measures **how many stretches there were**.

v23 supplies it. Read the same artifacts per front and count the **maximal contiguous below-floor episodes** (`below_runs`): the number of separate times the front's binding floor entered `below-acceptable` and stayed there until a *stated* recovery (a round whose binding floor is at or above acceptable). One descent is one episode; a recover-then-relapse is two; an oscillating front is three or more. The gate follows: `--fail-on-recurring-exposure` fires when any front fell below floor in **two or more** episodes — it recovered and relapsed — the one recurrence condition whose meaning needs no tuning. All of this is cheaply derivable from the `floors[]` array v21 already carries.

## §2. What v23 is and is not

**It is:**
- A **document-free recurrence command.** `coherence-recurrence <r1.coherence.json> … <rN.coherence.json>` reads N ≥ 2 saved coherence artifacts in round order, verifies each, runs the cross-ladder guard across all of them, and prints, *per front*, the binding-floor path (`floors`), how many rounds it was below floor (`rounds_below`, the v21 sum, for context), the count of **separate below-floor episodes** (`below_runs`), the 1-based round ranges of each episode (`episodes`), and a `recurrence` class — `recurring` (≥ 2 episodes), `single` (exactly 1), `none` (stated, never below floor), or `unstated` (§3) — plus the deal's **most recurrent front** (`most_recurrent_dimension` / `max_runs`). Markdown (default) or `--format json`. No documents are read; the engine is never run.
- A **single deal-level recurrence gate.** `--fail-on-recurring-exposure` exits 2 when any front fell below floor in two or more separate episodes (`recurring_count > 0`). This is the *churn* counterpart to v21's *current-standing* gate and v20's *ever* gate: where `--fail-on-exposure` fires on any front ever below floor and `--fail-on-open-exposure` on any front still below floor, `--fail-on-recurring-exposure` fires on any front that went below floor, recovered, and went below floor **again**. A front that fell once and stayed (one episode) does not trip it; a single clean recovery (one episode that then resolved) does not trip it; only a recover-then-relapse does. It needs no tuning — two episodes is the threshold that *means* recurrence.
- A **whole-sequence-verified input, sharing the v17–v22 front end.** Every artifact's `coherence_hash` is re-derived and checked on load (a tampered/corrupt round is a hard error, errors prefixed `round N:`). The v15/v16 cross-ladder guard runs across the sequence via the same `verifyCoherenceSequence` loader the six trend/exposure/persistence/breadth commands use, with no change to it.
- A **derived report carrying its own fingerprint.** The recurrence carries a `recurrence_hash` (a stable SHA-256 over the canonical per-front set), namespaced apart from every `coherence_hash`, `movement_hash`, `trajectory_hash`, `shift_trajectory_hash`, `arc_hash`, `exposure_hash`, `persistence_hash`, and `breadth_hash`, so the same N artifacts in the same order always reproduce the same report.

**It is not:**
- **Not a new diff, classifier, predicate, or artifact format.** It reuses the `weakest_tier` binding floor v12 derives and the `below-acceptable` rung v10 defines; v23 is a subcommand plus one pure module (`computeCoherenceRecurrence`) whose only new logic is a per-front run-length scan of the same `floors[]` array v21 builds. `parsePostureCoherenceJson`, the coherence schema, and every trajectory/exposure/persistence/breadth function are unchanged.
- **Not a duration command.** v21 sums every below-floor round (`rounds_below`) and reports the current standing; v23 counts the *episodes* those rounds form. `rounds_below = 2` can be one episode (steady) or two (recur); v21 reports the 2, v23 reports the episode structure. v23 carries `rounds_below` only as context — its verdict is `below_runs`.
- **Not a "still down" command.** v23 does not gate on current standing (that is v21's `--fail-on-open-exposure`). A front that recurred and is *now resolved* still trips `--fail-on-recurring-exposure` (it relapsed at least once, even if its latest stated floor recovered), and a front still open with a *single* episode does not. Recurrence and current-standing are orthogonal; a consumer wanting both runs v21 and v23.
- **Not silence-splits-an-episode.** A round no document states does **not** end a below-floor episode: per §3 (the v21 contract that current standing reads the latest *stated* round), silence after an exposure keeps the last known standing — it is neither a recovery nor a fresh fall. So `below → unstated → below` is **one** episode (silence does not split it); only a *stated* at-or-above-floor round (a real recovery) ends an episode. This keeps v23 from inventing a recurrence out of a missing document.
- **Not a configurable-threshold "too churny" classifier.** v23 does not take a `--fail-over N` episodes knob; the gate fires on `below_runs ≥ 2`, the one recurrence condition whose meaning ("the front recovered and relapsed") needs no tuning. A team wanting to gate on a *higher* episode count reads `max_runs` from the JSON. (v20 made the same call against a configurable floor; v21 against a configurable duration; v22 against a configurable breadth; v23 against a configurable episode count.)
- **Not a per-round command.** v22 fixes a round and counts fronts; v23 fixes a front and counts episodes. They are different reductions of the same matrix; a consumer wanting one round's standing reads v22, one wanting one front's churn reads v23.
- **Not a recurrence artifact.** v23 introduces no new on-disk format; the recurrence is *derived*, recomputed on demand from the N auditable coherence inputs — the same "keep the derived thing derived" discipline v14–v22 hold.
- **Not a sequence the command discovers.** It does not glob a directory or sort filenames; the caller passes the artifacts **in round order** on the argv, exactly as the six trend/exposure/persistence/breadth commands do.
- **Not a browser surface.** An N-round recurrence of uploaded artifacts is a CI/dashboard concern, which is what this command serves (mirroring v16–v22).

## §3. The posture filter (unchanged)

1. **Deterministic** — `computeCoherenceRecurrence` over N `PostureCoherence` objects is pure: it matches fronts by dimension, pins them by `localeCompare(_, "en")` (the same order the trajectory/exposure/persistence functions use), and counts each front's maximal contiguous below-floor episodes over the caller's round order. Identical artifacts in identical order → identical `recurrence_hash` on any machine.
2. **Honest about unstated data** — a front no document states in *any* round is `unstated`, never `recurring`/`single`/`none`. Within a front's path, an unstated round does **not** end a below-floor episode (silence is not a recovery — the §3 contract that keeps `unstated` never-flagged in v20 and current standing reading the latest *stated* round in v21). Only a *stated* at-or-above-floor round splits an episode.
3. **Advisory** — the command names how many separate times each front sat below the team's own floor. It asserts no legal conclusion.
4. **No server** — N local files in, one report out. No socket, no engine run.
5. **Additive** — a brand-new subcommand and one new pure module. Every existing command (`analyze`, `diff`, `compare`, `compare-coherence`, `coherence-trend`, `coherence-shift-trend`, `coherence-arc`, `coherence-exposure`, `coherence-persistence`, `coherence-breadth`, `verify`) is byte-for-byte unchanged in *output and goldens*; `coherence-sequence.ts` is imported and reused **without modification** (v23 needs nothing exported that was not already public — like v19–v22, it touches no existing source file's behavior at all).

---

# Part I — The recurrence (pure)

`src/report/coherence-recurrence.ts` (a new sibling to `coherence-persistence.ts`):

- **`RecurrenceClass`** — a front's below-floor episode class: `recurring` (≥ 2 episodes — recovered and relapsed), `single` (exactly 1 episode), `none` (stated, never below floor), `unstated` (no document ever stated the front).
- **`CoherenceRecurrenceFront`** — one front's whole-sequence episode structure: the `dimension`, `floors` (the binding floor at each round, `null` = unstated), `rounds_below` (the v21 sum, for context), `below_runs` (the count of separate below-floor episodes), `episodes` (the 1-based `{ first_round, last_round }` range of each episode, in order), and the `recurrence` class.
- **`CoherenceRecurrence`** — the whole-sequence per-front series: `rounds` (count), `fronts[]` (the fronts above, pinned by `localeCompare`), `class_counts` (per-front tally by class), `recurring_count` (fronts with ≥ 2 episodes — the gate-worthy count), `most_recurrent_dimension` / `max_runs` (the front with the most episodes, earliest on a tie — `null` / `0` when no front was ever below floor), and `recurrence_hash`.
- **`computeCoherenceRecurrence(rounds: PostureCoherence[])`** — the pure, IO-free core. For each front, scans `floors[]` for maximal contiguous below-floor episodes (a *stated* at-or-above round ends an episode; an unstated round does not, §3), records each episode's round range, classifies the front, finds the most recurrent front, and returns the series with a `recurrence_hash`. Requires ≥ 2 rounds.
- **`exposureRecurred(recurrence)`** — the CI gate predicate: `recurrence.recurring_count > 0`. The episode-churn verdict no other command exposes (v20/v21 gate on level/standing; this gates on recover-then-relapse).
- **`buildCoherenceRecurrenceJson(recurrence)`** / **`renderCoherenceRecurrenceSummary(recurrence)`** — the JSON (`schema: vaulytica.posture-recurrence.v1`) and human-readable renderers. The summary prints the class tally and the recurring count, then one line per **recurring** front (its episode count, the episode round ranges, and the floor path), then one line per **single** front, then the hash.

v23 imports only the already-public `PostureCoherence` type, the `NegotiationTier` type, and the shared hashing helpers; the `below-acceptable` literal is a plain string; no existing source file changes.

# Part II — The command (headless)

`tools/cli/coherence-recurrence.ts` (a new sibling to `coherence-persistence.ts`):

- **`computeCoherenceRecurrenceArtifacts(texts, format?)`** — the pure CLI core. Verifies all N artifacts and runs the cross-ladder guard via the shared `verifyCoherenceSequence` loader (unchanged from v18–v22); on any malformed/tampered round returns `{ ok: false, errors }` (each prefixed `round N:`); on a cross-ladder pair returns `{ ok: false }` naming the two rounds; an unpinned artifact yields `{ ok: true }` with a `ladderNote`. Then `computeCoherenceRecurrence(rounds)` and renders (markdown summary or JSON), returning `{ ok: true, output, recurring, ladderNote }`.
- **`runCoherenceRecurrence(argv)`** — the CLI handler: reads the N files, calls the core, writes the `ladderNote` (if any) to stderr, prints the recurrence to stdout, and — under `--fail-on-recurring-exposure` — exits 2 when any front recurred. A malformed/tampered/cross-ladder input is a hard exit-1 error. Requires ≥ 2 positionals.

`tools/cli/run.ts` (the dispatcher) gains a `coherence-recurrence` case and a `USAGE` entry.

```
# Each round, archive its coherence (kilobytes, no clause text):
vaulytica analyze 'round1/*.docx' --playbook-file team.playbook.json --posture --emit-coherence round1.coherence.json
vaulytica analyze 'round2/*.docx' --playbook-file team.playbook.json --posture --emit-coherence round2.coherence.json
vaulytica analyze 'round3/*.docx' --playbook-file team.playbook.json --posture --emit-coherence round3.coherence.json

# Later — read/gate whether any front fell below floor, recovered, and fell again, from the archive alone:
vaulytica coherence-recurrence round1.coherence.json round2.coherence.json round3.coherence.json \
  --fail-on-recurring-exposure
```

---

# Part XV — Build plan

Continuing the global numbering after v22's Step 202. Verification gate for every step: `npm run typecheck && lint && test && build` green; the v7 coverage/parity/property gates, the v8 fuzz + citation gates, the v9 no-wall-clock gate, and the responsiveness e2e stay green.

Status legend: **✅ shipped** · ⬜ proposed.

| # | Step | Output | Tier |
|---|------|--------|------|
| 203 ✅ | `coherence-recurrence` per-front below-floor episode count & churn gate | `src/report/coherence-recurrence.ts` — `RecurrenceClass`, `CoherenceRecurrenceFront`, `CoherenceRecurrence`, pure `computeCoherenceRecurrence` (per-front maximal contiguous below-floor episode count + episode round ranges + class + most-recurrent front; namespaced `recurrence_hash`), `exposureRecurred` predicate (= `recurring_count > 0`), JSON + markdown renderers. `tools/cli/coherence-recurrence.ts` — `computeCoherenceRecurrenceArtifacts` (pure, reusing `verifyCoherenceSequence` unchanged) + `runCoherenceRecurrence` (file IO + exit codes); dispatcher + `USAGE` wired. Tests: recurrence identity disk-vs-in-memory, per-front episode count + ranges, the steady descent (1 episode, gate clears) vs the recover-then-relapse (2 episodes, gate trips) that v21 reports identically, silence-does-not-split-an-episode (§3), a stated recovery does split, recurred-then-resolved still trips, single-episode-still-open does not, most-recurrent front (earliest on tie), unstated-is-never-counted (§3), no-front-ever-below (max_runs 0), determinism, ≥2-artifact requirement, cross-ladder refusal across the sequence (naming the two rounds), unpinned-v1 note, tamper rejection (round-prefixed), gate parity, render + JSON. Every existing command's suite passes unchanged. | Reach |

Total work shipped this spec: **1 build step (203).** Purely additive — a new subcommand and one pure module that reads the binding floor already in every artifact; **no existing source file's behavior changes** (v23 needs nothing newly exported), and every existing command's output and golden is unchanged.

---

# Part XVI — Principled deferrals

- **A `coherence-persistence --episodes` flag.** ⬜ Not built — and deliberately not, mirroring v18/v19/v20/v21/v22 Part XVI. v23 is a separate command, not a flag on the duration command, so each command keeps exactly one gate and one hash.
- **A configurable "too churny" gate (`--fail-over N` episodes).** ⬜ Not built. The gate fires on `below_runs ≥ 2` (recovered and relapsed), the one recurrence condition whose meaning needs no tuning. `max_runs` is in the JSON for a consumer that wants to threshold on a higher episode count.
- **A standalone recurrence artifact (`--emit-recurrence`).** ⬜ Deferred, for the same reason v14–v22 keep the derived thing derived: the recurrence is cheaply recomputable from the N coherence artifacts on demand, keeping the auditable inputs (each ladder-pinned, hash-verified) as the source of truth.
- **A *gap-aware* episode model (silence splits an episode after K rounds).** ⬜ Not built. v23 treats silence as continuation (§3); a "silence resets after K rounds" rule re-introduces the tuning §3 avoids and has no consumer yet.
- **A *longest-episode* / *mean-episode-length* statistic.** ⬜ Not built. The `episodes[]` ranges already let a consumer compute either; a single headline has no consumer yet.
- **A directory/glob walker that infers round order.** ⬜ Not built. The command takes artifacts in round order on the argv (the caller's contract, mirroring the trend/exposure/persistence/breadth commands).
- **A browser surface for an N-round recurrence.** ⬜ Deferred (v16–v22 Part XVI). The browser does an in-session two-round comparison; an N-artifact recurrence is a CI/dashboard concern.

---

# Part XVII — Open questions for the maintainer

1. **Fold recurrence into a single "deal posture" command that reports duration *and* episodes?** Today the duration command (v21) and the episode command (v23) are split. A dashboard wanting both runs both and joins on the shared `floors[]` matrix. Recommendation: **keep them split at the command layer** — they carry categorically different gates (duration "still below" vs churn "recovered and relapsed") and different hashes; bolting one onto the other would give that command two unlike gates. If a dashboard asks for the combined view, add a consumer the same way v19 joined v17 and v18 — as its own composing command, not a flag.
2. **Report a *re-exposure latency* (how many rounds between a recovery and the next relapse)?** The `episodes[]` ranges already let a consumer compute the gap between consecutive episodes; v23 does not headline it. Recommendation: **defer** — the per-episode ranges expose it, and a single "mean recovery gap" headline has no consumer yet; add it if a dashboard asks to pin one.

---

# Part XVIII — What this gives the user

- **The shape of each front's exposure, from the archive alone.** Archive each round's kilobyte coherence artifact as you go; `coherence-recurrence` shows, per front, not just *how long* it sat below floor (v21) but *in how many separate episodes* — distinguishing a single steady descent from a concession won back and lost again, with no clause text checked out and no re-analysis run. The "did we re-open this front?" question a deal lead asks at the close, answered deterministically from N small, verifiable files.
- **A gate on churn, not just standing or level.** `--fail-on-recurring-exposure` fires when a front went below floor, recovered, and went below floor again — the recover-then-relapse pattern the duration gate (v21) and level gate (v20) structurally cannot pose, since one sums rounds and the other takes an extreme. It catches the unstable front the other side keeps re-opening, even when its latest stated floor has recovered.
- **The same five promises.** Deterministic, no AI, no server, citable, never drafts — every line of v23 passes the §3 gate. It reads the binding floor v12 already derives and the `below-acceptable` rung v10 already defines, through the loader v18–v22 already share; it adds one per-front episode count, no on-disk format, and no change to any existing source file's behavior — every existing surface is byte-for-byte unchanged.
