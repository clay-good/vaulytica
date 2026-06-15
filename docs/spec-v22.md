# Vaulytica v22 — Document-Free Exposure Breadth (Per-Round Deal Standing)

> **Status:** **Shipped (9.19.0).** Every posture command from v16 to v21 reads the N-round archive **down the front axis**: pick a negotiation front, summarize its history *across rounds* — v17 which way its floor moved, v20 how low its floor ever got, v21 how long it was below floor and whether it is still down. None of them reads the archive **down the round axis**: pick a *round*, summarize the whole deal's standing *across fronts*. So from the archive a deal lead can answer "is the Cap front still below floor?" (v21) but not "how many fronts were below floor in round 3, and was that the worst the package ever looked?" Every existing command produces a per-front series; none produces a per-round one. That is a missing **axis** — the transpose of v20/v21. v22 supplies it: read the same N artifacts not per-front-across-rounds but *per-round-across-fronts* — the count of fronts below the acceptable floor in each round (`exposed_fronts`), the deal's **worst round** (the round with the most fronts below floor at once), and whether the package's exposure **broadened** from the first round to the latest (`widened`) — plus one deal-level gate that trips when the latest round has strictly more fronts below floor than the first. It continues the global step numbering after v21's Step 201, beginning at **Step 202**. One new subcommand, one pure module, **zero** change to any existing source file.
> **Scope:** one idea — the *per-round* reduction the whole posture family never took. v17/v18/v19 answer *which way did a front move*; v20 answers *how low did a front ever get*; v21 answers *how long was a front down, and is it still down*; v22 answers *how broad was the deal's exposure each round, and did the package widen or narrow*. It is the transpose of v20/v21 on the same below-floor data: where they reduce each **front** to a number over time, v22 reduces each **round** to a number over fronts. The use case is the same dashboard or audit log that archived every round's kilobyte coherence artifact: v21 says "the Cap front has been below floor three rounds and is still down"; v22 says "and the deal as a whole went from one front below floor to three — the package broadened, and round 3 is its worst."
> **Posture (unchanged, non-negotiable):** deterministic (the breadth is a pure per-round count over the same `below-acceptable` rung v10 defines, taken over the binding floors v12 already derived and v20 already reads; same artifacts → identical `breadth_hash`, on any machine, forever), no AI / no probabilistic path, no server (N local files in, one report out; no socket), citable (the artifacts carry the same per-front binding floors v12 derived from each document's own clause and the team's own playbook — v22 adds no new claim), lints / references / positions — but never drafts, and never renders a legal conclusion. The command is **advisory and verifiable**: every artifact is hash-verified (a tampered round is a hard error, side-labeled by round index), and the ladders are checked for a match across the *whole* sequence (any cross-ladder pair is refused) via the same `verifyCoherenceSequence` loader the five trend/exposure/persistence commands use, unchanged. Every step passes the §3 filter or it does not ship.
> **Cousin docs:** [`spec.md`](spec.md) (v1, the linter), [`spec-v8.md`](spec-v8.md) (Reach — the headless CLI this rides on; `diff`/`compare`/`compare-coherence`/`coherence-trend`/`coherence-shift-trend`/`coherence-arc`/`coherence-exposure`/`coherence-persistence` are its sibling subcommands), [`spec-v10.md`](spec-v10.md) (Negotiation Posture — the **rung ladder** and the `below-acceptable` floor this reads), [`spec-v12.md`](spec-v12.md) (Posture Coherence — the artifact's payload and the **binding floor** `weakest_tier`), [`spec-v14.md`](spec-v14.md) (Saved Coherence Baselines — the artifact this consumes), [`spec-v15.md`](spec-v15.md) (Ladder-Pinned Coherence Baselines — the cross-ladder guard), [`spec-v17.md`](spec-v17.md) (Document-Free Coherence Trajectory — a movement-axis sibling; the shared sequence loader is reused unchanged), [`spec-v20.md`](spec-v20.md) (Document-Free Posture Exposure — the level-axis sibling), [`spec-v21.md`](spec-v21.md) (Document-Free Exposure Persistence — **the time-axis sibling whose per-front view this transposes to a per-round one**). Progress in [`BUILD_PROGRESS.md`](../BUILD_PROGRESS.md).

---

# Part 0 — Intent

## §1. Why we're doing this

v20 gave the posture archive a level axis (the worst floor each front ever reached); v21 gave it a time axis (how long each front was down, and whether it is still down). Both are *per-front* reductions: they fix a front and walk the rounds. That is the right shape for "tell me about the Cap front." But a deal lead at the close has a second, categorically different question: not "tell me about a front" but "tell me about a round" — **how broadly was the whole package below our floor at each step, and did it get broader or tighter as we negotiated?**

No command answers it, because every command v16–v21 reduces the wrong way. To learn that round 3 had three fronts below floor while round 1 had one, a consumer of v20/v21 must read every per-front row, pull out each front's `floors[]` array, and re-tabulate them column-by-column by hand — reconstructing the per-round view the archive never reports. Two deal shapes the per-front commands cannot distinguish at a glance:

- **The widening deal.** Round 1 has one front below floor; by round 3 three fronts are below floor. The package's exposure *broadened* — a worsening trend across the whole negotiation. v20 says "three fronts were ever exposed" (a single end-state count, no trajectory); v21 says "three fronts are open" (likewise). Neither shows the *shape*: one → two → three.
- **The narrowing deal.** Round 1 has three fronts below floor; by round 3 only one is. The team tightened the package. v20 still says "three fronts were ever exposed" (it never forgets the worst); v21 says "one front is open." Neither names that the deal *improved in breadth*.

This is not a bug in v20/v21 — a per-front reduction is *supposed* to fix a front. It is a missing **axis**: the *per-round* dimension of the same below-floor data.

v22 supplies it. Read the same artifacts not per-front but per-round: for each round, how many fronts sat below the acceptable floor (and which), the round where the most fronts were below floor at once (the deal's worst round), and whether the latest round has more fronts below floor than the first (`widened`). The gate follows: `--fail-on-widening-exposure` fires when the package broadened, so a narrowing deal clears it and a widening one trips it. All of this is cheaply derivable from data already in every artifact.

## §2. What v22 is and is not

**It is:**
- A **document-free breadth command.** `coherence-breadth <r1.coherence.json> … <rN.coherence.json>` reads N ≥ 2 saved coherence artifacts in round order, verifies each, runs the cross-ladder guard across all of them, and prints, *per round*, how many fronts had a binding floor of **below-acceptable** (`exposed_fronts`), how many fronts stated a floor at all (`stated_fronts`, the denominator), and which fronts were below floor (`exposed_dimensions`, pinned by `localeCompare`), plus the deal's **worst round** (`worst_round` / `worst_count`) and whether the package's exposure **widened** first→latest. Markdown (default) or `--format json`. No documents are read; the engine is never run.
- A **single deal-level breadth-trend gate.** `--fail-on-widening-exposure` exits 2 when the latest round has strictly more fronts below floor than the first round. This is the *aggregate trend* counterpart to v20's *per-front* level gate and v21's *per-front* current-standing gate: where `--fail-on-exposure` fires on any single front ever below floor and `--fail-on-open-exposure` on any single front still below floor, `--fail-on-widening-exposure` fires on the whole package having broadened. A narrowing deal clears it; a widening one trips it. It needs no tuning — it compares the two endpoint counts.
- A **whole-sequence-verified input, sharing the v17–v21 front end.** Every artifact's `coherence_hash` is re-derived and checked on load (a tampered/corrupt round is a hard error, errors prefixed `round N:`). The v15/v16 cross-ladder guard runs across the sequence via the same `verifyCoherenceSequence` loader the five trend/exposure/persistence commands use, with no change to it.
- A **derived report carrying its own fingerprint.** The breadth carries a `breadth_hash` (a stable SHA-256 over the canonical per-round set), namespaced apart from every `coherence_hash`, `movement_hash`, `trajectory_hash`, `shift_trajectory_hash`, `arc_hash`, `exposure_hash`, and `persistence_hash`, so the same N artifacts in the same order always reproduce the same report.

**It is not:**
- **Not a new diff, classifier, predicate, or artifact format.** It reuses the `weakest_tier` binding floor v12 derives and the `below-acceptable` rung v10 defines; v22 is a subcommand plus one pure module (`computeCoherenceBreadth`) whose only new logic is a per-round count and a first-vs-latest comparison. `parsePostureCoherenceJson`, the coherence schema, and every trajectory/exposure/persistence function are unchanged.
- **Not a per-front command.** It deliberately does *not* fix a front and walk the rounds (v17/v20/v21); it fixes a *round* and walks the fronts. The two reductions are transposes: v21's `floors[]` per front is a row of the same matrix v22 reads in columns. A consumer wanting one front's history reads v20/v21; one wanting one round's standing reads v22.
- **Not a cumulative count.** v20's `exposed_count` is monotone (a front exposed once is exposed forever); v22's per-round `exposed_fronts` rises *and falls* round to round, which is exactly what makes the worst round and the widen/narrow trend visible. v22 never says "ever"; it says "that round."
- **Not a configurable-threshold "too broad" classifier.** v22 does not take a `--fail-over N` knob; the gate fires on whether the deal *widened* (latest > first), the one breadth condition whose meaning ("the package got broader") needs no tuning. A team wanting to gate on an *absolute* count of below-floor fronts reads `worst_count` or `latest_count` from the JSON. (v20 Part XVI made the same call against a configurable floor; v21 against a configurable duration; v22 against a configurable breadth.)
- **Not a replacement for the per-round divergence check or the two-round compare.** `analyze --posture` reads one round's documents and already reports that round's below-floor count; `compare-coherence` diffs the last two rounds; v22 reads the *whole-deal* per-round breadth across N archived rounds, with no documents on any side, and is the only command that names the worst round and the breadth trend.
- **Not a breadth artifact.** v22 introduces no new on-disk format; the breadth is *derived*, recomputed on demand from the N auditable coherence inputs — the same "keep the derived thing derived" discipline v14–v21 hold.
- **Not a sequence the command discovers.** It does not glob a directory or sort filenames; the caller passes the artifacts **in round order** on the argv, exactly as the five trend/exposure/persistence commands do.
- **Not a browser surface.** An N-round breadth of uploaded artifacts is a CI/dashboard concern, which is what this command serves (mirroring v16–v21).

## §3. The posture filter (unchanged)

1. **Deterministic** — `computeCoherenceBreadth` over N `PostureCoherence` objects is pure: it counts each round's fronts whose binding floor is the `below-acceptable` rung and pins the per-round exposed-dimension lists by `localeCompare(_, "en")` — the same order the trajectory/exposure functions use. The round order is the caller's. Identical artifacts in identical order → identical `breadth_hash` on any machine.
2. **Honest about unstated data** — a front no document states in a round is not counted as below floor that round: "not stated" is not a point on the ideal→floor axis, so silence is never a false exposure (the §3 contract that keeps `newly-stated`/`now-unstated` unranked in v11/v13 and `unstated` never-flagged in v20). `stated_fronts` gives the denominator so a reader can see how much of the package was on the table that round; `exposed_fronts` counts only fronts that *stated* a below-floor rung.
3. **Advisory** — the command names how broadly each round of the package sat below the team's own floor and whether the deal widened. It asserts no legal conclusion.
4. **No server** — N local files in, one report out. No socket, no engine run.
5. **Additive** — a brand-new subcommand and one new pure module. Every existing command (`analyze`, `diff`, `compare`, `compare-coherence`, `coherence-trend`, `coherence-shift-trend`, `coherence-arc`, `coherence-exposure`, `coherence-persistence`, `verify`) is byte-for-byte unchanged in *output and goldens*; `coherence-sequence.ts` is imported and reused **without modification** (v22 needs nothing exported that was not already public — like v19/v20/v21, it touches no existing source file's behavior at all).

---

# Part I — The breadth (pure)

`src/report/coherence-breadth.ts` (a new sibling to `coherence-persistence.ts`):

- **`CoherenceBreadthRound`** — one round's deal-wide standing: the 1-based `round` index, `exposed_fronts` (count of fronts with a `below-acceptable` binding floor that round), `stated_fronts` (count of fronts with any stated floor — the denominator), and `exposed_dimensions` (the below-floor fronts, pinned by `localeCompare`).
- **`CoherenceBreadth`** — the whole-sequence per-round series: `rounds` (count), `per_round[]` (the rounds above, in sequence order), `worst_round` / `worst_count` (the 1-based round with the most fronts below floor — earliest on a tie — and that count; `null`/`0` when no front was ever below floor), `first_count` / `latest_count` (the first and latest rounds' exposed-front counts), `widened` (`latest_count > first_count`), and `breadth_hash`.
- **`computeCoherenceBreadth(rounds: PostureCoherence[])`** — the pure, IO-free core. For each round, counts the fronts whose `weakest_tier` is `below-acceptable` (ignoring unstated fronts, §3), pins the exposed-dimension list by `localeCompare`, finds the worst round (earliest peak), compares first vs latest, and returns the series with a `breadth_hash`. Requires ≥ 2 rounds.
- **`exposureWidened(breadth)`** — the CI gate predicate: `breadth.widened`. The aggregate-trend verdict no per-front command exposes (v20/v21 gate on a single front; this gates on the whole package's breadth).
- **`buildCoherenceBreadthJson(breadth)`** / **`renderCoherenceBreadthSummary(breadth)`** — the JSON (`schema: vaulytica.posture-breadth.v1`) and human-readable renderers. The summary prints the widen/narrow/hold trend and the worst round, then one line per round (its below-floor count, the stated denominator, and the named fronts), then the hash.

v22 imports only the already-public `PostureCoherence` type and the shared hashing helpers; the `below-acceptable` literal is a plain string; no existing source file changes.

# Part II — The command (headless)

`tools/cli/coherence-breadth.ts` (a new sibling to `coherence-persistence.ts`):

- **`computeCoherenceBreadthArtifacts(texts, format?)`** — the pure CLI core. Verifies all N artifacts and runs the cross-ladder guard via the shared `verifyCoherenceSequence` loader (unchanged from v18–v21); on any malformed/tampered round returns `{ ok: false, errors }` (each prefixed `round N:`); on a cross-ladder pair returns `{ ok: false }` naming the two rounds; an unpinned artifact yields `{ ok: true }` with a `ladderNote`. Then `computeCoherenceBreadth(rounds)` and renders (markdown summary or JSON), returning `{ ok: true, output, widened, ladderNote }`.
- **`runCoherenceBreadth(argv)`** — the CLI handler: reads the N files, calls the core, writes the `ladderNote` (if any) to stderr, prints the breadth to stdout, and — under `--fail-on-widening-exposure` — exits 2 when the package widened. A malformed/tampered/cross-ladder input is a hard exit-1 error. Requires ≥ 2 positionals.

`tools/cli/run.ts` (the dispatcher) gains a `coherence-breadth` case and a `USAGE` entry.

```
# Each round, archive its coherence (kilobytes, no clause text):
vaulytica analyze 'round1/*.docx' --playbook-file team.playbook.json --posture --emit-coherence round1.coherence.json
vaulytica analyze 'round2/*.docx' --playbook-file team.playbook.json --posture --emit-coherence round2.coherence.json
vaulytica analyze 'round3/*.docx' --playbook-file team.playbook.json --posture --emit-coherence round3.coherence.json

# Later — read/gate the deal's per-round breadth and whether the package widened, from the archive alone:
vaulytica coherence-breadth round1.coherence.json round2.coherence.json round3.coherence.json \
  --fail-on-widening-exposure
```

---

# Part XV — Build plan

Continuing the global numbering after v21's Step 201. Verification gate for every step: `npm run typecheck && lint && test && build` green; the v7 coverage/parity/property gates, the v8 fuzz + citation gates, the v9 no-wall-clock gate, and the responsiveness e2e stay green.

Status legend: **✅ shipped** · ⬜ proposed.

| # | Step | Output | Tier |
|---|------|--------|------|
| 202 ✅ | `coherence-breadth` per-round below-floor count & breadth trend | `src/report/coherence-breadth.ts` — `CoherenceBreadthRound`, `CoherenceBreadth`, pure `computeCoherenceBreadth` (per-round below-floor count + named fronts + worst round + first-vs-latest `widened`; namespaced `breadth_hash`), `exposureWidened` predicate (= `widened`), JSON + markdown renderers. `tools/cli/coherence-breadth.ts` — `computeCoherenceBreadthArtifacts` (pure, reusing `verifyCoherenceSequence` unchanged) + `runCoherenceBreadth` (file IO + exit codes); dispatcher + `USAGE` wired. Tests: breadth identity disk-vs-in-memory, per-round count + named fronts, worst round (earliest peak on tie), the widening deal (1→2→3 fronts → gate trips) the per-front commands cannot show as a trend, the narrowing deal (gate clears), the flat-but-broad deal (held, not widened), unstated-is-never-counted (§3), no-front-ever-below (worst `null`), determinism, ≥2-artifact requirement, cross-ladder refusal across the sequence (naming the two rounds), unpinned-v1 note, tamper rejection (round-prefixed), gate parity, render + JSON. Every existing command's suite passes unchanged. | Reach |

Total work shipped this spec: **1 build step (202).** Purely additive — a new subcommand and one pure module that reads the binding floor already in every artifact; **no existing source file's behavior changes** (v22 needs nothing newly exported), and every existing command's output and golden is unchanged.

---

# Part XVI — Principled deferrals

- **A `coherence-persistence --breadth` flag.** ⬜ Not built — and deliberately not, mirroring v18/v19/v20/v21 Part XVI. v22 is a separate command, not a flag on a per-front command, so each command keeps exactly one gate and one hash.
- **A configurable "too broad" gate (`--fail-over N` fronts below floor).** ⬜ Not built. The gate fires on whether the deal *widened* (latest > first), the one breadth condition whose meaning needs no tuning. `worst_count` / `latest_count` are in the JSON for a consumer that wants to threshold on an absolute count.
- **A standalone breadth artifact (`--emit-breadth`).** ⬜ Deferred, for the same reason v14–v21 keep the derived thing derived: the breadth is cheaply recomputable from the N coherence artifacts on demand, keeping the auditable inputs (each ladder-pinned, hash-verified) as the source of truth.
- **A per-round *severity-weighted* breadth (e.g. counting `acceptable` fronts at a fraction).** ⬜ Not built. v22 counts only the `below-acceptable` rung — the one floor the team will not accept. A weighted index has no consumer yet and would re-introduce the tuning §3 avoids.
- **A directory/glob walker that infers round order.** ⬜ Not built. The command takes artifacts in round order on the argv (the caller's contract, mirroring the trend/exposure/persistence commands).
- **A browser surface for an N-round breadth.** ⬜ Deferred (v16–v21 Part XVI). The browser does an in-session two-round comparison; an N-artifact breadth is a CI/dashboard concern.

---

# Part XVII — Open questions for the maintainer

1. **Fold breadth into a single "deal posture" command that reports per-front *and* per-round?** Today the per-front commands (v20/v21) and the per-round command (v22) are split. A dashboard wanting both runs both and joins on the shared `floors[]` matrix. Recommendation: **keep them split at the command layer** — they carry categorically different gates (per-front "ever/still below" vs deal-level "widened") and different hashes; bolting one onto the other would give that command two unlike gates. If a dashboard asks for the combined matrix view, add a consumer the same way v19 joined v17 and v18 — as its own composing command, not a flag.
2. **Report a *longest contiguous widening run* (breadth rose for K rounds straight)?** The breadth reports each round's count and the first-vs-latest trend; it does not name the longest monotone-rising stretch. Recommendation: **defer** — the per-round series already lets a consumer compute it, and a single "longest run" headline has no consumer yet; add it if a dashboard asks to pin one.

---

# Part XVIII — What this gives the user

- **The deal's per-round standing, from the archive alone.** Archive each round's kilobyte coherence artifact as you go; `coherence-breadth` shows, per round, how many fronts sat below the floor (and which), the worst round, and whether the package broadened — across the entire negotiation, with no clause text checked out and no re-analysis run. The "how exposed was the whole deal at each step, and is it getting broader" question a deal lead asks at the close, answered deterministically from N small, verifiable files.
- **A gate on the package's trend, not just a single front.** `--fail-on-widening-exposure` fires when the deal ends with more fronts below floor than it started — the aggregate breadth regression the per-front gates (v20/v21) structurally cannot pose, since each fixes a single front. It rewards a team that *narrowed* the package even while individual fronts remain open.
- **The same five promises.** Deterministic, no AI, no server, citable, never drafts — every line of v22 passes the §3 gate. It reads the binding floor v12 already derives and the `below-acceptable` rung v10 already defines, through the loader v18–v21 already share; it adds one per-round count and one endpoint comparison, no on-disk format, and no change to any existing source file's behavior — every existing surface is byte-for-byte unchanged.
