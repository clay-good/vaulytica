# Vaulytica v40 — Document-Free Exposure Duration (How Long a Front *Typically* Stays Below, Not Its Single Worst Spell — the Central Tendency of v28's Recovery Episodes)

> **Status:** **Shipped (9.37.0).** v28 gave the posture archive its **recovery-latency** axis: it pairs each *fall* below the acceptable floor with the *recovery* that closes it, then reads two reductions — the deal's **slowest** single recovery (`max_latency`, an extreme) and whether any fall went **unrecovered** (`open_count`, the gate). Both throw away the read a deal lead asks reviewing a close: not the single worst spell, but the **typical** one — *when this front falls below the floor, how long does it usually take to come back?* A front that recovers in one round three times and once takes five has the deal's slowest single recovery, yet it almost always recovers at once; a front that takes four rounds every single time has a shorter worst spell, yet it is the one that *chronically* lingers. The `max_latency` extreme calls the first worse; the **mean** calls the second worse — and the mean is the one that names the front a counterparty keeps parked below the floor. v40 is the **central-tendency magnitude of v28's episodes**: per front, the mean rounds its binding floor sat below the acceptable floor across its *recovered* exposures (`mean_duration`), gated on the one tuning-free condition — a front whose recovered exposures average **at least two rounds** (`--fail-on-lingering-exposure`): it typically does not recover the very next round. It continues the global step numbering after v39's Step 219, beginning at **Step 220**. One new subcommand, one pure module, **zero** change to any existing source file.
> **Scope:** one idea — the *typical length* of an exposure, where v28 reads its *extreme*. It is not a new crossing, ordering, rate, or pairwise read; it reuses `computeCoherenceLatency` **unchanged** (the join pattern v38 used for v36+v37) and averages the per-front episode lengths v28 already computes. The use case is the chronic lingerer: v28 says "the slowest single recovery was Cap, five rounds below floor"; v40 says "but **Term** averages four rounds below *every time it falls* — Cap's five was one bad spell among quick ones." Where v28 names the *worst case* and the *unrecovered* fall, v40 names the *typical case* — orthogonal to both, and a rank-swap away from the extreme.
> **Posture (unchanged, non-negotiable):** deterministic (the duration verdict is a pure reduction over the episodes v28 derives — the longest-mean pick decided by *integer cross-multiplication* (`total_rounds × closed_episodes`), the gate an integer comparison (`total_rounds ≥ 2 × closed_episodes`); no float threshold enters the verdict, so the same artifacts → identical `duration_hash`, on any machine, forever), no AI / no probabilistic path, no server (N local files in, one report out; no socket), citable (the artifacts carry the same per-front binding floors v12 derived from each document's own clause and the team's own playbook — v40 adds no new claim), lints / references / positions — but never drafts, and never renders a legal conclusion. The command is **advisory and verifiable**: every artifact is hash-verified (a tampered round is a hard error, side-labeled by round index), and the ladders are checked for a match across the _whole_ sequence (any cross-ladder pair is refused) via the same `verifyCoherenceSequence` loader the twenty-three trend/exposure/…/cadence commands use, unchanged. Every step passes the §3 filter or it does not ship.
> **Cousin docs:** [`spec.md`](spec.md) (v1, the linter), [`spec-v8.md`](spec-v8.md) (Reach — the headless CLI this rides on), [`spec-v10.md`](spec-v10.md) (Negotiation Posture — the **rung ladder** and the `below-acceptable` floor), [`spec-v12.md`](spec-v12.md) (Posture Coherence — the artifact's payload and the **binding floor** `weakest_tier`), [`spec-v14.md`](spec-v14.md) (Saved Coherence Baselines — the artifact this consumes), [`spec-v15.md`](spec-v15.md) (Ladder-Pinned Coherence Baselines — the cross-ladder guard), [`spec-v28.md`](spec-v28.md) (Document-Free Exposure Recovery Latency — **the episodes this averages; v40 reads the central tendency where v28 reads the extreme**), [`spec-v39.md`](spec-v39.md) (Document-Free Exposure Cadence — the per-front *churn rate*, the sibling normalization v40's magnitude read complements). Progress in [`BUILD_PROGRESS.md`](../BUILD_PROGRESS.md).

---

# Part 0 — Intent

## §1. Why we're doing this

v39's Open Question #1 named the next axis explicitly: with the per-front *rung* reads complete (level, time, recurrence, count, settling/onset, latency/relapse, dwell, churn rate), the remaining genuinely-new direction is **magnitude** — the mean below-floor duration, a *float* read orthogonal to a count, an index, or a rate. v37, v38, and v39 each deferred it in Part XVI by name ("a magnitude read — mean below-floor duration / mean lead-time, in rounds"). v40 is that magnitude read.

v28 already pairs each fall with its recovery and measures every episode's length. It reduces those lengths two ways, and both are **extremes**:

- **`max_latency`** — the single longest closed episode across the deal. It answers "what was the worst single recovery?" — but one bad spell dominates it. A front that recovers in one round nine times and once takes ten owns the deal's `max_latency` (10), yet it recovers at once 90% of the time.
- **`open_count`** — whether any fall never recovered. It answers "did anything stay broken?" — the gate, but blind to the *length* of the closed episodes entirely.

The missing read is the **mean**: the total recovered rounds normalized by the number of recovered episodes. That is the signal a deal lead reviewing a close actually wants:

- **The chronic lingerer.** Term falls below floor three times and takes four rounds to recover *every* time — a mean of 4. It is the front the counterparty keeps parked below the floor; every concession drags. Its `max_latency` (4) is *smaller* than the front below, yet it is the one that typically lingers.
- **The one bad round (cleared).** Cap falls below floor four times, recovers the next round three times, and once takes five — a `max_latency` of 5 (the deal's slowest single recovery), yet a mean of 2. One spell dragged; the front usually recovers at once. Push the quick recoveries to four (`[1,1,1,1,5]`) and the mean drops to 1.8 — *below* the gate — while the worst spell is unchanged.

To `max_latency` read alone this is invisible — it sees only the longest spell and cannot tell the chronic lingerer (every episode long) from the front with one bad round (one episode long, the rest short). v40 supplies the mean and the one verdict whose meaning needs no tuning: per front, the `latencies` (its recovered episode lengths), `closed_episodes`, `open_episodes`, `total_rounds`, the `mean_duration` (`total_rounds / closed_episodes`), a `class` (`lingering` / `brief` / `open` / `steady` / `unstated`), and the deal's `longest_mean_dimension` / `max_mean` and `lingering` gate. All of it is a reduction over the same episodes v28 already pairs — no new crossing, no new pairing, no new on-disk format.

## §2. What v40 is and is not

**It is:**

- A **document-free exposure-duration command.** `coherence-duration <r1.coherence.json> … <rN.coherence.json>` reads N ≥ 2 saved coherence artifacts in round order, verifies each, runs the cross-ladder guard across all of them, and prints, per **front**, the recovered-episode lengths (`latencies`), the `mean_duration`, the longest single recovery (`max_latency`, carried from v28 for contrast), the count of still-open falls (`open_episodes`), and its `class` — plus the deal's `longest_mean_dimension` (the highest mean), `max_mean`, `total_closed_episodes` (= v28's `recovered_count`), `total_open_episodes` (= v28's `open_count`), `total_rounds`, and `lingering` (the gate verdict). Markdown (default) or `--format json`. No documents are read; the engine is never run.
- A **single deal-level per-front gate, on the typical length.** `--fail-on-lingering-exposure` exits 2 when at least one front's recovered exposures average at least two rounds (`total_rounds ≥ 2 × closed_episodes`) — a front that, when it falls, typically does not recover the very next round. Two rounds is the first integer above the metric's structural minimum (a fall and the immediately following recovery is one round), so the bar inherits no knob.
- A **whole-sequence-verified input, sharing the v17–v39 front end.** Every artifact's `coherence_hash` is re-derived and checked on load (a tampered/corrupt round is a hard error, errors prefixed `round N:`). The v15/v16 cross-ladder guard runs across the sequence via the same `verifyCoherenceSequence` loader the twenty-three trend/exposure/…/cadence commands use, with no change to it.
- A **derived report carrying its own fingerprint.** The report carries a `duration_hash` (a stable SHA-256 over the canonical per-front set — the front, its `floors`, sorted `latencies`, `open_episodes`, and `class`; the derived float `mean_duration`, `max_latency`, `longest_mean_dimension`, `max_mean`, and `lingering` are omitted, so the fingerprint is integer-exact over the inputs), namespaced apart from every prior hash (`coherence_hash`, …, `cadence_hash`), so the same N artifacts in the same order always reproduce the same report.

**It is not:**

- **Not a new diff, classifier, pairing, ordering, or artifact format.** It reuses the episodes `computeCoherenceLatency` already pairs — no new fall, recovery, crossing, or ordering math. v40 is a subcommand plus one pure module (`computeCoherenceDuration`) whose only new logic is averaging the recovered episode lengths. `parsePostureCoherenceJson`, the coherence schema, `coherence-latency.ts`, and every other function are unchanged.
- **Not the latency command (v28).** v28 reads the **extreme** (`max_latency`, the single slowest recovery) and the **unrecovered** gate (`open_count`). v40 reads the **mean** (the typical recovered spell). A front that always recovers but slowly (mean 3, no open fall) trips v40 and clears v28; a front that recovers promptly twice then falls and never returns trips v28 and clears v40. And the headline can swap: a front with episodes `[1, 6]` owns the deal's slowest single recovery (6) yet a mean of 3.5, while a front with `[4, 4]` has a smaller worst spell (4) yet a *larger* mean (4) — v28 names the first, v40 the second.
- **Not the cadence command (v39).** v39 reads the *churn rate* (crossings over transitions — how *often* a front flips). v40 reads the *duration magnitude* (how *long* each recovered exposure lasts). A front that flips every round but recovers each time within a round is `oscillating` to v39 (a 100% rate) but `brief` here (mean 1); a front that crosses twice in a long sequence (one slow fall, one slow recovery) is `settled` to v39 (a low rate) but `lingering` here (a long single spell). Rate and length are independent.
- **Not a depth-weighted score.** The floor is binary (`below-acceptable` is the only sub-floor rung), so a *depth* weighting is not viable; v40 weights by *duration* (rounds below floor), the orthogonal magnitude the binary floor does admit.
- **Not a gate on the worst case.** v40 deliberately gates on the **mean**, not `max_latency`. A consumer wanting to flag a single slow-but-recovered episode reads `max_latency` from the JSON (or runs v28); v40's gate fires only when the *typical* exposure is long.
- **Not an averaging of open episodes.** A fall that never recovered is an *unbounded* duration with no finite length to average; it is counted (`open_episodes`) but excluded from the mean. v28's `--fail-on-unrecovered-exposure` owns the open fall; v40 reads the *recovered* exposures' typical length, so the two gates never overlap.
- **Not a duration artifact.** v40 introduces no new on-disk format; the report is _derived_, recomputed on demand from the N auditable coherence inputs.
- **Not a sequence the command discovers.** It takes the artifacts **in round order** on the argv, exactly as the twenty-three trend/exposure/… commands do.
- **Not a browser surface.** An N-round per-front duration synthesis of uploaded artifacts is a CI/dashboard concern (mirroring v16–v39).

## §3. The posture filter (unchanged)

1. **Deterministic** — `computeCoherenceDuration` over N `PostureCoherence` objects is pure: it delegates the fall-to-recovery pairing to `computeCoherenceLatency` (the `localeCompare`-pinned front order, the silence-skipping scan), splits each front's episodes into the recovered (a finite length) and the open (excluded), sums the recovered lengths, and picks the longest mean by **integer cross-multiplication** (`total_rounds × closed_episodes`, earliest label on a tie), never a float compare. The gate is the integer test `total_rounds ≥ 2 × closed_episodes`. Identical artifacts in identical order → identical `duration_hash` on any machine.
2. **Honest about unstated data** — a front no document states does not fall or recover (the §3 contract v28 already enforces): silence contributes no episode, so a front that never fell in-sequence carries no mean (`steady`), and an unstated front carries none (`unstated`). An *open* episode (a fall that never recovered) is an unbounded duration with no finite length to average, so it is counted (`open_episodes`) but never folded into the mean — v28's gate owns the unrecovered fall; v40 reads the *recovered* exposures' typical length.
3. **Advisory** — the command names how long the team's own floor *typically* stays crossed between a fall and its recovery. It asserts no legal conclusion.
4. **No server** — N local files in, one report out. No socket, no engine run.
5. **Additive** — a brand-new subcommand and one new pure module. Every existing command (`analyze`, `diff`, `compare`, `compare-coherence`, `coherence-trend`, …, `coherence-cadence`, `verify`) is byte-for-byte unchanged in _output and goldens_; `coherence-latency.ts` and `coherence-sequence.ts` are imported and reused **without modification** (v40 needs nothing exported that was not already public — like v19–v39, it touches no existing source file's behavior at all).

---

# Part I — The report (pure)

`src/report/coherence-duration.ts` (a new sibling to `coherence-cadence.ts`):

- **`DurationClass`** — a front's recovered-exposure duration class: `lingering` (≥ 1 recovered episode and `total_rounds ≥ 2 × closed_episodes` — a mean of at least two rounds, the gate-worthy class), `brief` (≥ 1 recovered episode but a mean below two rounds, including a mean of exactly one), `open` (fell in-sequence but no episode recovered — an unbounded duration, v28's gate owns it), `steady` (stated, never fell in-sequence), `unstated` (no document ever stated the front).
- **`CoherenceDurationFront`** — one front's whole-sequence recovered-exposure duration: the `dimension`, the `floors` (binding floor at each round, `null` = unstated), the sorted `latencies` (its recovered episode lengths), `closed_episodes`, `open_episodes`, `total_rounds` (the sum of `latencies`), `mean_duration` (`total_rounds / closed_episodes`, `null` when none recovered), `max_latency` (the longest single recovery — v28's per-front extreme, carried for contrast), and its `class`.
- **`CoherenceDuration`** — the whole-sequence reduction: `rounds` (count), `fronts[]` (pinned by `dimension`), `class_counts` (the per-front tally by class), `total_closed_episodes` (= v28's `recovered_count`), `total_open_episodes` (= v28's `open_count`), `total_rounds` (every recovered episode's length summed), `max_mean` (the highest mean, `null` when none recovered), `longest_mean_dimension` (the front owning it, earliest label on a tie), `lingering` (`≥ 1` lingering front — the gate verdict), and `duration_hash`.
- **`computeCoherenceDuration(rounds: PostureCoherence[])`** — the pure, IO-free core. Delegates the episode pairing to `computeCoherenceLatency`, averages each front's recovered episode lengths, classifies it, selects the longest mean by integer cross-multiplication, and returns the reduction with a `duration_hash`. Requires ≥ 2 rounds (v28 enforces this — a recovery span is a between-round event).
- **`exposureLingers(duration)`** — the CI gate predicate: `duration.lingering`. The read no other command exposes (v28 gates on the unrecovered fall; v39 on the flip rate; neither averages the closed episode lengths).
- **`buildCoherenceDurationJson(duration)`** / **`renderCoherenceDurationSummary(duration)`** — the JSON (`schema: vaulytica.posture-duration.v1`) and human-readable renderers. The summary prints the chronic lingerer (the front and its mean rounds below floor, or none when nothing recovered), the class tally, then one line per front that recovered any episode (`lingering` first), then the hash.

v40 imports `computeCoherenceLatency` and the shared hashing helpers; no existing source file changes.

# Part II — The command (headless)

`tools/cli/coherence-duration.ts` (a new sibling to `coherence-cadence.ts`):

- **`computeCoherenceDurationArtifacts(texts, format?)`** — the pure CLI core. Verifies all N artifacts and runs the cross-ladder guard via the shared `verifyCoherenceSequence` loader (unchanged from v18–v39); on any malformed/tampered round returns `{ ok: false, errors }` (each prefixed `round N:`); on a cross-ladder pair returns `{ ok: false }` naming the two rounds; an unpinned artifact yields `{ ok: true }` with a `ladderNote`. Then `computeCoherenceDuration(rounds)` and renders (markdown summary or JSON), returning `{ ok: true, output, lingering, ladderNote }`.
- **`runCoherenceDuration(argv)`** — the CLI handler: reads the N files, calls the core, writes the `ladderNote` (if any) to stderr, prints the report to stdout, and — under `--fail-on-lingering-exposure` — exits 2 when any front's recovered exposures average at least two rounds. A malformed/tampered/cross-ladder input is a hard exit-1 error. Requires ≥ 2 positionals.

`tools/cli/run.ts` (the dispatcher) gains a `coherence-duration` case and a `USAGE` entry.

```
# Each round, archive its coherence (kilobytes, no clause text):
vaulytica analyze 'round1/*.docx' --playbook-file team.playbook.json --posture --emit-coherence round1.coherence.json
vaulytica analyze 'round2/*.docx' --playbook-file team.playbook.json --posture --emit-coherence round2.coherence.json
vaulytica analyze 'round3/*.docx' --playbook-file team.playbook.json --posture --emit-coherence round3.coherence.json

# Later — name the deal's chronic lingerers (typically slow to recover), from the archive alone:
vaulytica coherence-duration round1.coherence.json round2.coherence.json round3.coherence.json \
  --fail-on-lingering-exposure
```

---

# Part XV — Build plan

Continuing the global numbering after v39's Step 219. Verification gate for every step: `npm run typecheck && lint && test && build` green; the v7 coverage/parity/property gates, the v8 fuzz + citation gates, the v9 no-wall-clock gate, and the responsiveness e2e stay green.

Status legend: **✅ shipped** · ⬜ proposed.

| #      | Step                                              | Output | Tier  |
| ------ | ------------------------------------------------- | ----- | ----- |
| 220 ✅ | `coherence-duration` per-front mean recovered-exposure duration & gate | `src/report/coherence-duration.ts` — `DurationClass`, `CoherenceDurationFront`, `CoherenceDuration`, pure `computeCoherenceDuration` (reuses `computeCoherenceLatency` unchanged, averages each front's recovered episode lengths, classifies `lingering`/`brief`/`open`/`steady`/`unstated`, picks the longest mean by integer cross-multiplication, deal-level `total_closed_episodes` = v28's `recovered_count` + `lingering` gate; namespaced integer-exact `duration_hash`), `exposureLingers` predicate (= `lingering`), JSON + markdown renderers. `tools/cli/coherence-duration.ts` — `computeCoherenceDurationArtifacts` (pure, reusing `verifyCoherenceSequence` unchanged) + `runCoherenceDuration` (file IO + exit codes); dispatcher + `USAGE` wired. Tests: duration identity disk-vs-in-memory, the lingering front vs the brief one, the central-tendency case (a front with one bad round that stays brief — mean below two despite a long worst spell), the v28-rank-swap case (mean vs `max_latency` name different fronts; `total_closed_episodes` = v28's), the open-episode exclusion (counted, not averaged), the open-only front, the steady/unstated fronts, the longest-mean pick by integer ratio (ratio beats label order), tie-break by earliest label, determinism, ≥2-round requirement, cross-ladder refusal across the sequence (naming the two rounds), unpinned-v1 note, tamper rejection (round-prefixed), gate parity, render + JSON. Every existing command's suite passes unchanged. | Reach |

Total work shipped this spec: **1 build step (220).** Purely additive — a new subcommand and one pure module that averages the same episodes v28 already pairs; **no existing source file's behavior changes** (v40 needs nothing newly exported), and every existing command's output and golden is unchanged.

---

# Part XVI — Principled deferrals

- **A direction-resolved magnitude (mean fall depth vs mean recovery climb).** ⬜ Not built. The floor is binary, so a magnitude has only one dimension — duration; a *depth* read needs a graded sub-floor the ladder does not have.
- **A configurable "average at least K rounds" gate (`--min-mean K`).** ⬜ Not built. The gate fires at a mean of two rounds — the first integer above the metric's structural minimum — already tuning-free. The per-front means are in the JSON for a consumer wanting a different bar.
- **A median (or other quantile) instead of the mean.** ⬜ Not built. The mean is the integer-exact reduction (a sum over a count, gated by cross-multiplication); a median needs a sorted-position pick that is not a single integer ratio. The sorted `latencies` are in the JSON for a consumer that wants one.
- **A relapse-interval magnitude (mean *clean* rounds between exposures).** ⬜ Deferred. v30 reads the relapse interval (rounds *above* floor between a recovery and the next fall); its *mean* is the above-floor mirror of v40's below-floor mean — a clean next magnitude axis, orthogonal to this one.
- **A standalone duration artifact (`--emit-duration`).** ⬜ Deferred, for the same reason v14–v39 keep the derived thing derived: the report is cheaply recomputable from the N coherence artifacts on demand.
- **A browser surface for an N-round duration synthesis.** ⬜ Deferred (v16–v39 Part XVI). The browser does an in-session two-round comparison; an N-artifact per-front duration read is a CI/dashboard concern.

---

# Part XVII — Open questions for the maintainer

1. **Is the per-front family now complete, magnitude included?** v20 (level), v21 (time), v23 (recurrence), v24 (count), v26/v27 (settling/onset), v28/v30 (latency/relapse), v31 (dwell), v39 (churn rate), and now v40 (duration magnitude) cover the per-front below-floor reads the binary floor admits — a count, an index, a rate, an extreme, and now a central tendency. Recommendation: **treat the per-front axes as complete.** The remaining genuinely-new reads are the *above-floor* mirror (v30's relapse interval has a mean too — the clean-rounds magnitude) or a *2-D* read (per-front × per-step), not another reduction of the same below-floor episodes.
2. **Should the gate read the mean or the worst case?** Today `--fail-on-lingering-exposure` reads the **mean** (`total_rounds ≥ 2 × closed_episodes`); a consumer wanting to flag a single slow recovery reads `max_latency` or runs v28's gate. Recommendation: **keep the gate on the mean** — the worst-case gate already exists (v28), and the mean is the read no existing gate supplies.

---

# Part XVIII — What this gives the user

- **The deal's chronic lingerers, named from the archive alone.** Archive each round's kilobyte coherence artifact as you go; `coherence-duration` averages each front's recovered below-floor spells — naming the front that, *every time* it falls, takes multiple rounds to recover, the one a counterparty keeps parked below the floor. It distinguishes the *chronic lingerer* (every episode long) from the *one bad round* (one long spell among quick ones, which v28's `max_latency` cannot tell apart) and from the merely *unrecovered* fall (v28's gate), with no clause text checked out and no re-analysis run.
- **A gate on the typical exposure, not the worst one or the open one.** `--fail-on-lingering-exposure` fires only when a front's recovered exposures average at least two rounds — orthogonal to v28's `max_latency` extreme (blind to the typical episode) and `open_count` gate (blind to the closed episodes' length). It catches the front whose every concession drags, which a count, an index, a rate, or an extreme structurally cannot isolate, because none of them averages the recovered episode lengths.
- **The same five promises.** Deterministic, no AI, no server, citable, never drafts — every line of v40 passes the §3 gate. It reuses the episodes v28 already pairs, through the loader v18–v39 already share; it adds one per-front mean over those lengths, no on-disk format, and no change to any existing source file's behavior — every existing surface is byte-for-byte unchanged.
