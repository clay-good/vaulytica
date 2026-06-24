# Vaulytica v44 — Document-Free Exposure Matrix (The Per-Front × Per-Round Floor-State Grid Every Other Axis Collapses)

> **Status:** **Shipped (9.41.0).** Every `coherence-*` reading from v16 to v43 takes the same N-round posture archive and _reduces_ it to a scalar: v22 collapses each round to a below-floor count, v24 each front to a crossing count, v28/v40 to a latency or a mean, v35/v42 to an edge set and its transitive closure. Each is a lens — and each throws the rest of the grid away. None of them emits the grid _itself_: the full two-dimensional object whose cell `(front, round)` is that front's binding-floor standing in that round — below the acceptable floor, at-or-above it, or unstated. v44 is that grid — a posture **heatmap** a dashboard can render and a spreadsheet can pivot, the raw substrate behind every scalar the family computes. It is gated on the one whole-grid condition the shape makes natural and no reduction can pose: does any round **black out** — a column in which _every_ stated front sits below the floor at once, the deal's worst possible cross-section, the moment no front held the line (`--fail-on-blackout-round`)? It continues the global step numbering after v43's Step 223, beginning at **Step 224**. One new subcommand, one pure module, **zero** change to any existing source file.
> **Scope:** one idea — the un-reduced _shape_ the whole family is implicitly a function of. It is not a new crossing, ordering, magnitude, pairwise, or transitive read; it reads the same `weakest_tier` binding floor v22/v24 already read off each round, and lays it out as a grid rather than summing it. This is a missing **shape**, not a missing reduction: every prior axis is O(fronts) or O(rounds) scalars; the matrix is the O(fronts × rounds) object they all collapse. The use case is the heatmap: v22 says "round 3 had two fronts below floor"; v24 says "the Cap front crossed the floor twice"; v44 says "here is the whole grid — Cap was above, below, below, above; Term was ideal, below, above, below; and **round 3 blacked out**, every stated front below at once." Where every sibling answers one question about one axis, the matrix hands back the substrate from which all of those questions are answered.
> **Posture (unchanged, non-negotiable):** deterministic (every cell is one of three fixed string symbols read straight off `weakest_tier`; rows are pinned by `localeCompare`, columns keep the caller's round order; the per-round summaries, the cell tally, and the blackout list are all integer functions of the cells; no float, no count, enters the fingerprint, so the same artifacts → identical `matrix_hash`, on any machine, forever), no AI / no probabilistic path, no server (N local files in, one report out; no socket), citable (the cells carry the same per-front binding floors v12 derived from each document's own clause and the team's own playbook — v44 adds no new claim), lints / references / positions — but never drafts, and never renders a legal conclusion. The command is **advisory and verifiable**: every artifact is hash-verified (a tampered round is a hard error, side-labeled by round index), and the ladders are checked for a match across the _whole_ sequence (any cross-ladder pair is refused) via the same `verifyCoherenceSequence` loader the twenty-seven trend/exposure/…/recovery-chain commands use, unchanged. Every step passes the §3 filter or it does not ship.
> **Cousin docs:** [`spec.md`](spec.md) (v1, the linter), [`spec-v8.md`](spec-v8.md) (Reach — the headless CLI this rides on), [`spec-v10.md`](spec-v10.md) (Negotiation Posture — the **rung ladder** and the `below-acceptable` floor), [`spec-v12.md`](spec-v12.md) (Posture Coherence — the artifact's payload and the **binding floor** `weakest_tier`), [`spec-v14.md`](spec-v14.md) (Saved Coherence Baselines — the artifact this consumes), [`spec-v15.md`](spec-v15.md) (Ladder-Pinned Coherence Baselines — the cross-ladder guard), [`spec-v22.md`](spec-v22.md) (Document-Free Exposure Breadth — **the per-round count v44 generalizes; v22 collapses each column to a count, v44 keeps the cells**), [`spec-v24.md`](spec-v24.md) (Document-Free Exposure Volatility — **the per-front count; v24 collapses each row, v44 keeps the cells**). Progress in [`BUILD_PROGRESS.md`](../BUILD_PROGRESS.md).

---

# Part 0 — Intent

## §1. Why we're doing this

Every spec from v42 forward closed with the same Open Question: the per-front, pairwise, and now both transitive reads are complete on the structure the binary floor admits; the one genuinely-new direction left is the **2-D one** — a per-front × per-round read, a different _shape_ of output, not another reduction of the same edges. v44 is that read.

The whole `coherence-*` family is a tower of reductions over one underlying object: the grid whose cell `(front, round)` is that front's binding-floor standing in that round. Nobody ever emits that object — every command hands back a summary of it:

- **The collapse down columns.** v22 (breadth) walks each round and reports a _count_: how many fronts were below floor that round. It is exactly the column of the grid, summed to a scalar. The deal lead who wants the heatmap — _which_ fronts, in _which_ rounds, with the above and unstated cells visible too — gets a sequence of counts, not the grid the counts come from.
- **The collapse down rows.** v24 (volatility) walks each front and reports a _count_: how many times it crossed the floor. It is exactly the row of the grid, summed to a scalar. The same loss in the other direction.

Both throw the grid away. A dashboard that wants to render the deal's exposure as a heatmap, a spreadsheet that wants to pivot it, an auditor who wants the substrate behind a v22 count or a v35 edge — all of them want the cells, and no command produces them. v44 supplies the cells and the one verdict whose meaning needs no tuning: per front, its `cells[]` (the raw row, `below` / `above` / `unstated`); per round, its `below_fronts` / `stated_fronts` and whether it is a **blackout** (every stated front below at once); plus the whole-grid `cell_counts`, the `blackout_rounds` list, and `has_blackout` (the gate). All of it is one read of the same `weakest_tier` binding floor the family already reads — no new crossing, no new ordering, no new on-disk format.

## §2. What v44 is and is not

**It is:**

- A **document-free exposure-matrix command.** `coherence-matrix <r1.coherence.json> … <rN.coherence.json>` reads N ≥ 2 saved coherence artifacts in round order, verifies each, runs the cross-ladder guard across all of them, and prints the **grid**: one row per **front** (its `dimension` and its per-round `cells`), plus the per-round column summaries (`below_fronts`, `stated_fronts`, `blackout`), the whole-grid `cell_counts`, the `blackout_rounds` list, and `has_blackout` (the gate verdict). The markdown render is a terminal **heatmap** (`▓` below floor, `░` at-or-above, `·` unstated, `*` marking each blackout column); `--format json` emits the cells for a consumer. No documents are read; the engine is never run.
- A **single deal-level gate, on a whole-grid pathology.** `--fail-on-blackout-round` exits 2 when any round is a blackout — at least one front stated and _every_ stated front below the floor at once. "Every stated front" is a structural all-quantifier, not a threshold knob; the gate inherits none. It is the whole-grid verdict no per-front or per-round _reduction_ poses: v22 reports the worst round's count but never gates on it reaching full width.
- A **whole-sequence-verified input, sharing the v17–v43 front end.** Every artifact's `coherence_hash` is re-derived and checked on load (a tampered/corrupt round is a hard error, errors prefixed `round N:`). The v15/v16 cross-ladder guard runs across the sequence via the same `verifyCoherenceSequence` loader the twenty-seven trend/exposure/…/recovery-chain commands use, with no change to it.
- A **derived report carrying its own fingerprint.** The report carries a `matrix_hash` (a stable SHA-256 over the canonical grid — each front's `dimension` and its `cells`; the per-round summaries, the cell tally, and the blackout list, all fully determined by the cells, are omitted, so the fingerprint is string-exact over the inputs), namespaced apart from every prior hash (`coherence_hash`, …, `recovery_chain_hash`), so the same N artifacts in the same order always reproduce the same report.

**It is not:**

- **Not a new diff, classifier, crossing, or artifact format.** It reads the same `weakest_tier` binding floor `bundlePostureCoherence` already produces — no new fall, recovery, crossing, ordering, or magnitude math. v44 is a subcommand plus one pure module (`computeCoherenceMatrix`) whose only logic is the cell mapping and the per-round/whole-grid tally. `parsePostureCoherenceJson`, the coherence schema, and every other function are unchanged.
- **Not the breadth command (v22).** v22 collapses each round (column) to a below-floor _count_ and gates on `widened` — a _trend_ between two endpoint counts (did the latest round have strictly more fronts below floor than the first). v44 keeps the cells and gates on `blackout` — a single column reaching _full_ width. The two are independent: a deal can black out in round 1 and recover (not widened, but blacked out), and a deal can widen from one to three of five fronts (widened, but never a full column). v22 keeps only the below-floor list per round; v44 keeps the above and unstated cells and the per-front rows v22 discards.
- **Not the volatility command (v24).** v24 collapses each front (row) to a crossing _count_; v44 keeps the row. v24 cannot show the round-by-round standing or the deal-wide cross-section; v44 is the grid both v22 and v24 are reductions of.
- **Not a reduction at all.** Every other `coherence-*` command returns O(fronts) or O(rounds) scalars; v44 returns the O(fronts × rounds) grid. The per-round summaries and cell tally ride along for convenience, but the novel artifact is the cells — the shape, not a new scalar over it.
- **Not depth-weighted.** The floor is binary (`below-acceptable` is the only sub-floor rung), so `ideal` and `acceptable` are one `above` cell; v44 weights nothing — each cell is a three-valued read of the same floor every sibling reads.
- **Not a matrix artifact.** v44 introduces no new on-disk format; the report is _derived_, recomputed on demand from the N auditable coherence inputs.
- **Not a sequence the command discovers.** It takes the artifacts **in round order** on the argv, exactly as the twenty-seven trend/exposure/… commands do.
- **Not a browser surface.** An N-round grid export of uploaded artifacts is a CI/dashboard concern (mirroring v16–v43).

## §3. The posture filter (unchanged)

1. **Deterministic** — `computeCoherenceMatrix` over N `PostureCoherence` objects is pure: it pins the fronts (rows) by `localeCompare(_, "en")` (the order every sibling pins fronts), keeps the caller's round order for the columns, maps each `weakest_tier` to one of three fixed cell symbols (`null` → `unstated`, `below-acceptable` → `below`, any other stated rung → `above`), and derives the per-round summaries, the cell tally, and the blackout list as plain integer functions of the cells. No float enters the verdict. Identical artifacts in identical order → identical `matrix_hash` on any machine.
2. **Honest about unstated data** — a front no document states in a round is `unstated` that round, never `below` (the §3 contract that keeps `unstated` never-flagged in v20/v22): silence is not a point on the ideal→floor axis. A round in which _no_ front is even stated is never a blackout — a blackout needs at least one stated front, all of them below. The denominator each round is `stated_fronts`, never the front count.
3. **Advisory** — the grid names where each front stood across the team's own floor in each round. It asserts no legal conclusion.
4. **No server** — N local files in, one report out. No socket, no engine run.
5. **Additive** — a brand-new subcommand and one new pure module. Every existing command (`analyze`, `diff`, `compare`, `compare-coherence`, `coherence-trend`, …, `coherence-recovery-chain`, `verify`) is byte-for-byte unchanged in _output and goldens_; `coherence-sequence.ts` is imported and reused **without modification** (v44 needs nothing exported that was not already public — like v19–v43, it touches no existing source file's behavior at all).

---

# Part I — The report (pure)

`src/report/coherence-matrix.ts` (a new sibling to `coherence-breadth.ts` and `coherence-volatility.ts`):

- **`MatrixCell`** — one front's standing in one round, the value of a single grid cell: `below` (the binding floor was `below-acceptable`), `above` (stated, at-or-above the floor — `ideal` or `acceptable`, one cell since the floor is binary), `unstated` (no document stated the front that round — `unevaluable`, unranked, §3).
- **`CoherenceMatrixFront`** — one front's heatmap row: the `dimension`, its per-round `cells[]` (the raw grid row), `below_rounds` (a derived row tally), and `stated_rounds` (`below` + `above`).
- **`CoherenceMatrixRound`** — one round's column summary: the 1-based `round`, `below_fronts`, `stated_fronts`, and `blackout` (at least one front stated and every stated front below floor).
- **`CoherenceMatrix`** — the whole-sequence grid: `rounds` (column count), `fronts[]` (pinned by `dimension` — the rows), `per_round[]` (the column summaries), `cell_counts` (the whole-grid tally by state), `blackout_rounds[]` (the 1-based blacked-out rounds), `has_blackout` (the gate verdict), and `matrix_hash`.
- **`computeCoherenceMatrix(rounds: PostureCoherence[])`** — the pure, IO-free core. Pins the fronts, maps each `weakest_tier` to a cell, builds the per-front rows and per-round column summaries, tallies the grid, lists the blackout rounds, and returns the grid with a `matrix_hash`. Requires ≥ 2 rounds (the matrix is the whole-deal grid; one round is one column, exactly what `analyze --posture` already reports).
- **`exposureBlackout(matrix)`** — the CI gate predicate: `matrix.has_blackout`. The whole-grid verdict the shape makes natural and no reduction poses.
- **`buildCoherenceMatrixJson(matrix)`** / **`renderCoherenceMatrixSummary(matrix)`** — the JSON (`schema: vaulytica.posture-matrix.v1`) and human-readable renderers. The summary prints a legend, the blackout verdict (which rounds, or none), then the **heatmap** — a header row of round labels, a marker row flagging blackout columns with `*`, and one glyph-row per front (`▓`/`░`/`·`) — then the cell tally and the hash.

v44 imports the shared hashing helpers and the `PostureCoherence` type; no existing source file changes.

---

# Part II — The command (headless)

`tools/cli/coherence-matrix.ts` (a new sibling to `coherence-recovery-chain.ts`):

- **`computeCoherenceMatrixArtifacts(texts, format?)`** — the pure CLI core. Verifies all N artifacts and runs the cross-ladder guard via the shared `verifyCoherenceSequence` loader (unchanged from v18–v43); on any malformed/tampered round returns `{ ok: false, errors }` (each prefixed `round N:`); on a cross-ladder pair returns `{ ok: false }` naming the two rounds; an unpinned artifact yields `{ ok: true }` with a `ladderNote`. Then `computeCoherenceMatrix(rounds)` and renders (markdown heatmap or JSON), returning `{ ok: true, output, blackout, ladderNote }`.
- **`runCoherenceMatrix(argv)`** — the CLI handler: reads the N files, calls the core, writes the `ladderNote` (if any) to stderr, prints the report to stdout, and — under `--fail-on-blackout-round` — exits 2 when any round blacked out. A malformed/tampered/cross-ladder input is a hard exit-1 error. Requires ≥ 2 positionals.

`tools/cli/run.ts` (the dispatcher) gains a `coherence-matrix` case and a `USAGE` entry.

```
# Each round, archive its coherence (kilobytes, no clause text):
vaulytica analyze 'round1/*.docx' --playbook-file team.playbook.json --posture --emit-coherence round1.coherence.json
vaulytica analyze 'round2/*.docx' --playbook-file team.playbook.json --posture --emit-coherence round2.coherence.json
vaulytica analyze 'round3/*.docx' --playbook-file team.playbook.json --posture --emit-coherence round3.coherence.json

# Later — render the deal's exposure heatmap, or catch a blackout round (every stated front below floor at once), from the archive alone:
vaulytica coherence-matrix round1.coherence.json round2.coherence.json round3.coherence.json \
  --fail-on-blackout-round
```

---

# Part XV — Build plan

Continuing the global numbering after v43's Step 223. Verification gate for every step: `npm run typecheck && lint && test && build` green; the v7 coverage/parity/property gates, the v8 fuzz + citation gates, the v9 no-wall-clock gate, and the responsiveness e2e stay green.

Status legend: **✅ shipped** · ⬜ proposed.

| #      | Step                                                 | Output                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | Tier  |
| ------ | ---------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----- |
| 224 ✅ | `coherence-matrix` per-front × per-round grid & gate | `src/report/coherence-matrix.ts` — `MatrixCell`, `CoherenceMatrixFront`, `CoherenceMatrixRound`, `CoherenceMatrix`, pure `computeCoherenceMatrix` (maps each `weakest_tier` to a `below`/`above`/`unstated` cell, builds the `localeCompare`-pinned per-front rows and per-round column summaries, tallies the grid, lists the blackout rounds; namespaced string-exact `matrix_hash` over the cells alone), `exposureBlackout` predicate (= `has_blackout`), JSON + markdown heatmap renderers. `tools/cli/coherence-matrix.ts` — `computeCoherenceMatrixArtifacts` (pure, reusing `verifyCoherenceSequence` unchanged) + `runCoherenceMatrix` (file IO + exit codes); dispatcher + `USAGE` wired. Tests: the raw grid (rows pinned, cells correct), the binary `ideal`/`acceptable` → `above` mapping, the unstated cell (§3), the no-stated-front round (never a blackout), the clear gate (one front holds the line), both v22 distinctness cases (blackout-not-widened, widened-not-blackout), the v22 `below_fronts` invariant, the whole-grid tally invariant, determinism, ≥2-round requirement, cross-ladder refusal across the sequence (naming the two rounds), unpinned-v1 note, tamper rejection (round-prefixed), gate parity, render + JSON. Every existing command's suite passes unchanged. | Reach |

Total work shipped this spec: **1 build step (224).** Purely additive — a new subcommand and one pure module that reads the same binding floor v22/v24 already read; **no existing source file's behavior changes** (v44 needs nothing newly exported), and every existing command's output and golden is unchanged.

---

# Part XVI — Principled deferrals

- **A per-cell depth scale (area-under-floor).** ⬜ Not built. The floor is binary (`below-acceptable` is the only sub-floor rung), so a cell has no depth to weight — `below`/`above`/`unstated` is the exact resolution. The grid is the finest read the floor admits.
- **A configurable blackout bar (`--min-below-fronts K` per round).** ⬜ Not built. The gate fires on a _full_ column — a structural all-quantifier, tuning-free. A consumer wanting a partial-column bar reads `per_round[].below_fronts`/`stated_fronts` from the JSON (the same counts v22 gates a trend on).
- **A blackout-mirror gate (a round where every stated front is _above_ floor — a "clear" column).** ⬜ Deferred. A fully-clear round is the good-news cross-section, not a warning; the family gates on exposure, and a clear column is already legible in the heatmap. The cells are in the JSON for a consumer that wants to flag it.
- **A standalone matrix artifact (`--emit-matrix`) or a CSV/heatmap-image export.** ⬜ Deferred, for the same reason v14–v43 keep the derived thing derived: the report is cheaply recomputable from the N coherence artifacts on demand, and the JSON cells are a pivot away from any spreadsheet or plot.
- **A browser surface for an N-round heatmap.** ⬜ Deferred (v16–v43 Part XVI). The browser does an in-session two-round comparison; an N-artifact grid export is a CI/dashboard concern.

---

# Part XVII — Open questions for the maintainer

1. **Is the matrix the natural terminus of the family?** Every prior axis is a reduction of this grid; v44 emits the grid itself, the one genuinely-different _shape_ the binary floor admits. Recommendation: **treat the document-free posture family as feature-complete on shape** — per-front, per-round, pairwise, transitive (both directions), and now the un-reduced 2-D substrate are all present. Further work is corpus/attorney calibration (the human-gated v5 thrust), not another reduction.
2. **Should the gate read the blackout or the partial column?** Today `--fail-on-blackout-round` reads the structural extreme (a full column); a consumer wanting to flag a near-blackout reads `per_round[].below_fronts`/`stated_fronts`. Recommendation: **keep the gate on the full column** — it is the uniquely-2-D condition (a whole stated cross-section below floor, which no per-front read sees) and tuning-free, where any partial-column bar would need a knob v22's trend gate already approximates.

---

# Part XVIII — What this gives the user

- **The deal's exposure heatmap, rendered from the archive alone.** Archive each round's kilobyte coherence artifact as you go; `coherence-matrix` lays out the whole grid — every front's standing in every round, the above and unstated cells visible alongside the below ones — with no clause text checked out and no re-analysis run. v22 hands back a sequence of counts and v24 a per-front tally; only the matrix hands back the substrate from which both, and every other scalar the family computes, are derived.
- **A gate on a blackout no per-round or per-front reduction names.** `--fail-on-blackout-round` fires only when a whole stated cross-section sits below floor at once — the deal's worst moment, when no front held the line. v22 reports the worst round's _count_ but never gates on it reaching full width; the blackout is the all-quantifier over a column that the trend gate and the per-front gates structurally cannot pose.
- **The shape the whole family is a function of.** Deterministic, no AI, no server, citable, never drafts — every line of v44 passes the §3 gate. It reads the same binding floor v22/v24 already read, through the loader v18–v43 already share; it adds one cell mapping and one tally over those floors, no on-disk format, and no change to any existing source file's behavior — every existing surface is byte-for-byte unchanged.
