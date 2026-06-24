# Vaulytica v42 — Document-Free Exposure Lead Chain (Who Leads the Whole Cascade, Not Just One Pair — the Transitive Closure of v35's Lead-Lag Relation)

> **Status:** **Shipped (9.39.0).** v35 gave the posture archive its first **directional** pairwise axis: per *pair* of fronts, does one cross the acceptable floor *before* the other for a strict majority of their comparisons (`leads`)? Its leader is an early-warning indicator for its follower — watch the leader, anticipate the follower. But a deal lead does not watch one pair; they want a single **watch-order**: a front upstream of *everything*, whose movement gives advance notice on a whole cascade. v35 cannot supply it — it reads each pair in isolation and never composes them. v42 is the **transitive closure** of that relation: it builds the directed graph whose edges are exactly v35's strict-majority `leading` pairs (`leader → follower`), computes reachability, and reads the structure no pairwise scan can see — the *chains* (Cap leads Term leads Indemnity, so Cap is a transitive indicator for Indemnity even with no direct edge), the deal's **headwater** (the greatest-reach source, the one front to watch first), and the **cycle** (Cap leads Term leads Indemnity leads Cap — three clean pairwise leads that cannot be globally ranked, a Condorcet cycle no pairwise read can detect). It is gated on the one tuning-free condition: does the relation contain a directed cycle (`--fail-on-lead-cycle`)? It continues the global step numbering after v41's Step 221, beginning at **Step 222**. One new subcommand, one pure module, **zero** change to any existing source file.
> **Scope:** one idea — the *transitive* read of the same lead-lag edges v35 derives pairwise. It is not a new crossing, ordering, magnitude, or pairwise read; it reuses `computeCoherencePrecedence` **unchanged** (the join pattern v38/v40/v41 use) and composes its strict-majority `leading` pairs into a directed graph. The use case is the watch-order: v35 says "Cap leads Term, and Term leads Indemnity"; v42 says "so **Cap** is the headwater — watch it to anticipate the whole chain" — or "your fronts form a **cycle**, so there is *no* single front to watch first." Where v35 names a *pair's* leader, v42 names the deal's *global* ordering — and whether one exists at all.
> **Posture (unchanged, non-negotiable):** deterministic (the chain verdict is a pure reduction over the edges v35 derives — the reachability a plain integer Floyd–Warshall fixpoint, the headwater pick decided by greatest `reach` with the earliest label on a tie, the gate a pure boolean over the integer-derived edges; no float threshold enters the verdict, so the same artifacts → identical `chain_hash`, on any machine, forever), no AI / no probabilistic path, no server (N local files in, one report out; no socket), citable (the artifacts carry the same per-front binding floors v12 derived from each document's own clause and the team's own playbook — v42 adds no new claim), lints / references / positions — but never drafts, and never renders a legal conclusion. The command is **advisory and verifiable**: every artifact is hash-verified (a tampered round is a hard error, side-labeled by round index), and the ladders are checked for a match across the _whole_ sequence (any cross-ladder pair is refused) via the same `verifyCoherenceSequence` loader the twenty-five trend/exposure/…/durability commands use, unchanged. Every step passes the §3 filter or it does not ship.
> **Cousin docs:** [`spec.md`](spec.md) (v1, the linter), [`spec-v8.md`](spec-v8.md) (Reach — the headless CLI this rides on), [`spec-v10.md`](spec-v10.md) (Negotiation Posture — the **rung ladder** and the `below-acceptable` floor), [`spec-v12.md`](spec-v12.md) (Posture Coherence — the artifact's payload and the **binding floor** `weakest_tier`), [`spec-v14.md`](spec-v14.md) (Saved Coherence Baselines — the artifact this consumes), [`spec-v15.md`](spec-v15.md) (Ladder-Pinned Coherence Baselines — the cross-ladder guard), [`spec-v24.md`](spec-v24.md) (Document-Free Exposure Volatility — **the crossing events the lead-lag edges are built from**), [`spec-v35.md`](spec-v35.md) (Document-Free Exposure Precedence — **the pairwise lead-lag relation this composes; v42 reads its transitive closure where v35 reads each pair**). Progress in [`BUILD_PROGRESS.md`](../BUILD_PROGRESS.md).

---

# Part 0 — Intent

## §1. Why we're doing this

v41's Open Question #1 named the next axis explicitly: with the per-front magnitude family complete (both the below-floor and above-floor means the binary floor admits), the remaining genuinely-new reads are a *2-D* one (per-front × per-step matrix) or a **transitive** one (lead-lag chains over the pairwise family). v42 is that transitive read.

v35 already pairs each two fronts and asks which crosses the floor *first* for a strict majority of their comparisons. It reads each pair in isolation, and that isolation hides two facts a deal lead reviewing the close actually wants:

- **The chain.** Cap leads Term, Term leads Indemnity. v35 reports two pairs and *never* the composed fact: Cap is a transitive early-warning indicator for Indemnity — *through* Term — even though Cap and Indemnity may never have crossed in different steps (no direct edge). The deal lead who watches Cap gets advance notice on the entire downstream pipeline; v35 cannot name that Cap is the *headwater*, because it never composes the edges.
- **The cycle.** Cap leads Term, Term leads Indemnity, Indemnity leads Cap — three pairwise leads, each a perfectly consistent strict majority, that **cannot be globally ranked**. There is no first-mover; the lead-lag relation is *intransitive* (a Condorcet cycle, the same intransitive-tournament phenomenon non-transitive dice exhibit). Every pair looks clean to v35; only composing all three reveals the paradox. When this happens, the per-pair early-warning signal v35 sells *does not compose* into a watch-order — there is no single front to watch first, because movement propagates around a loop.

To v35 read alone both are invisible — it sees pairs, never the graph they form. v42 supplies the closure and the one verdict whose meaning needs no tuning: per front, the `leads_directly` (its direct out-neighbours), the transitive `reach` (how many fronts it leads through *any* chain) and `led_by` (how many lead it), whether it sits on a cycle (`in_cycle`), and a `class` (`source` / `relay` / `sink` / `cyclic` / `isolated`); plus the deal's `headwater` (the greatest-reach source), `max_reach`, `edges` (= v35's `leading` tally), `acyclic`, and `cyclic` (the gate). All of it is a reachability fixpoint over the same lead-lag edges v35 already derives — no new crossing, no new ordering, no new on-disk format.

## §2. What v42 is and is not

**It is:**

- A **document-free exposure lead-chain command.** `coherence-chain <r1.coherence.json> … <rN.coherence.json>` reads N ≥ 2 saved coherence artifacts in round order, verifies each, runs the cross-ladder guard across all of them, and prints, per **front**, its direct out-neighbours (`leads_directly`), its transitive `reach` and `led_by`, whether it sits on a cycle (`in_cycle`), and its `class` — plus the deal's `headwater` (the greatest-reach source — a front with nothing upstream), `max_reach`, the `edges` count, `acyclic`, and `cyclic` (the gate verdict). Markdown (default) or `--format json`. No documents are read; the engine is never run.
- A **single deal-level gate, on the global ordering's coherence.** `--fail-on-lead-cycle` exits 2 when the lead-lag relation contains a directed cycle — three or more fronts each crossing the floor first over the next in a loop, so no single watch-order ranks every front. A directed cycle either exists or it does not; the gate is a pure boolean over the integer-derived edges and inherits no knob. It is the *transitive* verdict v35 structurally cannot pose: every pair on the loop is individually `leading` to v35.
- A **whole-sequence-verified input, sharing the v17–v41 front end.** Every artifact's `coherence_hash` is re-derived and checked on load (a tampered/corrupt round is a hard error, errors prefixed `round N:`). The v15/v16 cross-ladder guard runs across the sequence via the same `verifyCoherenceSequence` loader the twenty-five trend/exposure/…/durability commands use, with no change to it.
- A **derived report carrying its own fingerprint.** The report carries a `chain_hash` (a stable SHA-256 over the canonical per-front set — the `dimension`, its sorted `leads_directly`, and its `class`; the derived transitive `reach`/`led_by` integers, fully determined by the edge set, and the deal-level scalars are omitted, so the fingerprint is integer-/string-exact over the inputs), namespaced apart from every prior hash (`coherence_hash`, …, `durability_hash`), so the same N artifacts in the same order always reproduce the same report.

**It is not:**

- **Not a new diff, classifier, crossing, or artifact format.** It reuses the lead-lag edges `computeCoherencePrecedence` already derives — no new fall, recovery, crossing, or ordering math. v42 is a subcommand plus one pure module (`computeCoherenceChain`) whose only new logic is the reachability fixpoint over those edges. `parsePostureCoherenceJson`, the coherence schema, `coherence-precedence.ts`, and every other function are unchanged.
- **Not the precedence command (v35).** v35 reads each **pair** in isolation and gates on the *presence* of a stable lead-lag (`--fail-on-leading-front`). v42 **composes** those pairs into a directed graph and gates on the *incoherence* of the composed ordering (`--fail-on-lead-cycle`). A deal whose every pair is `leading` (v35 fires) can be acyclic (v42 clears — a clean pipeline) or cyclic (v42 fires — an intransitive loop); the two verdicts are independent, one over a pair, one over the whole graph.
- **Not a read over plurality edges.** The graph uses only v35's strict-majority `leading` pairs (the edges v35's own gate fires on), not every non-null `leader`. A razor-thin plurality first-mover is not a stable lead, so it carries no edge; the chain is built from the same stable couplings the family gates on everywhere else.
- **Not a longest-path or simple-path read.** v42 reads transitive *reach* (how many fronts a front leads through any chain) and cycle *existence*, both polynomial and integer-exact. The longest *simple* path is NP-hard on a cyclic graph and would need a float-free tie-break the binary floor does not naturally supply; the reach count is the cascade-breadth read that is exact.
- **Not a depth-weighted score.** The floor is binary (`below-acceptable` is the only sub-floor rung), so a *depth* weighting is not viable; v42 weights nothing — it counts reachable fronts and detects cycles, both pure structure.
- **Not a chain artifact.** v42 introduces no new on-disk format; the report is _derived_, recomputed on demand from the N auditable coherence inputs.
- **Not a sequence the command discovers.** It takes the artifacts **in round order** on the argv, exactly as the twenty-five trend/exposure/… commands do.
- **Not a browser surface.** An N-round transitive lead-lag synthesis of uploaded artifacts is a CI/dashboard concern (mirroring v16–v41).

## §3. The posture filter (unchanged)

1. **Deterministic** — `computeCoherenceChain` over N `PostureCoherence` objects is pure: it delegates the per-pair lead-lag derivation to `computeCoherencePrecedence` (the `localeCompare`-pinned front order, the silence-skipping crossing scan), keeps only its strict-majority `leading` pairs as directed `leader → follower` edges, computes a plain integer reachability fixpoint (Floyd–Warshall, paths of length ≥ 1), and picks the headwater by greatest `reach` with the earliest label on a tie. The gate is the boolean "any front reaches itself." No float enters the verdict. Identical artifacts in identical order → identical `chain_hash` on any machine.
2. **Honest about unstated data** — a front no document states never crosses the floor (the §3 contract v35 already enforces): it has no lead-lag edge, so it is `isolated` (reach 0, led-by 0), counted but carrying no chain. A pair with no consistent first-mover (v35 `interleaved`) is no edge — it joins no chain. Silence is never an edge.
3. **Advisory** — the command names which front the counterparty moves *first* across the team's own floor *through a chain*, and whether that ordering is coherent. It asserts no legal conclusion.
4. **No server** — N local files in, one report out. No socket, no engine run.
5. **Additive** — a brand-new subcommand and one new pure module. Every existing command (`analyze`, `diff`, `compare`, `compare-coherence`, `coherence-trend`, …, `coherence-durability`, `verify`) is byte-for-byte unchanged in _output and goldens_; `coherence-precedence.ts` and `coherence-sequence.ts` are imported and reused **without modification** (v42 needs nothing exported that was not already public — like v19–v41, it touches no existing source file's behavior at all).

---

# Part I — The report (pure)

`src/report/coherence-chain.ts` (a new sibling to `coherence-precedence.ts`):

- **`ChainRole`** — a front's role in the transitive lead-lag graph: `cyclic` (it transitively leads itself — on a directed cycle, the gate-worthy class), `source` (not on a cycle, leads ≥ 1 front and `led_by` 0 — a headwater), `sink` (not on a cycle, led by ≥ 1 and leads none — a terminal follower), `relay` (not on a cycle, both leads and is led), `isolated` (no edge touches it — reach 0 and led-by 0, incl. an unstated front).
- **`CoherenceChainFront`** — one front's place in the graph: the `dimension`, the sorted `leads_directly` (its direct out-neighbours), `reach` (transitive out-reach, excluding self), `led_by` (transitive in-reach, excluding self), `in_cycle` (does it transitively lead itself), and its `class`.
- **`CoherenceChain`** — the whole-sequence reduction: `rounds` (count), `fronts[]` (pinned by `dimension`), `class_counts` (the per-front tally by role), `edges` (the directed lead-lag edge count = v35's `leading` pair count), `max_reach` (the greatest `reach` among source fronts), `headwater` (the source owning it, earliest label on a tie; `null` when no source), `acyclic`, `cyclic` (`≥ 1` front on a cycle — the gate verdict), and `chain_hash`.
- **`computeCoherenceChain(rounds: PostureCoherence[])`** — the pure, IO-free core. Delegates the per-pair lead-lag derivation to `computeCoherencePrecedence`, builds the directed graph from its `leading` edges, computes the reachability fixpoint, classifies each front, selects the headwater by greatest reach, and returns the reduction with a `chain_hash`. Requires ≥ 2 rounds (v35 enforces this — a crossing is a between-round event).
- **`exposureCyclic(chain)`** — the CI gate predicate: `chain.cyclic`. The read no other command exposes (v35 gates on the presence of a stable pair; neither it nor any other command composes the edges to detect a global cycle).
- **`buildCoherenceChainJson(chain)`** / **`renderCoherenceChainSummary(chain)`** — the JSON (`schema: vaulytica.posture-chain.v1`) and human-readable renderers. The summary prints the headwater (the source and its reach, or none when no clean source exists), the ordering verdict (acyclic / intransitive), the role tally, then one line per front that touches the graph (sources first, then relays, cyclic fronts, sinks), then the hash. An `isolated` front is counted but never listed (§3 honesty — it joins no chain).

v42 imports `computeCoherencePrecedence` and the shared hashing helpers; no existing source file changes.

---

# Part II — The command (headless)

`tools/cli/coherence-chain.ts` (a new sibling to `coherence-precedence.ts`):

- **`computeCoherenceChainArtifacts(texts, format?)`** — the pure CLI core. Verifies all N artifacts and runs the cross-ladder guard via the shared `verifyCoherenceSequence` loader (unchanged from v18–v41); on any malformed/tampered round returns `{ ok: false, errors }` (each prefixed `round N:`); on a cross-ladder pair returns `{ ok: false }` naming the two rounds; an unpinned artifact yields `{ ok: true }` with a `ladderNote`. Then `computeCoherenceChain(rounds)` and renders (markdown summary or JSON), returning `{ ok: true, output, cyclic, ladderNote }`.
- **`runCoherenceChain(argv)`** — the CLI handler: reads the N files, calls the core, writes the `ladderNote` (if any) to stderr, prints the report to stdout, and — under `--fail-on-lead-cycle` — exits 2 when the lead-lag relation contains a directed cycle. A malformed/tampered/cross-ladder input is a hard exit-1 error. Requires ≥ 2 positionals.

`tools/cli/run.ts` (the dispatcher) gains a `coherence-chain` case and a `USAGE` entry.

```
# Each round, archive its coherence (kilobytes, no clause text):
vaulytica analyze 'round1/*.docx' --playbook-file team.playbook.json --posture --emit-coherence round1.coherence.json
vaulytica analyze 'round2/*.docx' --playbook-file team.playbook.json --posture --emit-coherence round2.coherence.json
vaulytica analyze 'round3/*.docx' --playbook-file team.playbook.json --posture --emit-coherence round3.coherence.json

# Later — name the deal's headwater (the front to watch first), or catch an intransitive lead-lag cycle, from the archive alone:
vaulytica coherence-chain round1.coherence.json round2.coherence.json round3.coherence.json \
  --fail-on-lead-cycle
```

---

# Part XV — Build plan

Continuing the global numbering after v41's Step 221. Verification gate for every step: `npm run typecheck && lint && test && build` green; the v7 coverage/parity/property gates, the v8 fuzz + citation gates, the v9 no-wall-clock gate, and the responsiveness e2e stay green.

Status legend: **✅ shipped** · ⬜ proposed.

| #      | Step                                              | Output | Tier  |
| ------ | ------------------------------------------------- | ----- | ----- |
| 222 ✅ | `coherence-chain` transitive lead-lag closure & cycle gate | `src/report/coherence-chain.ts` — `ChainRole`, `CoherenceChainFront`, `CoherenceChain`, pure `computeCoherenceChain` (reuses `computeCoherencePrecedence` unchanged, builds the directed graph from its `leading` edges, computes a Floyd–Warshall reachability fixpoint, classifies `source`/`relay`/`sink`/`cyclic`/`isolated`, picks the headwater by greatest reach, deal-level `edges` = v35's `leading` count + `acyclic`/`cyclic` gate; namespaced integer-exact `chain_hash`), `exposureCyclic` predicate (= `cyclic`), JSON + markdown renderers. `tools/cli/coherence-chain.ts` — `computeCoherenceChainArtifacts` (pure, reusing `verifyCoherenceSequence` unchanged) + `runCoherenceChain` (file IO + exit codes); dispatcher + `USAGE` wired. Tests: the acyclic chain (source/relay/sink, reach and led-by, headwater), the intransitive cycle (the canonical non-transitive Condorcet triple — every front cyclic, the gate firing, no headwater), the edges = v35 `leading` tally invariant, the interleaved-pair no-edge case (both isolated), the never-crosses isolated front, the source-feeding-a-cycle case (a headwater plus a downstream loop), determinism, ≥2-round requirement, cross-ladder refusal across the sequence (naming the two rounds), unpinned-v1 note, tamper rejection (round-prefixed), gate parity, render + JSON. Every existing command's suite passes unchanged. | Reach |

Total work shipped this spec: **1 build step (222).** Purely additive — a new subcommand and one pure module that composes the same lead-lag edges v35 already derives; **no existing source file's behavior changes** (v42 needs nothing newly exported), and every existing command's output and golden is unchanged.

---

# Part XVI — Principled deferrals

- **A longest-chain (cascade depth) read.** ⬜ Not built. The longest *simple* path is NP-hard on a cyclic graph and needs a float-free tie-break the binary floor does not naturally supply; v42 reads transitive `reach` (cascade *breadth*), the polynomial, integer-exact magnitude. The full edge set is in the JSON for a consumer that wants to walk paths.
- **Plurality edges (every non-null leader, not just strict majority).** ⬜ Not built. The graph uses only v35's `leading` edges — the same stable couplings the family gates on everywhere. A razor-thin plurality first-mover is not a stable lead; admitting it would make the cycle gate fire on noise.
- **A configurable cascade-breadth gate (`--min-reach K`).** ⬜ Not built. The gate fires on a directed *cycle* — a structural pathology, not a threshold — already tuning-free. The per-front `reach` is in the JSON for a consumer wanting a depth/breadth bar.
- **A 2-D per-front × per-step read.** ⬜ Deferred (v41 Part XVI). The per-front and pairwise families and now the first transitive read are complete on the structure the binary floor admits; the next genuinely-new direction is a *matrix* read (per-front × per-step), not another reduction of the same edges.
- **A standalone chain artifact (`--emit-chain`).** ⬜ Deferred, for the same reason v14–v41 keep the derived thing derived: the report is cheaply recomputable from the N coherence artifacts on demand.
- **A browser surface for an N-round chain synthesis.** ⬜ Deferred (v16–v41 Part XVI). The browser does an in-session two-round comparison; an N-artifact transitive lead-lag read is a CI/dashboard concern.

---

# Part XVII — Open questions for the maintainer

1. **Is the pairwise family now closed, transitive read included?** v35 reads each pair; v42 composes them into the global ordering and detects its incoherence. Recommendation: **treat the directional pairwise family as complete.** The remaining genuinely-new read is the *2-D* one (per-front × per-step matrix) — a different shape of output, not another reduction of the lead-lag edges.
2. **Should the gate read the cycle or the cascade?** Today `--fail-on-lead-cycle` reads the structural pathology (an intransitive loop); a consumer wanting to flag a deep cascade reads `reach`/`max_reach` from the JSON. Recommendation: **keep the gate on the cycle** — it is the uniquely-transitive condition (impossible to detect pairwise) and tuning-free, where any cascade-depth bar would need a knob.

---

# Part XVIII — What this gives the user

- **The deal's headwater, named from the archive alone.** Archive each round's kilobyte coherence artifact as you go; `coherence-chain` composes v35's pairwise leads into a directed graph and names the front upstream of everything — the one to watch first, whose movement gives advance notice on a whole cascade. v35 can name a pair's leader; only the closure can name the *deal's* leading indicator, with no clause text checked out and no re-analysis run.
- **A gate on an intransitive lead-lag no pairwise read can see.** `--fail-on-lead-cycle` fires only when the relation contains a directed cycle — three or more fronts each crossing first over the next in a loop. Every pair on the loop is individually consistent (v35 calls each `leading`), so the cycle is structurally undetectable per-pair; it catches the case where the per-pair early-warning signal v35 sells *does not compose* into a watch-order, which no count, ordering, or pairwise read can isolate.
- **The same five promises.** Deterministic, no AI, no server, citable, never drafts — every line of v42 passes the §3 gate. It reuses the lead-lag edges v35 already derives, through the loader v18–v41 already share; it adds one reachability fixpoint over those edges, no on-disk format, and no change to any existing source file's behavior — every existing surface is byte-for-byte unchanged.
