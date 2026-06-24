# Changelog

All notable changes to this project will be documented in this file. Format adapted from [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [9.40.0] — 2026-06-24 — Document-free recovery chain / the transitive closure of v37's pairwise recovery-order relation, the recovery mirror of v42 (spec-v43)

### Added
- **A `coherence-recovery-chain` headless subcommand — the *transitive closure* of v37's pairwise
  recovery-order relation, the *recovery mirror* of v42.** v37 (`coherence-recovery-order`) reads each
  *pair* of fronts in isolation — when both *recover* (climb back at-or-above the acceptable floor),
  does one consistently recover *first* (and so the other *last*, the laggard)? It never composes the
  pairs, so two facts a deal lead wants stay hidden: the **chain** (Cap recovers before Term, Term
  before Indemnity, so Indemnity is restored *after* Cap *through* Term — the deal's *tailwater*, the
  front exposed below the floor longest of all — even with no direct Cap→Indemnity edge), and the
  **cycle** (Cap recovers before Term, Term before Indemnity, Indemnity before Cap — three clean
  pairwise orders that cannot be globally ranked, a Condorcet cycle no pairwise read can detect). v43
  reuses `computeCoherenceRecoveryOrder` **unchanged** (the join pattern v38/v40/v41/v42 use), builds
  the directed graph whose edges are exactly v37's strict-majority `leading` pairs (`first_recoverer →
  last_recoverer`), and computes its transitive closure. Per front: the sorted
  `recovers_before_directly` (direct out-neighbours), the transitive `reach` and `recovered_before_by`,
  whether it sits on a cycle (`in_cycle`), and a `class` (`source` / `relay` / `sink` / `cyclic` /
  `isolated`); plus the deal's `tailwater` (the greatest-`recovered_before_by` sink — the front
  restored last of all), `max_lag`, `edges` (= v37's `leading` tally, by construction), `acyclic`, and
  `cyclic`. Where v42 names the *headwater* (the front to watch first), v43 names the *tailwater* (the
  front exposed longest) — the two transitive reads the two directions of a floor crossing admit.
  Introduces no new crossing/ordering math — it is a reachability fixpoint over the same recovery-order
  edges v37 already derives. (`src/report/coherence-recovery-chain.ts`,
  `tools/cli/coherence-recovery-chain.ts`.)
- **A `--fail-on-recovery-cycle` gate** — exits 2 when the recovery-order relation contains a directed
  cycle: three or more fronts each recovering above the floor first over the next in a loop, so no
  single restoration order ranks every front. A directed cycle either exists or it does not — a pure
  boolean over the integer-derived edges, so the gate inherits no knob. It is the *transitive* verdict
  v37 structurally cannot pose: every pair on the loop is individually `leading` to v37, so the
  intransitivity is undetectable per-pair. *Distinct from* v37's `--fail-on-lagging-recovery` (the
  *presence* of a stable laggard; v43 flags the *incoherence* of the composed restoration order
  instead).
- **`vaulytica.posture-recovery-chain.v1` report schema** and an integer-exact `recovery_chain_hash`
  (over the canonical per-front set — the front, its sorted `recovers_before_directly`, and its
  `class`; the derived transitive `reach` / `recovered_before_by` integers and the deal-level scalars
  omitted, since the edge set fully determines them), namespaced apart from every prior hash so
  computing the chain moves no golden. Twenty-five posture axes, 31 document-free coherence
  subcommands. (`docs/spec-v43.md`.)

## [9.39.0] — 2026-06-24 — Document-free exposure lead chain / the transitive closure of v35's pairwise lead-lag relation (spec-v42)

### Added
- **A `coherence-chain` headless subcommand — the *transitive closure* of v35's pairwise lead-lag
  relation.** v35 (`coherence-precedence`) reads each *pair* of fronts in isolation — does one cross
  the acceptable floor *before* the other for a strict majority of their comparisons (`leads`)? It
  never composes the pairs, so two facts a deal lead wants stay hidden: the **chain** (Cap leads Term,
  Term leads Indemnity, so Cap is a transitive early-warning indicator for Indemnity *through* Term —
  the deal's *headwater* — even with no direct Cap→Indemnity edge), and the **cycle** (Cap leads Term,
  Term leads Indemnity, Indemnity leads Cap — three clean pairwise leads that cannot be globally ranked,
  a Condorcet cycle no pairwise read can detect). v42 reuses `computeCoherencePrecedence` **unchanged**
  (the join pattern v38/v40/v41 use), builds the directed graph whose edges are exactly v35's
  strict-majority `leading` pairs (`leader → follower`), and computes its transitive closure. Per
  front: the sorted `leads_directly` (direct out-neighbours), the transitive `reach` and `led_by`,
  whether it sits on a cycle (`in_cycle`), and a `class` (`source` / `relay` / `sink` / `cyclic` /
  `isolated`); plus the deal's `headwater` (the greatest-reach source — a front with nothing upstream),
  `max_reach`, `edges` (= v35's `leading` tally, by construction), `acyclic`, and `cyclic`. Introduces
  no new crossing/ordering math — it is a reachability fixpoint over the same lead-lag edges v35 already
  derives. (`src/report/coherence-chain.ts`, `tools/cli/coherence-chain.ts`.)
- **A `--fail-on-lead-cycle` gate** — exits 2 when the lead-lag relation contains a directed cycle:
  three or more fronts each crossing the floor first over the next in a loop, so no single watch-order
  ranks every front. A directed cycle either exists or it does not — a pure boolean over the
  integer-derived edges, so the gate inherits no knob. It is the *transitive* verdict v35 structurally
  cannot pose: every pair on the loop is individually `leading` to v35, so the intransitivity is
  undetectable per-pair. *Distinct from* v35's `--fail-on-leading-front` (the *presence* of a stable
  pair; v42 flags the *incoherence* of the composed global ordering instead — a deal whose every pair
  is `leading` can be a clean acyclic pipeline or an intransitive loop).
- **`vaulytica.posture-chain.v1` report schema** and an integer-exact `chain_hash` (over the canonical
  per-front set — the front, its sorted `leads_directly`, and its `class`; the derived transitive
  `reach` / `led_by` integers and the deal-level scalars omitted, since the edge set fully determines
  them), namespaced apart from every prior hash so computing the chain moves no golden. Twenty-three
  posture axes, 30 document-free coherence subcommands. (`docs/spec-v42.md`.)

## [9.38.0] — 2026-06-24 — Document-free recovery durability / per-front mean relapsed-interval length, the above-floor mirror of v40's below-floor mean (spec-v41)

### Added
- **A `coherence-durability` headless subcommand — the *typical length* of a fix, where v30 reads its
  *extreme*.** v30 (`coherence-relapse`) pairs each *recovery* above the acceptable floor with the
  *fall* that undoes it, then reduces the clean-interval lengths two ways — the deal's **quickest**
  single relapse (`min_interval`) and whether any recovery was undone the very next round
  (`immediate`). Both are extremes; neither reads the **mean**. A front that holds five rounds twice
  and once bounces back the next round owns the deal's quickest single relapse, yet its fixes almost
  always last; a front that holds one round *every* time has the same quickest relapse, yet it is the
  one whose every fix is fragile. v41 reuses `computeCoherenceRelapse` **unchanged** (the join pattern
  v38 used for v36+v37, v40 for v28) and averages each front's relapsed interval lengths — the
  *above-floor* mirror of v40's *below-floor* mean. Per front: the relapsed `clean_intervals`,
  `closed_intervals`, `open_intervals`, `total_rounds`, the `mean_durability`
  (`total_rounds / closed_intervals`), the `min_interval` (carried for contrast), and a `class`
  (`fragile` / `durable` / `held` / `steady` / `unstated`); plus the deal's `most_fragile_dimension`,
  `min_mean`, `total_relapsed_intervals` (= v30's `relapse_count`), `total_held_intervals` (= v30's
  `held_count`), and `fragile`. Introduces no new pairing/crossing math — it averages the same
  intervals v30 already pairs. (`src/report/coherence-durability.ts`, `tools/cli/coherence-durability.ts`.)
- **A `--fail-on-fragile-recovery` gate** — exits 2 when at least one front's relapsed recoveries
  average fewer than two clean rounds above the acceptable floor (`total_rounds < 2 × closed_intervals`):
  a *fragile* front whose fix, when it recovers, typically does not survive even one clean round before
  relapsing. Two rounds is the first integer above the metric's structural minimum (a recovery and the
  immediately following fall is one clean round), so the bar is tuning-free. *Strictly stronger
  evidence than* v30's `--fail-on-immediate-relapse`: a fragile mean forces at least one clean interval
  of one round, so every `fragile` front also trips v30's `immediate` gate — but the converse fails
  (a front with intervals `[1, 5]`, mean 3, trips v30's gate on its single fast relapse yet is
  `durable` here). *Distinct from* v40's `--fail-on-lingering-exposure` (the below-floor mean; v41 is
  its above-floor mirror). A *held* recovery (one never undone) is excluded from the mean — an
  unbounded clean interval, the durable best case — but counted (`open_intervals`).
- **`vaulytica.posture-durability.v1` report schema** and an integer-exact `durability_hash` (over the
  canonical per-front set — the front, its `floors`, sorted `clean_intervals`, `open_intervals`, and
  `class`; the derived `mean_durability` / `min_interval` / `min_mean` / `fragile` omitted), namespaced
  apart from every prior hash so computing the durability moves no golden. Twenty-two posture axes, 29
  document-free coherence subcommands. (`docs/spec-v41.md`.)

## [9.37.0] — 2026-06-24 — Document-free exposure duration / per-front mean recovered-exposure length, the central tendency of v28's recovery episodes (spec-v40)

### Added
- **A `coherence-duration` headless subcommand — the *typical length* of an exposure, where v28 reads
  its *extreme*.** v28 (`coherence-latency`) pairs each *fall* below the acceptable floor with the
  *recovery* that closes it, then reduces the episode lengths two ways — the deal's **slowest** single
  recovery (`max_latency`) and whether any fall went **unrecovered** (`open_count`). Both are extremes;
  neither reads the **mean**. A front that recovers in one round three times and once takes five owns
  the deal's slowest single recovery, yet it almost always recovers at once; a front that takes four
  rounds *every* time has a shorter worst spell, yet it is the one that chronically lingers. v40
  reuses `computeCoherenceLatency` **unchanged** (the join pattern v38 used for v36+v37) and averages
  each front's recovered episode lengths. Per front: the recovered `latencies`, `closed_episodes`,
  `open_episodes`, `total_rounds`, the `mean_duration` (`total_rounds / closed_episodes`), the
  `max_latency` (carried for contrast), and a `class` (`lingering` / `brief` / `open` / `steady` /
  `unstated`); plus the deal's `longest_mean_dimension`, `max_mean`, `total_closed_episodes`
  (= v28's `recovered_count`), `total_open_episodes` (= v28's `open_count`), and `lingering`.
  Introduces no new pairing/crossing math — it averages the same episodes v28 already pairs.
  (`src/report/coherence-duration.ts`, `tools/cli/coherence-duration.ts`.)
- **A `--fail-on-lingering-exposure` gate** — exits 2 when at least one front's recovered exposures
  average at least two rounds below the acceptable floor (`total_rounds ≥ 2 × closed_episodes`): a
  *lingering* front that, when it falls, typically does not recover the very next round. Two rounds is
  the first integer above the metric's structural minimum (a fall and the immediately following
  recovery is one round), so the bar is tuning-free. *Distinct from* v28's
  `--fail-on-unrecovered-exposure` (the open fall, blind to the closed episodes' length — a front that
  always recovers but slowly trips this gate and clears v28's; a front that recovers promptly then
  falls and never returns trips v28's and clears this one) and from a `max_latency` extreme (the mean
  can rank-swap against the worst case — episodes `[1, 6]` own the slowest single recovery yet a mean
  of 3.5, while `[4, 4]` has a smaller worst spell yet a larger mean). An *open* (unrecovered) episode
  is excluded from the mean — an unbounded duration v28's gate owns — but counted (`open_episodes`).
- **`vaulytica.posture-duration.v1` report schema** and an integer-exact `duration_hash` (over the
  canonical per-front set — the front, its `floors`, sorted `latencies`, `open_episodes`, and `class`;
  the derived `mean_duration` / `max_latency` / `max_mean` / `lingering` omitted), namespaced apart
  from every prior hash so computing the duration moves no golden. Twenty-one posture axes, 28
  document-free coherence subcommands. (`docs/spec-v40.md`.)

## [9.36.0] — 2026-06-24 — Document-free exposure cadence / per-front floor-crossing churn rate, the churn mirror of v31's dwell (spec-v39)

### Added
- **A `coherence-cadence` headless subcommand — the *churn* counterpart to v31's *dwell*.** v31
  (`coherence-tenure`) reads how *long* a front sits below the acceptable floor (its occupancy
  *share*); v24 (`coherence-volatility`) counts how *many times* a front's standing crosses the floor.
  Neither reads the **rate**: across the transitions a front actually had, how *often* did it flip
  across the floor? Two fronts with identical below-floor share — both below half their stated rounds —
  can be opposites: one dips once and holds, the other alternates every round; v31 calls them the
  same, and v24, gating on the raw count, calls a front that crossed twice in twenty transitions just
  as `volatile` as one that crossed twice in two. v39 normalizes the same crossings v24 counts by the
  transitions between the rounds that *stated* the front. Per front: the floor `crossings` (both
  directions), its `transitions` (= `stated_rounds − 1`), the `cadence` (`crossings / transitions`),
  and a `class` (`oscillating` / `settled` / `static` / `unstated`); plus the deal's
  `busiest_dimension`, `max_cadence`, `total_crossings` (= v24's `crossings` summed), and
  `oscillating`. Introduces no new crossing/ordering math — it scans the same `floors[]` v24 reads.
  (`src/report/coherence-cadence.ts`, `tools/cli/coherence-cadence.ts`.)
- **A `--fail-on-oscillating-front` gate** — exits 2 when at least one front crossed the acceptable
  floor for a strict **majority** of its transitions (`crossings × 2 > transitions`): an *oscillating*
  front that flips sides more often than it holds one, never able to settle. *Distinct from* v24's
  `--fail-on-volatile-exposure` (the raw crossing *count*, blind to opportunity — a front crossing
  twice in twenty transitions is `volatile` to v24 but `settled` here; one crossing once in its single
  transition is `monotone` to v24 but `oscillating` here) and v31's `--fail-on-majority-below` (the
  *dwell* — a front below floor rounds 1–3 of 6 that holds is a `majority` tenure but a `settled`
  cadence; a front flipping every round is a `minority` tenure but `oscillating`). A strict majority of
  the transitions is the one churn boundary needing no knob.
- **An integer-exact `cadence_hash`** (`schema: vaulytica.posture-cadence.v1`) over the canonical
  per-front set (the front, its `floors`, `stated_rounds`, `transitions`, `crossings`, and class; the
  derived float `cadence`, `busiest_dimension`, `max_cadence`, and `oscillating` omitted), namespaced
  apart from every prior hash. The busiest-cadence pick uses integer cross-multiplication
  (`crossings × transitions`, earliest label on a tie), never a float compare.

### Lineage
- **The per-front cadence v38 steered to.** v38 Open Question #1 named the next axis explicitly: with
  the pairwise-precedence family and its first synthesis complete, the natural next read is "a fresh
  *per-front cadence* read (below/above oscillation rate), not another pairwise direction or
  conjunction." v39 is that read.
- **Distinct from v24 and v31.** v24 gates on the raw crossing count (blind to opportunity); v31 on
  the below-floor dwell (blind to order); v39 on the flip *rate* (crossings normalized by transitions).
  The test suite includes a `volatile`-but-`settled` fixture (the v24 divergence) and a same-dwell /
  opposite-churn fixture (the v31 divergence).

### Unchanged (additive)
- Purely additive — a new subcommand and one pure module reusing `verifyCoherenceSequence` unchanged.
  **No existing source file's behavior changes**; every other command's output and golden is
  byte-for-byte unchanged. The report stays *derived* (no new on-disk format). Suite **3,504 passing +
  2 skips** (was 3,482 + 2; +22 new tests), 237 test files (was 235).

## [9.35.0] — 2026-06-16 — Document-free persistent weak front / the per-front join of v36 + v37 (spec-v38)

### Added
- **A `coherence-weak-front` headless subcommand — the posture family's first *per-front* synthesis:
  the join of v36's concession order and v37's recovery order.** v36 (`coherence-concession`) names,
  per pair, the front that *concedes* (falls below the acceptable floor) **first**; v37
  (`coherence-recovery-order`) names the front that *recovers* (climbs back at-or-above the floor)
  **last** — the laggard left exposed longest. Each is a directional half-truth, and each spec named
  the same prize the other could not name alone: a front that **concedes first _and_ recovers last**
  is the deal's **persistent weak point** — exposed coming and going — while a front that concedes
  first but recovers *first* is merely *volatile*. v38 reduces the `leading` edges of both halves to a
  per-front verdict. Per front (with a weak signal on either axis): the partners it
  `concedes_first_against` (v36 `leading` pairs where it is the `first_conceder`), the partners it
  `recovers_last_against` (v37 `leading` pairs where it is the `last_recoverer`), the
  `confirmed_against` (the same-partner intersection — the sharpest evidence), and a `class`
  (`persistent-weak` / `conceding` / `lagging`); plus the deal's `most_exposed_front`, the
  `weak_fronts` list, and `has_persistent_weak_front`. Introduces no new fall/recovery/ordering math —
  it reads only the `leading` pairs v36/v37 already classify. (`src/report/coherence-weak-front.ts`,
  `tools/cli/coherence-weak-front.ts`.)
- **A `--fail-on-persistent-weak-front` gate** — exits 2 when at least one front is **both** a
  strict-majority first-conceder (v36) against some partner **and** a strict-majority last-recoverer
  (v37) against some partner. *Strictly stronger* than v36's `--fail-on-leading-concession` or v37's
  `--fail-on-lagging-recovery`, which each fire on a directional ordering existing at all; this
  requires a single front to be the weak side of **both**. A deal can trip v36 and v37 (different
  fronts lead each) yet clear v38 (no one front is weak on both). The conjunction of two already
  tuning-free strict-majority verdicts; no knob.
- **An integer-exact `weak_front_hash`** (`schema: vaulytica.posture-weak-front.v1`) over the
  canonical per-front set (the front, its sorted `concedes_first_against`, its sorted
  `recovers_last_against`, the class; the derived `confirmed_against`, `most_exposed_front`, and
  `has_persistent_weak_front` omitted), namespaced apart from every prior hash. The most-exposed pick
  uses integer leading-edge counts (earliest label on a tie), never a float compare.

### Lineage
- **The join v36 and v37 each deferred.** v36 Part XVI and v37 Part XVI both deferred the join as "a
  downstream read over two independent reports, not a new command" — right while the recovery half was
  unbuilt. With v37 shipped, v38 elevates it, exactly as v37 Open Question #1 steers (the next axis
  should be *per-front*, not another pairwise direction).
- **Distinct from v36 and v37.** v36/v37 are pairwise and directional; v38 is per-front and
  bidirectional. A `first_conceder` in v36 is only `conceding` in v38 unless it is *also* a
  `last_recoverer` in v37, and vice versa. The test suite includes a fixture that trips both halves on
  *different* fronts yet has no persistent weak front (the join clears).

### Unchanged (additive)
- Purely additive — a new subcommand and one pure module reusing `verifyCoherenceSequence`,
  `computeCoherenceConcession`, and `computeCoherenceRecoveryOrder` unchanged. **No existing source
  file's behavior changes**; every other command's output and golden is byte-for-byte unchanged. The
  report stays *derived* (no new on-disk format). Suite **3,482 passing + 2 skips** (was 3,463 + 2;
  +19 new tests), 235 test files (was 233).

## [9.34.0] — 2026-06-16 — Document-free exposure recovery order / pairwise recovery-precedence (spec-v37)

### Added
- **A `coherence-recovery-order` headless subcommand — the recovery mirror of v36's
  direction-resolved precedence: per unordered *pair* of fronts, when the two both *recover* (climb
  back at-or-above the acceptable floor), does one consistently recover *first* (and so the other
  *last*)?** v36 (`coherence-concession`) ordered *falls* only — which front *concedes* first. The
  floor is crossed two ways, and the recovery half was unread. v37 restricts the ordering to
  *recoveries* only, isolating which front the counterparty restores first within a pair — and the
  warning side of the same relation, the **laggard** it leaves exposed below the floor longest. Per
  pair, how many round-transition comparisons saw front A recover *before* B (`a_recovers_first`),
  how many saw B first (`b_recovers_first`), how many were same-step ties (`co_recoveries`), out of
  all `comparisons` (`a_recovers_first + b_recovers_first + co_recoveries`); the pair's
  `first_recoverer` and its `last_recoverer` (the laggard), the `affinity` (the first-recoverer's
  share of all comparisons), the deal's clearest recovery order (`max_affinity` / `most_ordered_pair`
  / `first_recovering_front` / `last_recovering_front`), and a `class` (`leading`/`interleaved`).
  A *leading* pair has a front consistently restored last — the front the counterparty leaves
  exposed longest; an *interleaved* pair recovers in mixed order with no laggard. Reuses v33's exact
  recovery events (silence-skipping, §3); adds no posture math beyond a per-pair *ordered* comparison
  of the recovery-step lists. (`src/report/coherence-recovery-order.ts`,
  `tools/cli/coherence-recovery-order.ts`.)
- **A `--fail-on-lagging-recovery` gate** — exits 2 when at least one pair has a front that recovered
  above the floor first for a strict **majority** of the comparisons (`max(a_recovers_first,
  b_recovers_first) × 2 > comparisons`, ties and reverse-order working against it) — and so a partner
  restored *last* for that same majority. Recovering first is good news; the gate is on the laggard.
  The recovery mirror of v36's `--fail-on-leading-concession`. No tuning knob; a consumer wanting a
  different bar reads `affinity` / `max_affinity` from the JSON.
- **An integer-exact `recovery_order_hash`** (`schema: vaulytica.posture-recovery-order.v1`) over the
  canonical per-pair set (the integer `a_recovers_first`/`b_recovers_first`/`co_recoveries`, the
  `first_recoverer`, the class; the derived `last_recoverer`, the float `affinity`, and derived
  integer `comparisons` omitted), namespaced apart from every prior hash. The clearest-order pick
  uses integer cross-multiplication, never a float compare.

### Lineage
- **Exact tie to v33 and v29.** By construction each pair's `co_recoveries` (the same-step recovery
  ties) equals v33's `co_recoveries` for that pair, and summed over all pairs `total_co_recoveries`
  equals `Σ_t C(recovering_t, 2)` (v29's per-step recovery count choose-two'd) — the same total v33
  reports. Verified against `computeCoherenceRecoveryAffinity` and `computeCoherenceConcurrency` in
  the test suite.
- **Distinct from v36.** A pair `leading` on v36 (orders falls — who concedes first) can be
  `interleaved` on v37 (orders recoveries — who is restored last) and vice versa; the test suite
  includes a fixture that leads on falls but interleaves on recoveries. Joined with v36, v37 names
  the deal's persistent weak front — the one that *concedes first and recovers last*.

### Unchanged (additive)
- Purely additive — a new subcommand and one pure module reusing `verifyCoherenceSequence`
  unchanged. **No existing source file's behavior changes**; every other command's output and
  golden is byte-for-byte unchanged. The report stays *derived* (no new on-disk format). Suite
  **3,463 passing + 2 skips** (was 3,441 + 2; +22 new tests), 233 test files (was 231).

## [9.33.0] — 2026-06-16 — Document-free exposure concession order / pairwise fall-precedence (spec-v36)

### Added
- **A `coherence-concession` headless subcommand — the posture family's first *direction-resolved*
  precedence: per unordered *pair* of fronts, when the two both *fall* below the acceptable floor,
  does one consistently concede *first*?** v35 (`coherence-precedence`) ordered v24's *crossings*
  — a fall **or** a recovery — so it is *direction-blind*: a pair can lead there because one front
  reliably *recovers* first, not because it *concedes* first. v36 restricts the ordering to *falls*
  only, isolating the question a deal lead actually asks ("which front does the counterparty give
  ground on **first**?"). Per pair, how many round-transition comparisons saw front A fall *before*
  B (`a_concedes_first`), how many saw B first (`b_concedes_first`), how many were same-step ties
  (`co_falls`), out of all `comparisons` (`a_concedes_first + b_concedes_first + co_falls`); the
  pair's `first_conceder`, the `affinity` (the first-conceder's share of all comparisons), the
  deal's most-conceding pairing (`max_affinity` / `most_conceding_pair` / `first_conceding_front`),
  and a `class` (`leading`/`interleaved`). A *leading* pair has a front that reliably gives ground
  first — an **early-warning indicator** that the follower is about to concede too; an *interleaved*
  pair falls in mixed order with no first-conceder. Reuses v32's exact fall events (silence-skipping,
  §3); adds no posture math beyond a per-pair *ordered* comparison of the fall-step lists.
  (`src/report/coherence-concession.ts`, `tools/cli/coherence-concession.ts`.)
- **A `--fail-on-leading-concession` gate** — exits 2 when at least one pair has a front that fell
  below the floor first for a strict **majority** of the comparisons (`max(a_concedes_first,
  b_concedes_first) × 2 > comparisons`, ties and reverse-order working against it). The
  *direction-resolved* counterpart to v35's direction-blind `--fail-on-leading-front` — a stable
  concession order that catches the warning a recovery-driven v35 lead would mask. No tuning knob; a
  consumer wanting a different bar reads `affinity` / `max_affinity` from the JSON.
- **An integer-exact `concession_hash`** (`schema: vaulytica.posture-concession.v1`) over the
  canonical per-pair set (the integer `a_concedes_first`/`b_concedes_first`/`co_falls`, the
  `first_conceder`, the class; the derived float `affinity` and derived integer `comparisons`
  omitted), namespaced apart from every prior hash. The most-conceding pick uses integer
  cross-multiplication, never a float compare.

### Lineage
- **Exact tie to v32 and v29.** By construction each pair's `co_falls` (the same-step fall ties)
  equals v32's `co_falls` for that pair, and summed over all pairs `total_co_falls` equals
  `Σ_t C(falling_t, 2)` (v29's per-step fall count choose-two'd) — the same total v32 reports.
  Verified against `computeCoherenceAffinity` and `computeCoherenceConcurrency` in the test suite.
- **Distinct from v35.** A pair `leading` on v35 (direction-blind, orders any crossing) can be
  `interleaved` on v36 (it led only because one front *recovers* first); the test suite includes a
  fixture that leads on all crossings but interleaves on falls.

### Unchanged (additive)
- Purely additive — a new subcommand and one pure module reusing `verifyCoherenceSequence`
  unchanged. **No existing source file's behavior changes**; every other command's output and
  golden is byte-for-byte unchanged. The report stays *derived* (no new on-disk format). Suite
  **3,441 passing + 2 skips** (was 3,419 + 2; +22 new tests), 231 test files (was 229).

## [9.32.0] — 2026-06-16 — Document-free exposure precedence / pairwise lead-lag coupling (spec-v35)

### Added
- **A `coherence-precedence` headless subcommand — the posture family's first *directional*
  pairwise read: per unordered *pair* of fronts, when the two both cross the acceptable floor (in
  any direction), does one consistently cross *first*?** v32/v33/v34 read three *same-step*
  pairwise relations (which two fronts cross *together* in one transition — aligned co-fall,
  aligned co-recovery, opposed counter-move) and are blind to order *across* transitions. v35
  supplies the ordering: per pair, how many round-transition comparisons saw front A cross *before*
  B (`a_leads`), how many saw B first (`b_leads`), how many were same-step ties (`co_crossings`),
  out of all `comparisons` (`a_leads + b_leads + co_crossings`); the pair's `leader`, the
  `affinity` (the leader's share of all comparisons), the deal's most-leading pairing
  (`max_affinity` / `most_leading_pair` / `leading_front`), and a `class` (`leading`/`interleaved`).
  A *leading* pair has a front that reliably moves first — an **early-warning indicator** for the
  follower; an *interleaved* pair crosses in mixed order with no first-mover. Reuses v24's exact
  crossing events (silence-skipping, §3); adds no posture math beyond a per-pair *ordered*
  comparison of the crossing-step lists. (`src/report/coherence-precedence.ts`,
  `tools/cli/coherence-precedence.ts`.)
- **A `--fail-on-leading-front` gate** — exits 2 when at least one pair has a front that crossed
  first for a strict **majority** of the comparisons (`max(a_leads, b_leads) × 2 > comparisons`,
  ties and reverse-order working against it). The *directional* counterpart to v32's
  `--fail-on-coupled-fronts`, v33's `--fail-on-coupled-recoveries`, and v34's
  `--fail-on-opposed-fronts` — a stable lead-lag a same-step read cannot pose. No tuning knob; a
  consumer wanting a different bar reads `affinity` / `max_affinity` from the JSON.
- **An integer-exact `precedence_hash`** (`schema: vaulytica.posture-precedence.v1`) over the
  canonical per-pair set (the integer `a_leads`/`b_leads`/`co_crossings`, the `leader`, the class;
  the derived float `affinity` and derived integer `comparisons` omitted), namespaced apart from
  every prior hash. The most-leading pick uses integer cross-multiplication, never a float compare.

### Lineage
- **Exact tie to v34 and v25.** By construction each pair's `co_crossings` (the same-step ties)
  equals v34's `joint_moves` for that pair, and summed over all pairs `total_co_crossings` equals
  `Σ_t C(crossing_t, 2)` (v25's per-step crossing count choose-two'd) — the same total v34 splits
  into aligned + opposed moves. Verified against `computeCoherenceOpposition` and
  `computeCoherenceSynchrony` in the test suite.

### Unchanged (additive)
- Purely additive — a new subcommand and one pure module reusing `verifyCoherenceSequence`
  unchanged. **No existing source file's behavior changes**; every other command's output and
  golden is byte-for-byte unchanged. The report stays *derived* (no new on-disk format). Suite
  **3,419 passing + 2 skips** (was 3,397 + 2; +22 new tests), 229 test files (was 227).

## [9.31.0] — 2026-06-16 — Document-free exposure counter-move affinity / pairwise opposition coupling (spec-v34)

### Added
- **A `coherence-opposition` headless subcommand — per unordered *pair* of fronts, how often the
  two crossed the acceptable floor the same step in *opposite* directions (one fell as the other
  recovered), the deal's most-opposed such pairing, and whether any pair counter-moved more often
  than it aligned; the off-diagonal completion of v32's co-fall and v33's co-recovery affinities
  (spec-v34).** v32 (`coherence-affinity`) and v33 (`coherence-recovery-affinity`) took the
  posture family's first two pairwise reads — the two *aligned* directions: which two fronts
  *fall* together (the concession block) and which two *recover* together (the restoration
  block). Those are two of the four cells of the 2×2 of {front A falls / recovers} × {front B
  falls / recovers}. The off-diagonal is unread: across the deal, **which two fronts does the
  counterparty move in *opposite* directions at once?** A step where Cap *falls* exactly as Term
  *recovers* is a *counter-move* — a trade-off, the counterparty giving ground on one front
  precisely as it takes ground on another. The two fronts are *substitutes*, bargaining chips
  swapped against each other. v34 reads, per pair, how reliably the two move against each other —
  the substitution v32/v33 (aligned-only) and v29 (per-step counts) structurally cannot pose.
  - **The affinity (pure).** `src/report/coherence-opposition.ts` —
    `computeCoherenceOpposition(rounds)` derives each front's fall-step set and recovery-step set
    (the v29 *fall* and *recovery* events, silence-skipping per §3), then for each unordered pair
    intersects A's falls with B's recoveries and A's recoveries with B's falls for `opposed_moves`
    (transitions the two moved opposite ways), computes the aligned split `co_falls` / `co_recoveries`,
    the `joint_moves` (transitions both crossed, `co_falls + co_recoveries + opposed_moves`), the
    `affinity` (`opposed_moves / joint_moves`), and a `class`: `opposed` (a strict majority of the
    joint moves, `opposed_moves × 2 > joint_moves`) or `incidental` (≥1 counter-move but not a
    majority, including an exact split). A pair that never counter-moved has no opposition edge and
    is omitted. The deal-level report adds `most_opposed_pair` / `max_affinity` (the most-opposed
    coupling, picked by **integer cross-multiplication** — never a float compare, so the ranking is
    platform-exact), `total_opposed_moves` (= `Σ_t falling_t × recovering_t` over v29's per-step
    counts) and `total_aligned_moves` (= v32's `total_co_falls` + v33's `total_co_recoveries`),
    `class_counts`, the `opposed` verdict, and a namespaced `opposition_hash` over the integer move
    counts + class (the derived float `affinity` and derived integer `joint_moves` omitted, so the
    fingerprint is integer-exact over the inputs). `exposureOpposed` is the gate predicate;
    `buildCoherenceOppositionJson` (`schema: vaulytica.posture-opposition.v1`) and
    `renderCoherenceOppositionSummary` are the renderers.
  - **The command (headless).** `tools/cli/coherence-opposition.ts` —
    `computeCoherenceOppositionArtifacts(texts, format?)` verifies all N artifacts and runs the
    spec-v15/v16 cross-ladder guard via the shared `verifyCoherenceSequence` loader (unchanged from
    v18–v33); `runCoherenceOpposition(argv)` does the file IO and exit codes. `--fail-on-opposed-fronts`
    exits 2 when any pair counter-moved for a strict majority of the steps both crossed — distinct
    from v32's `--fail-on-coupled-fronts` and v33's `--fail-on-coupled-recoveries`. Dispatcher +
    `USAGE` wired in `tools/cli/run.ts`.
  - **Join invariants.** `total_opposed_moves` equals `Σ_t falling_t × recovering_t` (v29's per-step
    fall count times its recovery count, summed); `total_aligned_moves` equals v32's `total_co_falls`
    plus v33's `total_co_recoveries`; their sum equals `Σ_t C(crossing_t, 2)` (v25's per-step crossing
    count choose-two'd). The three pairwise reads (v32 co-fall, v33 co-recovery, v34 opposed) partition
    every pair's joint moves exactly.
- **Purely additive — zero existing-source change.** Like v19–v33, v34 needs nothing newly exported;
  `coherence-sequence.ts` and every trajectory/exposure/…/recovery-affinity function are byte-for-byte
  unchanged, and every existing command's output and golden is unchanged. 23 new tests (14 pure-module,
  9 CLI).

## [9.30.0] — 2026-06-16 — Document-free exposure co-recovery affinity / pairwise recovery coupling (spec-v33)

### Added
- **A `coherence-recovery-affinity` headless subcommand — per unordered *pair* of fronts, how
  reliably the two climbed back at-or-above the acceptable floor *together* across the deal,
  the deal's tightest such pairing, and whether any pair coupled more often than it recovered
  apart; the recovery-direction mirror of v32's co-fall affinity (spec-v33).** v32
  (`coherence-affinity`) took the posture family's first pairwise read — which two fronts
  *fall* below floor together (the concession linkage). But the floor is crossed two ways, and
  v32 reads only one. v29 resolved each step into *falls* and *recoveries*; v32 paired the fall
  direction. The mirror is unread: across the deal, **which two fronts does the counterparty
  keep *restoring* as a block?** A recovery on front A that only ever lands alongside a recovery
  on front B is a *linked recovery* — A is hostage to B, repaired as a bundle, never alone. Two
  deals with byte-identical v32 co-fall affinity can have opposite recovery coupling. v33 is to
  v32 as v30 (relapse) is to v28 (latency), and v27 (onset) is to v26 (settling): the exact
  mirror on the opposite floor-crossing direction.
  - **The affinity (pure).** `src/report/coherence-recovery-affinity.ts` —
    `computeCoherenceRecoveryAffinity(rounds)` derives each front's recovery-step set (the v29
    *recovery* event: below → at-or-above, silence-skipping per §3), then for each unordered
    pair intersects the two sets for `co_recoveries` (transitions both recovered), computes
    `union_recoveries` (transitions *either* recovered, `a_recoveries + b_recoveries −
    co_recoveries`), the `affinity` (`co_recoveries / union_recoveries`, the Jaccard overlap),
    and a `class`: `coupled` (a strict majority of the union, `co_recoveries × 2 >
    union_recoveries`) or `incidental` (≥1 co-recovery but not a majority, including an exact
    split). A pair that never both-recovered has no affinity edge and is omitted. The deal-level
    report adds `tightest_pair` / `max_affinity` (the tightest coupling, picked by **integer
    cross-multiplication** — never a float compare, so the ranking is platform-exact),
    `total_co_recoveries` (= `Σ_t C(recovering_t, 2)` over v29's per-step recovery counts) and
    `total_recoveries` (= v29's), `class_counts`, the `coupled` verdict, and a namespaced
    `recovery_affinity_hash` over the integer recovery counts + class (the derived float
    `affinity` and derived integer `union_recoveries` omitted, so the fingerprint is
    integer-exact over the inputs). `exposureRecoveryCoupled` is the gate predicate;
    `buildCoherenceRecoveryAffinityJson` (`schema: vaulytica.posture-recovery-affinity.v1`) and
    `renderCoherenceRecoveryAffinitySummary` are the renderers.
  - **The command (headless).** `tools/cli/coherence-recovery-affinity.ts` —
    `computeCoherenceRecoveryAffinityArtifacts(texts, format?)` verifies all N artifacts and
    runs the cross-ladder guard via the shared `verifyCoherenceSequence` loader (unchanged from
    v18–v32), then computes and renders the affinity. `runCoherenceRecoveryAffinity(argv)` does
    the file IO and exit codes; `--fail-on-coupled-recoveries` exits 2 when any pair recovered
    together for a strict majority of the steps either recovered. The `run.ts` dispatcher gains
    a `coherence-recovery-affinity` case and a `USAGE` entry.
  - **Distinct from v32 and v29.** A pair `coupled` on falls (v32) can be `incidental` on
    recoveries (v33) and vice versa — the two directions are independent relations over the same
    `floors[]` matrix (a covered regression test builds a pair that falls together yet recovers
    on opposite steps: v32 reports a co-fall edge, v33 reports none). Every co-recovery step is
    a v29 `recovering ≥ 2` step, but three different pairs each recovering together once give
    v29 three such steps yet leave every pair `incidental` to v33.
  - **Purely additive.** A new subcommand + one pure module; `verifyCoherenceSequence` and every
    existing source file are reused **without modification**. Every existing command's output
    and golden is byte-for-byte unchanged. Tests: source (15) + CLI (9) — identity
    disk-vs-in-memory, the linked vs the independent recovery, a co-recovery requires both
    fronts to recover the same step, the exact-split incidental boundary, the `Σ C(recovering,
    2)` and `total_recoveries` join invariants, the tightest-pair pick + tie-break,
    no-pairing/§3-silence/both-recovered-once edges, the v32-divergence, determinism,
    ≥2-artifact, cross-ladder refusal, unpinned-v1 note, tamper rejection, gate parity, render +
    JSON.

### Changed
- **README** — new "Exposure co-recovery affinity" section with a worked example; the
  posture-axis callout now reads **fifteen orthogonal axes** (adds RECOVERY-AFFINITY); the
  version table, the dispatcher command lists, the command count (twenty-two), and the CLI
  cheat-sheet all list `coherence-recovery-affinity`.

## [9.29.0] — 2026-06-16 — Document-free exposure co-fall affinity / pairwise concession coupling (spec-v32)

### Added
- **A `coherence-affinity` headless subcommand — per unordered *pair* of fronts, how
  reliably the two fell below the acceptable floor *together* across the deal, the deal's
  tightest such pairing, and whether any pair coupled more often than it fell apart; the
  first *pairwise* read the posture family has taken (spec-v32).** Every reduction through
  v31 is a scalar — per front, per round, or per episode. v25/v29 come closest to a
  relational read (they count, per step, *how many* fronts crossed or fell together) but
  collapse the relation to a count the instant they record it: v29 knows round 3 saw two
  fronts fall, even lists *which* two, but never asks across the sequence whether it is the
  same two again and again. Two deals with byte-identical v29 concurrency profiles (same
  per-step fall counts) can be opposites — one a single stable pair falling together every
  time (a linked concession), the other a different co-falling pair every round (no
  coupling). v32 supplies the missing pairwise axis.
  - **The affinity (pure).** `src/report/coherence-affinity.ts` —
    `computeCoherenceAffinity(rounds)` derives each front's fall-step set (the v29 *fall*
    event: at-or-above → below, silence-skipping per §3), then for each unordered pair
    intersects the two sets for `co_falls` (transitions both fell), computes `union_falls`
    (transitions *either* fell, `a_falls + b_falls − co_falls`), the `affinity`
    (`co_falls / union_falls`, the Jaccard overlap), and a `class`: `coupled` (a strict
    majority of the union, `co_falls × 2 > union_falls`) or `incidental` (≥1 co-fall but not
    a majority, including an exact split). A pair that never both-fell has no affinity edge
    and is omitted. The deal-level report adds `tightest_pair` / `max_affinity` (the tightest
    coupling, picked by **integer cross-multiplication** — never a float compare, so the
    ranking is platform-exact), `total_co_falls` (= `Σ_t C(falling_t, 2)` over v29's per-step
    fall counts) and `total_falls` (= v29's), `class_counts`, the `coupled` verdict, and a
    namespaced `affinity_hash` over the integer fall counts + class (the derived float
    `affinity` and derived integer `union_falls` omitted, so the fingerprint is integer-exact
    over the inputs). `exposureCoupled` is the gate predicate; `buildCoherenceAffinityJson`
    (`schema: vaulytica.posture-affinity.v1`) and `renderCoherenceAffinitySummary` are the
    renderers.
  - **The command (headless).** `tools/cli/coherence-affinity.ts` —
    `computeCoherenceAffinityArtifacts(texts, format?)` verifies all N artifacts and runs the
    cross-ladder guard via the shared `verifyCoherenceSequence` loader (unchanged from
    v18–v31), then computes and renders the affinity. `runCoherenceAffinity(argv)` does the
    file IO and exit codes; `--fail-on-coupled-fronts` exits 2 when any pair fell together for
    a strict majority of the steps either fell. The `run.ts` dispatcher gains a
    `coherence-affinity` case and a `USAGE` entry.
  - **Distinct from v29's `--fail-on-concerted-fall`.** Every co-fall step *is* a v29
    concerted-fall step (two fronts down at once), so `coupled ⟹ concerted` for that step —
    but the reverse fails where it matters: three *different* pairs each falling together once
    trip v29 (three concerted-fall steps) yet leave every pair `incidental` to v32 (each
    co-fell once, apart more). v29 asks "did any step lurch?"; v32 asks "is there a *stable*
    concession pairing?".
  - **Purely additive.** A new subcommand + one pure module; `verifyCoherenceSequence` and
    every existing source file are reused **without modification**. Every existing command's
    output and golden is byte-for-byte unchanged. Tests: source (14) + CLI (9) — identity
    disk-vs-in-memory, the coupling vs the coincidence (v29 trips, v32 clears), a co-fall
    requires both fronts to fall the same step, the exact-split incidental boundary, the
    `Σ C(falling, 2)` and `total_falls` join invariants, the tightest-pair pick + tie-break,
    no-pairing/§3-silence/both-fell-once edges, determinism, ≥2-artifact, cross-ladder
    refusal, unpinned-v1 note, tamper rejection, gate parity, render + JSON.

### Changed
- **README** — new "Exposure co-fall affinity" section with a worked example; the posture-axis
  callout now reads **fourteen orthogonal axes** (adds AFFINITY); the version table, the
  dispatcher command lists, the command count (twenty-one), and the CLI cheat-sheet all list
  `coherence-affinity`.

## [9.28.0] — 2026-06-16 — Document-free exposure tenure / below-floor occupancy share (spec-v31)

### Added
- **A `coherence-tenure` headless subcommand — per front, what *share* of the rounds that
  stated it sat below the acceptable floor, the deal's heaviest such share, and whether any
  front was below floor for a strict *majority* of its stated rounds; the occupancy axis the
  posture family never read (spec-v31).** v21 (`coherence-persistence`) reads a raw
  `rounds_below` count against the *total* round span and gates on the *endpoint* (a front
  below floor *now*). v31 supplies the missing occupancy axis: read the same `floors[]`
  matrix per front, but normalize the below-floor count by the front's *stated* rounds (the
  §3-honest denominator) and headline the *burden*. A brief dip that recovered and a chronic
  burden that recovered are identical to v21 (both `resolved`) — opposites here.
  - **The tenure (pure).** `src/report/coherence-tenure.ts` —
    `computeCoherenceTenure(rounds)` counts, per front, the rounds that *stated* it
    (`stated_rounds`, the denominator) and the rounds it sat below floor (`below_rounds`, the
    numerator; an unstated round counts toward neither, §3), and computes the `share`
    (`below_rounds / stated_rounds`). Each front is classed `majority` (below floor for a
    strict majority of its stated rounds, `below_rounds × 2 > stated_rounds`), `minority`
    (below floor but not a majority, including an exact split), `none` (never below floor), or
    `unstated` (§3). The deal-level report adds `max_share` / `heaviest_dimension` (the
    heaviest occupancy, picked by **integer cross-multiplication** — never a float compare,
    so the ranking is platform-exact; earliest dimension on a tie), `total_below_rounds`
    (equal by construction to v21's `rounds_below` summed) and `total_stated_rounds`.
    `exposureMajorityBelow` = `tenure.majority` — the gate predicate, **distinct from v21's
    `exposureOpen`**: a front below floor only at the close is `open` to v21 (gate trips) but
    a minority here (gate clears); a front below floor for rounds 1–4 of 5 that recovers at
    round 5 is `resolved` to v21 (gate clears) but a majority here (gate trips). **Honest by
    construction (§3):** silence dilutes neither the numerator nor the denominator, so a
    front below floor both times it was on the table reads 100%, not 40% diluted by rounds it
    was never part of. `buildCoherenceTenureJson` (`schema: vaulytica.posture-tenure.v1`) +
    `renderCoherenceTenureSummary` (heaviest-occupancy verdict, class tally, then one line per
    below-floor front, `majority` first). A namespaced `tenure_hash` (SHA-256 over the
    canonical per-front occupancy set — the integer `stated_rounds`/`below_rounds` and class;
    the derived float `share` is omitted, so the fingerprint is integer-exact), apart from
    every `coherence_hash` … `relapse_hash`.
  - **The command (headless).** `tools/cli/coherence-tenure.ts` —
    `computeCoherenceTenureArtifacts(texts, format?)` verifies all N artifacts and runs the
    spec-v15/v16 cross-ladder guard via the shared `verifyCoherenceSequence` loader
    (unchanged from v18–v30), then renders markdown (default) or `--format json`.
    `runCoherenceTenure(argv)` reads the files and exits 2 under `--fail-on-majority-below`
    when any front was below floor for a strict majority of its stated rounds. Wired into the
    `run.ts` dispatcher + `USAGE`. Requires ≥ 2 artifacts in round order.
  - **Tests.** 24 new (15 pure + 9 CLI): the brief dip vs the chronic burden (both `resolved`
    to v21, opposite tenure), the fresh late dip (`open` to v21 but minority here), the exact
    split (minority, not majority), stated-vs-total normalization (§3), the join invariant
    (`total_below_rounds` = v21's `rounds_below` sum), the heaviest-share pick by exact
    integer ratio + tie-break, no-front-ever-below, unstated-never-counted, stated-once-and-
    below → 100%/majority, determinism, ≥2-artifact requirement, cross-ladder refusal,
    unpinned-v1 note, tamper rejection (round-prefixed), gate parity, render + JSON.
  - **Purely additive.** No existing source file's behavior changes; every existing command's
    output and golden is byte-for-byte unchanged. TWELVE → THIRTEEN posture axes.

## [9.27.0] — 2026-06-16 — Document-free exposure relapse interval / rounds above floor per recovery-to-relapse span (spec-v30)

### Added
- **A `coherence-relapse` headless subcommand — per front, how many rounds its binding
  floor held *above* the acceptable floor between a *recovery* and the *next fall* that
  undoes it, the deal's quickest relapse, and whether any recovery was reversed the very
  next round; the exact mirror of v28's recovery latency (spec-v30).** v28
  (`coherence-latency`) pairs each *fall* forward with the *recovery* that closes it and
  reads the rounds *below* floor (the slowest recovery, gated on a fall that never came
  back). v30 supplies the missing mirror axis: pair each recovery forward with the next
  fall that undoes it and read the rounds *above* floor. Two fronts v24 reports identically
  (same crossing count) and that v28 cannot tell apart (a relapse is not a latency) — a fix
  that held for rounds vs. one reversed the next exchange — are opposites here.
  (Fulfills v28 Part XVI's deferred "clean interval" stat.)
  - **The relapse (pure).** `src/report/coherence-relapse.ts` —
    `computeCoherenceRelapse(rounds)` scans each front's binding floors, attributes each
    stated crossing to the round that reveals it (the same §3 attribution v24/v28 use),
    and pairs each `recovery` (below → at-or-above) forward with the next `fall`
    (at-or-above → below) into `intervals[]`, each carrying its `clean_rounds`
    (`fall_round − recovery_round`, the rounds above floor; `null` when the recovery held).
    Each front is classed `relapsed` (a recovery undone in-sequence — the fix did not hold),
    `held` (recovered and every recovery held), `steady` (never recovered in-sequence), or
    `unstated` (§3). The deal-level report adds `min_interval` / `quickest_dimension` (the
    quickest relapse, earliest on a tie), `relapse_count` / `held_count`, and
    `total_crossings` (equal by construction to v24's per-front sum and v25/…/v29's totals).
    `exposureImmediateRelapse` = `relapse.immediate` (any `clean_rounds === 1`) — the gate
    predicate, **distinct from v28's `exposureUnrecovered`**: v28 fires on a fall that never
    recovered (an unbounded gap *below*); v30 fires on a recovery undone the very next round
    (a minimal gap *above*). **The mirror asymmetry:** a *leading recovery* (a front below
    from round 1 that recovers) is `steady` to v28 but pairs forward here (`held`/`relapsed`).
    **Honest by construction (§3):** silence is neither a recovery nor a fall; a relapse
    revealed after a silent round spans the silent rounds (never *immediate*).
    `buildCoherenceRelapseJson` (`schema: vaulytica.posture-relapse.v1`) +
    `renderCoherenceRelapseSummary`. A namespaced `relapse_hash` (SHA-256 over the canonical
    per-front interval set) keeps every existing golden unmoved. **Zero changes to any
    existing source file** — v30 imports only the already-public `PostureCoherence`/
    `NegotiationTier` types and the shared hashing helpers.
  - **The command (headless).** `tools/cli/coherence-relapse.ts` —
    `computeCoherenceRelapseArtifacts(texts, format?)` is the pure core (the shared
    `verifyCoherenceSequence` loader — parse + hash-verify + cross-ladder guard, unchanged —
    then `computeCoherenceRelapse`, rendered markdown or JSON). `runCoherenceRelapse(argv)`
    is the handler (file IO + exit codes); requires ≥ 2 positionals; under
    `--fail-on-immediate-relapse` exits 2 only when a recovery was undone at the very next
    round. Wired into the `run.ts` dispatcher (`case "coherence-relapse"`) + `USAGE` + header
    doc + unknown-command list. A separate command, not a `coherence-latency` flag — each
    command keeps one gate and one hash.
- **Verified live end-to-end:** a deal where Cap recovers round 3 and falls again round 4
  prints `⚠ Cap: relapsed — recovered round 3 → fell again round 4 (1 round above)` and
  exits **2** under `--fail-on-immediate-relapse`; a recovery that holds ≥2 rounds before
  relapsing clears the gate — the fix-did-not-hold axis the crossing count (v24) and the
  below-latency (v28) cannot isolate.
- **Tests:** +27 (`src/report/coherence-relapse.test.ts` ×18, `tools/cli/coherence-relapse.test.ts` ×9):
  immediate relapse, durable vs immediate fix (same v24 crossing count, different interval),
  a held recovery, the v28 mirror (a fall that never recovered is `open` to v28 but `steady`
  here; a leading recovery is `steady` to v28 but `held`/`relapsed` here), the reduction
  invariant (`total_crossings` = v24's/v25's/v28's/v29's totals), the quickest-relapse pick
  across fronts, silence-does-not-shorten and silence-attribution (§3), above-floor whipsaw
  never pairs (distinct from v17), no-front-ever-recovered, unstated-never-counted (§3), two
  intervals on one front, determinism, ≥2-artifact requirement, cross-ladder refusal naming
  both rounds, unpinned-v1 note, round-prefixed tamper, gate-predicate parity, render + JSON.
  Suite **3,303 passing + 2 skips** (was 3,276), 219 test files (was 217). Every existing
  command's output and golden is byte-for-byte unchanged. New [`docs/spec-v30.md`](docs/spec-v30.md).
  The posture matrix now has **twelve axes** — MOVEMENT (v16–v19), LEVEL (v20), TIME/duration
  (v21), BREADTH (v22), RECURRENCE (v23), VOLATILITY (v24), SYNCHRONY (v25), SETTLING (v26),
  ONSET (v27), LATENCY (v28), CONCURRENCY (v29), and RELAPSE (v30, the mirror of v28).

## [9.26.0] — 2026-06-16 — Document-free exposure concurrency / fronts falling vs recovering per step (spec-v29)

### Added
- **A `coherence-concurrency` headless subcommand — per step, how many fronts *fell*
  below the floor vs. how many *recovered*, the deal's peak fall step, and whether any
  step was a concerted fall; the direction-resolved split of v25's per-step crossing
  count (spec-v29).** v25 (`coherence-synchrony`) counts the fronts crossing the floor in
  each step — but **direction-blind**: a step where two fronts *fell* together and a step
  where one fell while another recovered both register as the same "synchronized" (two
  crossings). v29 supplies the missing axis: split each step's crossings by direction.
  (Fulfills v25 Part XVI's deferred direction-homogeneous synchrony.)
  - **The concurrency (pure).** `src/report/coherence-concurrency.ts` —
    `computeCoherenceConcurrency(rounds)` scans each front's binding floors, attributes
    each stated crossing to the round that reveals it (the same §3 attribution v24/v25 use),
    and buckets it into that step's `falling` (a fall, at-or-above → below) or `recovering`
    (a recovery, below → at-or-above) list. Each step is classed by direction —
    `concerted-fall` (≥2 fell, the gate-worthy class), `concerted-recovery` (≥2 recovered,
    <2 fell), `mixed` (both directions, neither reaching two), `isolated` (one crossing),
    `quiet` (none). The deal-level report adds `peak_fall_transition` / `peak_fall_count`
    (the step the most fronts fell at once, earliest on a tie), the
    `concerted_fall_count` / `concerted_recovery_count` / `mixed_count`, and
    `total_crossings` (equal by construction to v24's per-front sum and v25/v26/v27/v28's
    totals), with `total_falls + total_recoveries = total_crossings`. `exposureConcerted` =
    `concerted_fall_count > 0` — the gate predicate, **distinct from v25's
    `exposureSynchronized`**: v25 fires on any step where ≥2 fronts crossed regardless of
    direction (a one-down-one-up churn trips it); v29 fires only on ≥2 fronts moving the
    same way, down. **Honest by construction (§3):** silence is neither a fall nor a
    recovery; a crossing across a silent gap lands on the round that reveals it, never the
    silent step. `buildCoherenceConcurrencyJson` (`schema: vaulytica.posture-concurrency.v1`)
    + `renderCoherenceConcurrencySummary`. A namespaced `concurrency_hash` (SHA-256 over the
    canonical per-transition set) keeps every existing golden unmoved. **Zero changes to any
    existing source file** — v29 imports only the already-public `PostureCoherence`/
    `NegotiationTier` types and the shared hashing helpers.
  - **The command (headless).** `tools/cli/coherence-concurrency.ts` —
    `computeCoherenceConcurrencyArtifacts(texts, format?)` is the pure core (the shared
    `verifyCoherenceSequence` loader — parse + hash-verify + cross-ladder guard, unchanged —
    then `computeCoherenceConcurrency`, rendered markdown or JSON).
    `runCoherenceConcurrency(argv)` is the handler (file IO + exit codes); requires ≥ 2
    positionals; under `--fail-on-concerted-fall` exits 2 only when a step saw ≥2 fronts fall
    together. Wired into the `run.ts` dispatcher (`case "coherence-concurrency"`) + `USAGE` +
    header doc + unknown-command list. A separate command, not a `coherence-synchrony` flag —
    each command keeps one gate and one hash.
- **Verified live end-to-end:** a concerted-fall deal (Cap and Term both fall in round
  1→2) prints `⚠ round 1→2: 2 fell (Cap, Term), 0 recovered (—) [concerted-fall]` and exits
  **2** under `--fail-on-concerted-fall`; a staggered deal (Cap then Term fall one at a
  time) classes both steps `isolated` and exits **0** — the coordinated-collapse axis v25's
  direction-blind count cannot isolate.
- **Tests:** +24 (`src/report/coherence-concurrency.test.ts` ×15, `tools/cli/coherence-concurrency.test.ts` ×9):
  concerted fall vs churn (same v25 crossing count, different concurrency class), concerted
  recovery, concerted-fall dominates a step with a simultaneous recovery, isolated single
  crossing, the reduction invariant (`total_crossings` = v24's/v25's/v28's totals;
  `total_falls + total_recoveries = total_crossings`), silence-attribution and
  silence-is-quiet (§3), above-floor whipsaw never crosses (distinct from v17),
  no-front-ever-fell, earliest-peak-fall tiebreak, determinism, ≥2-artifact requirement,
  cross-ladder refusal naming both rounds, unpinned-v1 note, round-prefixed tamper,
  gate-predicate parity, render + JSON. Suite **3,276 passing + 2 skips** (was 3,252), 217
  test files (was 215). Every existing command's output and golden is byte-for-byte
  unchanged. New [`docs/spec-v29.md`](docs/spec-v29.md). The posture matrix now has **eleven
  axes** — MOVEMENT (v16–v19), LEVEL (v20), TIME/duration (v21), BREADTH (v22), RECURRENCE
  (v23), VOLATILITY (v24), SYNCHRONY (v25), SETTLING (v26), ONSET (v27), LATENCY (v28), and
  CONCURRENCY (v29, the direction split of v25).

## [9.25.0] — 2026-06-15 — Document-free exposure recovery latency / rounds below floor per episode (spec-v28)

### Added
- **A `coherence-latency` headless subcommand — per front, how many rounds its
  standing sat *below* the floor between a fall and the recovery that closes it, the
  deal's slowest recovery, and whether any fall went unrecovered; the recovery-latency
  reduction of the same crossings v24/v25/v26/v27 count (spec-v28).** v24
  (`coherence-volatility`) counts a front's crossings (`crossings`); v25
  (`coherence-synchrony`) re-buckets them per step; v26 (`coherence-settling`) /
  v27 (`coherence-onset`) read the **index** of the *last* / *first* crossing. All four
  reduce the crossings to a count or a single index — and a count and an index both
  throw away the **gap between a fall and the recovery that closes it**. Two fronts with
  the identical crossing count (both fell once and recovered once) can be opposites here:
  a fall caught at the next exchange (one round below) vs. one that festered for rounds.
  v28 supplies the missing axis: pair each fall with the recovery that closes it and read
  the duration between them. (Fulfills v26/v27 Part XVI's deferred re-exposure-latency
  stat.)
  - **The latency (pure).** `src/report/coherence-latency.ts` —
    `computeCoherenceLatency(rounds)` scans each front's binding floors, attributes each
    stated crossing to the round that reveals it (the same §3 attribution v24/v25/v26/v27
    use), and pairs each *fall* (at-or-above → below) with the next *recovery* (below →
    at-or-above) into `episodes[]`. Each closed episode carries its `latency`
    (`recovery_round − fall_round` — the rounds below floor); an unclosed fall is an *open*
    episode (`recovery_round` `null`, an unbounded latency). The deal-level report adds
    `max_latency` / `slowest_dimension` (the longest closed episode and the front that owns
    it), `recovered_count` / `open_count`, a per-front `LatencyClass`
    (`open` / `recovered` / `steady` / `unstated`), and `total_crossings` — equal by
    construction to v24's per-front sum and v25/v26/v27's per-step sum.
    `exposureUnrecovered(latency)` = `open_count > 0` — the gate predicate, **distinct
    from v21's `exposureOpen`**: v21 fires on a front whose *current standing* is below
    floor (including one stated below from round 1 that never *fell* in-sequence); v28
    fires only on an in-sequence *fall that never closed*. **Honest by construction (§3):**
    silence inside a gap does not reset the standing or invent a recovery; a front stated
    below from round 1 has no in-sequence fall to pair (its descent predates the archive),
    so it contributes no episode and is `steady`. `buildCoherenceLatencyJson`
    (`schema: vaulytica.posture-latency.v1`) + `renderCoherenceLatencySummary`. A
    namespaced `latency_hash` (SHA-256 over the canonical per-front episode set) keeps every
    existing golden unmoved. **Zero changes to any existing source file** — v28 imports only
    the already-public `PostureCoherence`/`NegotiationTier` types and the shared hashing
    helpers.
  - **The command (headless).** `tools/cli/coherence-latency.ts` —
    `computeCoherenceLatencyArtifacts(texts, format?)` is the pure core (the shared
    `verifyCoherenceSequence` loader — parse + hash-verify + cross-ladder guard, unchanged
    — then `computeCoherenceLatency`, rendered markdown or JSON). `runCoherenceLatency(argv)`
    is the handler (file IO + exit codes); requires ≥ 2 positionals; under
    `--fail-on-unrecovered-exposure` exits 2 only when a front fell and never recovered.
    Wired into the `run.ts` dispatcher (`case "coherence-latency"`) + `USAGE` + header doc +
    unknown-command list. A separate command, not a `coherence-onset` flag — each command
    keeps one gate and one hash.
- **Verified live end-to-end:** a slow-but-recovered deal
  (`acceptable → below → below → below → acceptable`) prints
  `slowest recovery: Cap — sat below floor for 3 rounds` and exits **0**; an unrecovered
  fall (`acceptable → below → below`) prints `⚠ Cap: open — fell round 2, never recovered`
  and exits **2** — the recovery-latency axis no count or index can show.
- **Tests:** +26 (`src/report/coherence-latency.test.ts` ×17, `tools/cli/coherence-latency.test.ts` ×9):
  prompt vs slow recovery (same v24 crossing count, different latency), the unrecovered
  episode (gate trips) vs the recovered one (gate clears), the v21 distinction (a front
  below from round 1 is `open` to v21 but contributes no episode here), the reduction
  invariant (`total_crossings` = v24's/v25's/v26's/v27's totals), the slowest-recovery pick
  across fronts (earliest on a tie), silence-inside-a-gap and silence-attribution (§3),
  two-episode fronts (a recovered then an unrecovered fall), above-floor whipsaw never pairs
  (distinct from v17), no-front-ever-fell, unstated never counted, determinism, ≥2-artifact
  requirement, cross-ladder refusal naming both rounds, unpinned-v1 note, round-prefixed
  tamper, gate-predicate parity, render + JSON. Suite **3,252 passing + 2 skips** (was 3,226),
  215 test files (was 213). Every existing command's output and golden is byte-for-byte
  unchanged. New [`docs/spec-v28.md`](docs/spec-v28.md). The posture matrix now has **ten
  axes** — MOVEMENT (v16–v19), LEVEL (v20), TIME/duration (v21), BREADTH (v22), RECURRENCE
  (v23), VOLATILITY (v24, per-front crossings), SYNCHRONY (v25, per-step crossings), SETTLING
  (v26, last-crossing index), ONSET (v27, first-crossing index), and LATENCY (v28,
  fall-to-recovery gap).

## [9.24.0] — 2026-06-15 — Document-free exposure onset / first floor crossing (spec-v27)

### Added
- **A `coherence-onset` headless subcommand — the round the package *first* crossed
  the floor, and whether it degraded from the very opening; the time-of-first-movement
  mirror of v26's last-crossing index (spec-v27).** v24 (`coherence-volatility`) reads
  the N-round archive *down the front axis* (`crossings`); v25 (`coherence-synchrony`)
  re-buckets those crossings *per step* (`crossing_fronts`); v26 (`coherence-settling`)
  reads the **index of the last one** (`settling_round`, `unsettled`). v26 reads the
  *latest* crossing — and the latest throws away *when the first crossing happened*. So a
  deal lead can learn "the package's last floor crossing was the final round" (v26) but
  not "and its *first* crossing was round 1→2 — it degraded from the opening." A deal
  whose crossings were a front falling in round 1→2 and again in the final round (*early
  onset*) is **identical to v26** (same `settling_round`, same `unsettled`) as a deal
  whose crossings were a front falling in round 4→5 and again in the final round (a *clean
  lead-in* of three rounds). The first and last crossing indices are independent whenever
  a deal crosses the floor more than once. v27 supplies the missing axis: read the same
  floor crossings v24/v25/v26 count for the **index** of the first one. (Fulfills v26
  Part XVI's deferred first-crossing stat.)
  - **The onset (pure).** `src/report/coherence-onset.ts` —
    `computeCoherenceOnset(rounds)` attributes each front's stated floor crossing to the
    transition that reveals it (the same attribution v24/v25/v26 use) and marks each
    transition `active` (a front crossed) or `still` (none did). The series reports
    `onset_round` (the `to_round` of the *earliest* active step — the round the package
    first crossed the floor, `null` when none ever did), `lead_in` (the run of leading
    `still` steps before it — the whole sequence when none crossed), `active_count` (steps
    where any front crossed), `early_onset` (the *first* transition was active), and
    `total_crossings` — equal by construction to v24's per-front sum and v25/v26's per-step
    sum (v27 reads the same crossings for *where the first one falls*).
    `exposureEarlyOnset(onset)` = `onset.early_onset` — the *time-of-first-movement* gate
    predicate, distinct from `exposureVolatile` (a single front crossing ≥ 2 times),
    `exposureSynchronized` (≥ 2 fronts crossing in one step), and `exposureUnsettled` (the
    last crossing on the final step). **Honest by construction (§3):** silence does not
    count as a crossing; a crossing across a silent gap is attributed to the transition
    into the round that *reveals* the new standing, and an opening round left entirely
    unstated reveals no crossing — so the lead-in stays honest (silence at the open is not
    an onset). **Distinct from v26:** they are mirror reductions of the same crossings and
    coincide only when a deal crosses the floor exactly once; the moment it crosses twice,
    the first and last indices are independent — v27 separates two deals v26 reports
    identically. Carries a namespaced `onset_hash` (SHA-256, apart from every other hash).
    `buildCoherenceOnsetJson` (`schema: vaulytica.posture-onset.v1`) +
    `renderCoherenceOnsetSummary` (the onset verdict + active-step count, then one line per
    step). **Zero changes to any existing source file** — v27 imports only the
    already-public `PostureCoherence`/`NegotiationTier` types and the shared hashing helpers.
  - **The command (headless).** `tools/cli/coherence-onset.ts` —
    `computeCoherenceOnsetArtifacts(texts, format?)` is the pure core
    (`verifyCoherenceSequence` — the shared parse + hash-verify + cross-ladder guard,
    unchanged — then `computeCoherenceOnset` rendered markdown/JSON);
    `runCoherenceOnset(argv)` is the handler (file IO + exit codes), requiring ≥ 2
    positionals and exiting 2 under `--fail-on-early-onset-exposure` only when the first
    transition crossed the floor. A separate command, not a `coherence-settling` flag —
    one gate, one hash. Wired into the `run.ts` dispatcher (`case "coherence-onset"`) +
    USAGE + header doc + unknown-command list.
  - **Verified live end-to-end.** Drove the real CLI over ladder-pinned artifacts: a clean
    lead-in (`acceptable → acceptable → below`) prints `onset: at round 3 — … after 1
    steady step of clean lead-in` and exits **0**; an early cross (`below → acceptable`)
    prints `onset: EARLY — the floor was first crossed in round 1→2, the opening
    transition` and exits **2** — proving the first-move axis v26's last-move index cannot
    show.
  - **Additive.** A brand-new subcommand + one pure module — every existing command's
    output and every golden byte-for-byte unchanged; no existing source file's behavior
    changes; no new on-disk format (the onset stays *derived*). +22 tests
    (`src/report/coherence-onset.test.ts` ×14, `tools/cli/coherence-onset.test.ts` ×8);
    suite **3,226 passing + 2 skips** (was 3,204), 213 test files (was 211).
  - **Docs.** New [`docs/spec-v27.md`](docs/spec-v27.md); BUILD_PROGRESS v27 §; README
    "Saved coherence baselines" § extended with the onset workflow + the nine-axis summary
    callout + v27 spec-table row + CLI cheat-sheet + commands-table entry + specs list
    brought current v1–v27.

## [9.23.0] — 2026-06-15 — Document-free exposure settling / latest floor crossing (spec-v26)

### Added
- **A `coherence-settling` headless subcommand — the round the package *last* crossed
  the floor, and whether it was still moving at the close; the time-of-last-movement
  reduction the per-front (v24) and per-step (v25) crossing counts both leave out
  (spec-v26).** v24 (`coherence-volatility`) reads the N-round archive *down the front
  axis*: per front, how many times its standing crossed the floor across the whole deal
  (`crossings`). v25 (`coherence-synchrony`) re-buckets those same crossings *per step*:
  per round-transition, how many fronts crossed at once (`crossing_fronts`). Both reduce
  the crossings to a **count** — and a count throws away *when the last crossing
  happened*. So a deal lead can learn "the Cap front crossed the floor twice" (v24) and
  "two fronts crossed together in round 1→2" (v25) but not "the package's *last* floor
  crossing was the final round — it never settled." A deal whose only crossing was a
  front falling in round 1→2 then five steady rounds (*settled early*) is identical to
  v24 (one monotone front) and v25 (one isolated step) as a deal whose only crossing was
  a front falling in the **final** round (*unsettled*). v26 supplies the missing axis:
  read the same floor crossings v24/v25 count for the **index** of the last one.
  - **The settling (pure).** `src/report/coherence-settling.ts` —
    `computeCoherenceSettling(rounds)` attributes each front's stated floor crossing to
    the transition that reveals it (the same attribution v24/v25 use) and marks each
    transition `active` (a front crossed) or `still` (none did). The series reports
    `settling_round` (the `to_round` of the *latest* active step — the round the package
    last crossed the floor, `null` when none ever did), `quiet_tail` (the run of trailing
    `still` steps after it — the whole sequence when none crossed), `active_count` (steps
    where any front crossed), `unsettled` (the *final* transition was active), and
    `total_crossings` — equal by construction to v24's per-front sum and v25's per-step
    sum (v26 reads the same crossings for *where the last one falls*).
    `exposureUnsettled(settling)` = `settling.unsettled` — the *time-of-last-movement*
    gate predicate, distinct from `exposureVolatile` (a single front crossing ≥ 2 times)
    and `exposureSynchronized` (≥ 2 fronts crossing in one step). **Honest by
    construction (§3):** silence does not count as a crossing; a crossing across a silent
    gap is attributed to the transition into the round that *reveals* the new standing,
    and a final round left entirely unstated reveals no crossing — so the close is
    `settled` (silence at the close is stability, not movement). **Distinct from v17's
    whipsaw:** an above-floor jitter (`acceptable → ideal → acceptable`) crosses the floor
    zero times, so it has no settling round and is `settled`. **Distinct from v21's
    duration:** a front stuck below floor for all N rounds has a large `rounds_below` but
    *zero* crossings — it never moved — so it is `settled` to v26. Carries a namespaced
    `settling_hash` (SHA-256, apart from every other hash). `buildCoherenceSettlingJson`
    (`schema: vaulytica.posture-settling.v1`) + `renderCoherenceSettlingSummary` (the
    settling verdict + active-step count, then one line per step). **Zero changes to any
    existing source file** — v26 imports only the already-public `PostureCoherence`/
    `NegotiationTier` types and the shared hashing helpers.
  - **The command (headless).** `tools/cli/coherence-settling.ts` —
    `computeCoherenceSettlingArtifacts(texts, format?)` is the pure core
    (`verifyCoherenceSequence` — the shared parse + hash-verify + cross-ladder guard,
    unchanged — then `computeCoherenceSettling` rendered markdown/JSON);
    `runCoherenceSettling(argv)` is the handler (file IO + exit codes), requiring ≥ 2
    positionals and exiting 2 under `--fail-on-unsettled-exposure` only when the final
    transition crossed the floor. A separate command, not a `coherence-synchrony` flag —
    one gate, one hash. Wired into the `run.ts` dispatcher (`case "coherence-settling"`) +
    USAGE + header doc + unknown-command list.
  - **Verified live end-to-end.** Drove the real CLI over three ladder-pinned artifacts:
    a late cross (`acceptable → acceptable → below`) prints `settling: UNSETTLED — the
    floor was last crossed in round 2→3, the final transition` and exits **2**; an early
    cross (`acceptable → below → below`) prints `settled at round 2 — … then 1 steady step
    to the close` and exits **0** — proving the time axis the per-front/per-step counts
    cannot show.
  - **Additive.** A brand-new subcommand + one pure module — every existing command's
    output and every golden byte-for-byte unchanged; no existing source file's behavior
    changes; no new on-disk format (the settling stays *derived*). +22 tests
    (`src/report/coherence-settling.test.ts` ×14, `tools/cli/coherence-settling.test.ts`
    ×8); suite **3,204 passing + 2 skips** (was 3,182), 211 test files (was 209).
  - **Docs.** New [`docs/spec-v26.md`](docs/spec-v26.md); BUILD_PROGRESS v26 §; README
    "Saved coherence baselines" § extended with the settling workflow + the eight-axis
    summary callout + v26 spec-table row + CLI cheat-sheet + commands-table entry + specs
    list brought current v1–v26.

## [9.22.0] — 2026-06-15 — Document-free exposure synchrony / per-round floor crossings (spec-v25)

### Added
- **A `coherence-synchrony` headless subcommand — the per-round-transition count of
  how many fronts crossed the floor *together*, the per-step transpose of v24's
  per-front crossing count (spec-v25).** v24 (`coherence-volatility`) reads the
  N-round archive *down the front axis*: per front, how many times its standing
  crossed the floor *across the whole deal* (`crossings`). v22 (`coherence-breadth`)
  reads it *down the round axis*, but only on the *level*: per round, how many fronts
  sat *below* the floor (a static standing). Neither reads the archive down the round
  axis on the *movement*: per round-**transition**, how many fronts *crossed* the
  floor in the **same step**. So a deal lead can learn "the Cap front crossed the
  floor twice over the deal" (v24) and "four fronts were below floor in round 3" (v22)
  but not "round 1→2 is where the package **lurched** — two fronts crossed the floor
  at once." A deal with no single *volatile* front (each front crossed at most once)
  can still have a round where several fronts crossed *together* — a coordinated shift
  v24's per-front sum structurally cannot pose, because it slices the crossings by
  front, not by step. v25 supplies the missing axis: re-bucket the **same** floor
  crossings v24 counts — by *step* instead of by *front*.
  - **The synchrony (pure).** `src/report/coherence-synchrony.ts` —
    `computeCoherenceSynchrony(rounds)` attributes each front's stated floor crossing
    to the transition that reveals it and buckets the crossings *per step*: each
    transition reports `crossing_fronts` (the count), `crossed_dimensions` (which
    fronts, `localeCompare`-pinned), and a `synchrony` class — `synchronized` (≥ 2
    fronts crossed at once), `isolated` (exactly 1), `quiet` (0). The series carries
    `peak_transition`/`peak_count` (the single step the most fronts crossed together,
    earliest on a tie), `synchronized_count` (the gate-worthy count of synchronized
    steps), and `total_crossings` — equal by construction to the sum of every front's
    v24 `crossings` (v25 is the literal transpose: the same crossings sliced by step).
    `exposureSynchronized(synchrony)` = `synchronized_count > 0` — the *co-movement*
    gate predicate, distinct from `exposureVolatile` (a single front crossing ≥ 2 times
    across the deal) and `exposureWidened` (the below-floor count grew first→latest).
    **Honest by construction (§3):** silence does not count as a crossing and a crossing
    across a silent gap is attributed to the transition into the round that *reveals*
    the new standing — never to the silent step (`below → unstated → acceptable` is one
    crossing on the step ending at the third round; `below → unstated → below` is zero).
    **Distinct from v17's whipsaw:** an above-floor jitter (`acceptable → ideal →
    acceptable`) is all-`quiet` (zero floor crossings) to v25. Carries a namespaced
    `synchrony_hash` (SHA-256, apart from every other hash). `buildCoherenceSynchronyJson`
    (`schema: vaulytica.posture-synchrony.v1`) + `renderCoherenceSynchronySummary` (peak
    step + synchronized-step count, then one line per step). **Zero changes to any
    existing source file** — v25 imports only the already-public `PostureCoherence`/
    `NegotiationTier` types and the shared hashing helpers.
  - **The command (headless).** `tools/cli/coherence-synchrony.ts` —
    `computeCoherenceSynchronyArtifacts(texts, format?)` is the pure core
    (`verifyCoherenceSequence` — the shared parse + hash-verify + cross-ladder guard,
    unchanged — then `computeCoherenceSynchrony` rendered markdown/JSON);
    `runCoherenceSynchrony(argv)` is the handler (file IO + exit codes), requiring ≥ 2
    positionals and exiting 2 under `--fail-on-synchronized-exposure` only when a single
    step crossed the floor with two or more fronts at once. A separate command, not a
    `coherence-volatility` flag — one gate, one hash. Wired into the `run.ts` dispatcher
    (`case "coherence-synchrony"`) + USAGE + header doc + unknown-command list.
  - **Verified live end-to-end.** Drove the real CLI over three ladder-pinned artifacts
    (Cap+Term both fall in round 1→2, Cap recovers in round 2→3): `coherence-synchrony
    --fail-on-synchronized-exposure` prints `peak step: round 1→2 (2 fronts crossed the
    floor at once)`, `⚠ round 1→2: 2 fronts crossed (Cap, Term)`, and exits **2** (the
    lurch), with `total_crossings: 3` matching `coherence-volatility` on the same files
    (Cap 2 + Term 1 = 3) — proving the per-step transpose the per-front count cannot show.
  - **Additive.** A brand-new subcommand + one pure module — every existing command's
    output and every golden byte-for-byte unchanged; no existing source file's behavior
    changes; no new on-disk format (the synchrony stays *derived*). +20 tests
    (`src/report/coherence-synchrony.test.ts` ×12, `tools/cli/coherence-synchrony.test.ts`
    ×8); suite **3,182 passing + 2 skips** (was 3,162), 209 test files (was 207).
  - **Docs.** New [`docs/spec-v25.md`](docs/spec-v25.md); BUILD_PROGRESS v25 §; README
    badge + "Saved coherence baselines" § extended with the synchrony workflow + the
    seven-axis summary callout + v25 spec-table row + CLI cheat-sheet + commands-table
    entry + specs list brought current v1–v25.

## [9.21.0] — 2026-06-15 — Document-free exposure volatility / per-front floor crossings (spec-v24)

### Added
- **A `coherence-volatility` headless subcommand — the per-front count of times a
  front's standing *crossed* the floor, the crossing-count axis v23's episode count
  throws away (spec-v24).** v23 (`coherence-recurrence`) reads the N-round archive on
  the *episode-count* axis: per front, how many *separate* times it fell below the
  acceptable floor (`below_runs`). But an episode count counts only the **entries**
  into below-floor — it is blind to the **recoveries** between them. A front whose
  binding floor reads `below → below → below` (it never moved) and a front that reads
  `acceptable → below → acceptable` (it fell once and **cleanly recovered**) both
  report `below_runs = 1` and `recurrence = single`: the same episode count, the same
  gate — yet the second *crossed the floor twice* (down, then up) and the first never
  crossed it at all. v21 calls the first `open` and the second `resolved` (the current
  *standing*, not the *movement*); v20 calls both `exposed`; v17 nets the second
  `unchanged`. v24 supplies the missing axis: read the same N artifacts per front and
  count the **floor crossings** — every *stated* transition across the floor boundary,
  in either direction (falls **and** recoveries).
  - **The volatility (pure).** `src/report/coherence-volatility.ts` —
    `computeCoherenceVolatility(rounds)` scans each front's `floors[]` and counts every
    stated transition across the floor (`crossings`): zero is `stable` (it stayed on
    one side the whole deal), one is `monotone` (it crossed once, never back), two or
    more is `volatile` (its standing reversed across the floor at least once). Per front
    it reports the floor path, `rounds_below` (for context), `crossings`, and a
    `volatility` class — `volatile` / `monotone` / `stable` / `unstated` (§3) — plus the
    deal's `most_volatile_dimension` / `max_crossings` (the front with the most
    crossings, earliest on a tie) and `volatile_count`. `exposureVolatile` (=
    `volatile_count > 0`) is the gate predicate; JSON (`schema:
    vaulytica.posture-volatility.v1`) + markdown renderers ship beside it. A namespaced
    `volatility_hash` (SHA-256 over the canonical per-front set) keeps it apart from
    every other hash, so computing it moves no golden.
  - **§3 honesty — silence does not count as a crossing.** A round no document states
    is **skipped**: it neither counts as a crossing nor resets the standing. So
    `below → unstated → below` is **zero** crossings (silence keeps the last known
    standing), and `below → unstated → acceptable` is **one** crossing (a real
    recovery, just unstated in the gap round). A front never stated is `unstated`,
    never `volatile`/`monotone`/`stable`.
  - **Distinct from v17's whipsaw.** v17 fires on any improving *and* any regressing
    rung-step *anywhere on the ladder* (including `acceptable → ideal → acceptable`, an
    above-floor jitter that never risks the floor); v24's crossing count is specific to
    the **floor boundary**, so that same above-floor whipsaw is `stable` (zero
    crossings) to v24. v24 isolates instability that matters for exposure from rung
    jitter that never crosses the floor.
  - **The command (headless).** `tools/cli/coherence-volatility.ts` —
    `computeCoherenceVolatilityArtifacts` (pure: hash-verify + cross-ladder guard via
    the **unchanged** `verifyCoherenceSequence` loader the seven trend/exposure/
    persistence/breadth/recurrence commands share, then compute + render) and
    `runCoherenceVolatility` (file IO + exit codes). `--fail-on-volatile-exposure`
    exits **2** when any front's standing crossed the floor two or more times (it
    reversed at least once) — the *instability* counterpart to v23's churn gate and
    v21's current-standing gate, catching the front that bounced even when it ended on
    the right side of the floor, and ignoring the front that sat stably on the wrong
    side. The dispatcher (`tools/cli/run.ts`) gains the `coherence-volatility` case and
    a `USAGE` entry.
  - **Purely additive.** A new subcommand and one pure module that reads the binding
    floor (`weakest_tier`, v12) already in every artifact for the `below-acceptable`
    rung (v10); **no existing source file's behavior changes** and every existing
    command's output and golden is byte-for-byte unchanged. Tests: volatility identity
    disk-vs-in-memory, bounced (2 crossings) vs stuck (0 crossings) — the pair v23
    reports identically as `single`, single-fall (1 crossing, monotone),
    silence-does-not-cross (§3), recovery-across-silence (1 crossing),
    recover-then-relapse (2 crossings), above-floor whipsaw is stable (distinct from
    v17), most-volatile front (earliest on tie), unstated never counted, no-front-ever-
    crossed (max_crossings 0), determinism, ≥2-artifact requirement, cross-ladder
    refusal (naming both rounds), unpinned-v1 note, tamper rejection (round-prefixed),
    gate parity, render + JSON (20 new tests).

### Posture command family (after v24)
The N-round posture archive is now read on **six** orthogonal axes: MOVEMENT (v17
trajectory / v18 shift / v19 arc — which way a front moved), LEVEL (v20 exposure — how
low a front ever got), TIME (v21 persistence — how long a front was down, and is it
still), BREADTH (v22 — the per-round transpose: how many fronts were down each round),
RECURRENCE (v23 — how many *separate times* a front fell), and VOLATILITY (v24 — how
many times a front's standing *crossed* the floor, recoveries included). Each is a
separate command with exactly one gate and one namespaced hash; none changes any
other's behavior.

## [9.20.0] — 2026-06-15 — Document-free exposure recurrence / per-front below-floor episodes (spec-v23)

### Added
- **A `coherence-recurrence` headless subcommand — the per-front count of
  *separate* below-floor episodes, the episode-count axis v21's duration sum
  throws away (spec-v23).** v21 (`coherence-persistence`) reads the N-round archive
  on the *duration* axis: per front, how many rounds it sat below the acceptable
  floor (`rounds_below`) and whether it is *still* down. But `rounds_below` is a
  **sum** — it adds every below-floor round and forgets their *shape*. A front whose
  binding floor reads `below → below → below` (one steady descent) and a front that
  reads `below → acceptable → below` (it fell, **recovered**, and fell **again**)
  both report `rounds_below = 2` and `persistence = open`: the same duration, the
  same standing, the same gate — yet the second is a concession won back and lost,
  churn the first does not have. v17 (`unchanged` net), v20 (same worst point), and
  v22 (blind to *which* front) cannot tell them apart either. v23 supplies the
  missing axis: read the same N artifacts per front and count the maximal contiguous
  below-floor **episodes**.
  - **The recurrence (pure).** `src/report/coherence-recurrence.ts` —
    `computeCoherenceRecurrence(rounds)` scans each front's `floors[]` for maximal
    contiguous below-floor episodes (`below_runs`): one descent is one episode, a
    recover-then-relapse is two, an oscillating front is three or more. Per front it
    reports the floor path, `rounds_below` (the v21 sum, for context), `below_runs`,
    the 1-based round range of each `episodes[]` entry, and a `recurrence` class —
    `recurring` (≥ 2 episodes) / `single` (1) / `none` (stated, never below) /
    `unstated` (§3) — plus the deal's `most_recurrent_dimension` / `max_runs` (the
    front with the most episodes, earliest on a tie) and `recurring_count`.
    `exposureRecurred` (= `recurring_count > 0`) is the gate predicate; JSON
    (`schema: vaulytica.posture-recurrence.v1`) + markdown renderers ship beside it.
    A namespaced `recurrence_hash` (SHA-256 over the canonical per-front set) keeps
    it apart from every other hash, so computing it moves no golden.
  - **§3 honesty — silence does not split an episode.** A round no document states
    does **not** end a below-floor episode: per the v21 contract that current
    standing reads the latest *stated* round, silence after an exposure keeps the
    last known standing — it is neither a recovery nor a fresh fall. So
    `below → unstated → below` is **one** episode (not a false recurrence); only a
    *stated* at-or-above-floor round (a real recovery) splits one. A front never
    stated is `unstated`, never `recurring`/`single`/`none`.
  - **The command (headless).** `tools/cli/coherence-recurrence.ts` —
    `computeCoherenceRecurrenceArtifacts` (pure: hash-verify + cross-ladder guard
    via the **unchanged** `verifyCoherenceSequence` loader the six trend/exposure/
    persistence/breadth commands share, then compute + render) and
    `runCoherenceRecurrence` (file IO + exit codes). `--fail-on-recurring-exposure`
    exits **2** when any front fell below floor in two or more separate episodes (it
    recovered and relapsed) — the *churn* counterpart to v21's current-standing gate
    and v20's ever gate, catching the unstable front the other side keeps re-opening
    even after its latest stated floor has recovered. The dispatcher (`tools/cli/run.ts`)
    gains the `coherence-recurrence` case and a `USAGE` entry.
  - **Purely additive.** A new subcommand and one pure module that reads the binding
    floor (`weakest_tier`, v12) already in every artifact for the `below-acceptable`
    rung (v10); **no existing source file's behavior changes** and every existing
    command's output and golden is byte-for-byte unchanged. Tests: recurrence
    identity disk-vs-in-memory, recover-then-relapse vs steady descent (the pair v21
    reports identically), silence-does-not-split (§3), stated-recovery-does-split,
    recurred-then-resolved still trips, single-still-open does not, most-recurrent
    front (earliest on tie), unstated never counted, determinism, ≥2-artifact
    requirement, cross-ladder refusal (naming both rounds), unpinned-v1 note, tamper
    rejection (round-prefixed), gate parity, render + JSON (19 new tests).

### Posture command family (after v23)
The N-round posture archive is now read on **five** orthogonal axes: MOVEMENT
(v17 trajectory / v18 shift / v19 arc — which way a front moved), LEVEL (v20
exposure — how low a front ever got), TIME (v21 persistence — how long a front was
down, and is it still), BREADTH (v22 — the per-round transpose: how many fronts were
down each round), and RECURRENCE (v23 — how many *separate times* a front fell). Each
is a separate command with exactly one gate and one namespaced hash; none changes any
other's behavior.

## [9.19.0] — 2026-06-15 — Document-free exposure breadth / per-round deal standing (spec-v22)

### Added
- **A `coherence-breadth` headless subcommand — the whole-deal *per-round*
  standing across all fronts, the transpose axis every command v16–v21 skipped
  (spec-v22).** Every posture command from v16 to v21 reads the N-round archive
  *down the front axis*: pick a front, summarize its history across rounds (v17
  which way it moved, v20 how low it got, v21 how long it was down). None reads it
  *down the round axis*: pick a round, summarize the whole deal across fronts. So
  from the archive a deal lead can answer "is the Cap front still below floor?"
  (v21) but not "how many fronts were below floor in round 3, and was that the
  worst the package ever looked?" — to learn it from v20/v21 a consumer must read
  every per-front row and re-tabulate the `floors[]` columns by hand. v22 supplies
  the transpose: read the same N artifacts not per-front-across-rounds but
  per-round-across-fronts.
  - **The breadth (pure).** `src/report/coherence-breadth.ts` —
    `computeCoherenceBreadth(rounds)` counts, *per round*, the fronts whose binding
    floor (`weakest_tier`, v12) is the `below-acceptable` rung (v10), reporting per
    round `exposed_fronts`, `stated_fronts` (the denominator), and
    `exposed_dimensions` (the below-floor fronts, pinned by `localeCompare`), plus
    the deal's `worst_round`/`worst_count` (the round with the most fronts below
    floor at once, earliest on a tie), `first_count`/`latest_count`, and `widened`
    (`latest_count > first_count`). Carries a namespaced `breadth_hash` (SHA-256
    over the canonical per-round set — apart from every `coherence_hash`,
    `movement_hash`, `trajectory_hash`, `shift_trajectory_hash`, `arc_hash`,
    `exposure_hash`, and `persistence_hash`). `exposureWidened(breadth)` =
    `breadth.widened` — the deal-level breadth-trend gate predicate; unlike
    `exposureBreached` (any single front *ever* below floor) and `exposureOpen`
    (any single front *still* below floor), this fires on the *aggregate trend*:
    the package ended with more fronts below floor than it started. §3-honest: a
    front no document states in a round is not counted as below floor that round
    (silence is not exposure); `stated_fronts` gives the denominator.
    `buildCoherenceBreadthJson` (`schema: vaulytica.posture-breadth.v1`) +
    `renderCoherenceBreadthSummary` (widen/narrow/hold trend + worst round + one
    line per round).
  - **The command (headless).** `tools/cli/coherence-breadth.ts` —
    `computeCoherenceBreadthArtifacts(texts, format?)` is the pure core
    (`verifyCoherenceSequence` shared parse + hash-verify + cross-ladder guard,
    unchanged from v18–v21, then `computeCoherenceBreadth` rendered markdown or
    JSON), and `runCoherenceBreadth(argv)` is the handler (file IO + exit codes);
    requires ≥2 positionals; under `--fail-on-widening-exposure` exits 2 only when
    the latest round has strictly more fronts below floor than the first. A
    separate command, not a flag on a per-front command — each keeps one gate, one
    hash. Wired into the `run.ts` dispatcher (`case "coherence-breadth"`) + USAGE +
    header + unknown-command list.
  - **Verified live end-to-end.** Three ladder-pinned artifacts where the deal
    widens (round 1: Cap below floor → round 3: Cap + Risk + Indemnity below
    floor): `coherence-breadth --fail-on-widening-exposure` prints the per-round
    series `1 → 2 → 3 fronts below floor`, names `worst round: round 3`, and exits
    **2** (the package broadened), while `coherence-persistence` on the same files
    lists three open fronts but cannot show the per-round breadth trend without
    manual transposition — proving the new axis the per-front commands miss.
  - **Additive.** A brand-new subcommand + one pure module — every existing
    command's output (`analyze`/`diff`/`compare`/`compare-coherence`/
    `coherence-trend`/`coherence-shift-trend`/`coherence-arc`/`coherence-exposure`/
    `coherence-persistence`/`verify`) and every golden byte-for-byte unchanged; no
    existing source file's behavior changes; no new on-disk format (the breadth
    stays derived). +18 tests; suite 3,105 → 3,123 passing (+2 skips), 201 → 203
    test files. New [`docs/spec-v22.md`](docs/spec-v22.md). The posture matrix now
    has four axes: movement (v16–v19), level (v20), time (v21), and breadth (v22).

## [9.18.0] — 2026-06-15 — Document-free exposure persistence / current standing (spec-v21)

### Added
- **A `coherence-persistence` headless subcommand — the whole-deal below-floor
  *duration* and *current standing*, the orthogonal *time* axis v20's level view
  never read (spec-v21).** v20's `coherence-exposure` reads the posture archive
  for the *worst* binding floor each front ever reached (its low-water mark). But
  a low-water mark is a single extreme with no memory of time: a front that dipped
  to `below-acceptable` in round 2 and **recovered** to `acceptable` by round 4
  carries the same `worst_floor`/`exposed` as a front **still** below floor in the
  latest round — and v20's `--fail-on-exposure` fires on both, *forever* (the
  worst point never changes once it has happened), so a team that resolved a dip
  cannot make the gate go green. v21 reads the same N artifacts on the *duration*
  axis: not "how low did it get" but "how long was it down, and is it still down?"
  - **The persistence (pure).** `src/report/coherence-persistence.ts` —
    `computeCoherencePersistence(rounds)` matches fronts by dimension (pinned by
    the same `localeCompare` the trajectory/exposure functions use), scans each
    front's binding floors (`weakest_tier`, v12) for the `below-acceptable` rung
    (v10), and reports per front the `floors[]` sequence, `rounds_below` (count of
    rounds below floor), `first_below_round`/`last_below_round` (the span),
    `last_stated_round`, `currently_below` (latest *stated* floor is below floor),
    and a `persistence` class — `open` (still below floor), `resolved`
    (recovered), `none` (never below floor), `unstated` (never stated). Carries a
    `class_counts` tally, an `open_count`, and a namespaced `persistence_hash`
    (apart from every `coherence_hash`/`movement_hash`/`trajectory_hash`/
    `shift_trajectory_hash`/`arc_hash`/`exposure_hash`). `exposureOpen` =
    `open_count > 0` — the *current-standing* gate predicate that **clears when a
    front recovers**, unlike v20's ever-below gate. Honest by construction: a
    front no document ever states is `unstated`, never flagged; current standing
    reads the latest *stated* round, so silence after an exposure keeps the last
    *known* standing — neither an invented recovery nor a fresh exposure (§3).
    `buildCoherencePersistenceJson` (`schema: vaulytica.posture-persistence.v1`) +
    `renderCoherencePersistenceSummary` (class tally + open-front count, then one
    line per open front and one per resolved front). **Zero new posture math
    beyond a count and a last-stated lookup, and zero changes to any existing
    source file** — v21 imports only the unchanged `verifyCoherenceSequence`
    loader and a plain `below-acceptable` literal.
  - **The command.** `tools/cli/coherence-persistence.ts` —
    `computeCoherencePersistenceArtifacts(texts, format?)` is the pure core
    (shared parse + hash-verify + cross-ladder guard via
    `verifyCoherenceSequence`, then `computeCoherencePersistence` rendered
    markdown/JSON), returning `{ok, output, open, ladderNote}`.
    `runCoherencePersistence(argv)` is the handler; requires ≥2 positionals; under
    `--fail-on-open-exposure` exits 2 only when a front is *still* below floor at
    its latest stated round. A *separate* command, not a `coherence-exposure`
    flag — each command keeps one gate, one hash. Wired into the run.ts dispatcher
    (`case "coherence-persistence"`) + USAGE + header doc + unknown-command list.
  - **Additive:** a brand-new subcommand + one pure module — every existing
    command's output (analyze/diff/compare/compare-coherence/coherence-trend/
    coherence-shift-trend/coherence-arc/coherence-exposure/verify) and every
    golden byte-for-byte unchanged; no existing source file's behavior changes;
    the persistence stays *derived* (no new on-disk format). +20 tests. New
    [`docs/spec-v21.md`](docs/spec-v21.md); BUILD_PROGRESS v21 §; README extended
    with the persistence workflow + v21 spec-table row + CLI cheat-sheet +
    commands-table entry + specs list brought current v1–v21. Version 9.17.0 →
    9.18.0.

## [9.17.0] — 2026-06-15 — Document-free posture exposure / low-water mark (spec-v20)

### Added
- **A `coherence-exposure` headless subcommand — the whole-deal binding-floor
  *low-water mark*, the orthogonal *level* axis the movement family never read
  (spec-v20).** Every posture command from v10 to v19 reports *movement* — how a
  rung, a binding floor, or a coherence kind *changed* between rounds. That axis
  has a structural blind spot: a front sitting at `below-acceptable` in **every**
  round never *moves*, so v17's `coherence-trend` calls it `flat`, the summary
  omits it, and `--fail-on-coherence-regression` never fires (a floor only
  "regresses" when it changes to a *worse* rung — one born at the bottom never
  did). Yet it is the most exposed front in the deal. v20 reads the same N
  artifacts on the *level* axis: not "which way did the floor move" but "how low
  did it ever get."
  - **The low-water mark (pure).** `src/report/coherence-exposure.ts` —
    `compareCoherenceExposure(rounds)` matches fronts by dimension (pinned by the
    same `localeCompare` the trajectory functions use), takes a per-front
    **minimum** over the shared `TIER_RANK` (v11/v13) over the binding floor
    (`weakest_tier`) v12 already derives, and reports per front the `floors[]`
    sequence, the `worst_floor` (lowest-ranked stated rung, or `null` when never
    stated), the `worst_round` (1-based index it first fell there), `rounds_stated`,
    and an `exposed` flag (`worst_floor === "below-acceptable"`). Carries a
    `worst_counts` tally, an `exposed_count`, and a namespaced `exposure_hash`
    (apart from every `coherence_hash`/`movement_hash`/`trajectory_hash`/
    `shift_trajectory_hash`/`arc_hash`). `exposureBreached` = `exposed_count > 0`
    — the *level* gate predicate no movement command exposes. Honest by
    construction: a front no document ever states is `unstated`, counted but never
    flagged (silence is not below-floor, §3). `buildCoherenceExposureJson`
    (`schema: vaulytica.posture-exposure.v1`) + `renderCoherenceExposureSummary`
    (worst-level tally + exposed-front count, then one line per exposed front with
    its floor path and first-below-floor round). **Zero new posture math beyond a
    minimum over ranks, and zero changes to any existing source file** — v20
    imports only already-public functions (`TIER_RANK`, `weakest_tier`) and the
    unchanged `verifyCoherenceSequence` loader.
  - **The command.** `tools/cli/coherence-exposure.ts` —
    `compareCoherenceExposureArtifacts(texts, format?)` is the pure core (shared
    parse + hash-verify + cross-ladder guard via `verifyCoherenceSequence`, then
    `compareCoherenceExposure` rendered markdown/JSON), returning `{ok, output,
    breached, ladderNote}`. `runCoherenceExposure(argv)` is the handler; requires
    ≥2 positionals; under `--fail-on-exposure` exits 2 when any front sat below the
    acceptable floor at any round. A *separate* command, not a `coherence-trend`
    flag — each command keeps one gate, one hash. Wired into the run.ts dispatcher
    (`case "coherence-exposure"`) + USAGE + header doc + unknown-command list.
  - **Additive:** a brand-new subcommand + one pure module — every existing
    command's output (analyze/diff/compare/compare-coherence/coherence-trend/
    coherence-shift-trend/coherence-arc/verify) and every golden byte-for-byte
    unchanged; no existing source file's behavior changes; the exposure stays
    *derived* (no new on-disk format). +17 tests. New [`docs/spec-v20.md`](docs/spec-v20.md);
    BUILD_PROGRESS v20 §; README "Saved coherence baselines" § extended with the
    exposure workflow + v20 spec-table row + CLI cheat-sheet + commands-table
    entry + specs list brought current v1–v20. Version 9.16.0 → 9.17.0.

## [9.16.0] — 2026-06-15 — Document-free combined posture arc (spec-v19)

### Added
- **A `coherence-arc` headless subcommand — the v13 per-front combined view
  (binding floor *and* fracture/reconcile, in one report), generalized to N
  rounds and read from the archive alone (spec-v19, building v18 Part XVII open
  question #2).** v17's `coherence-trend` reads N archived coherence artifacts on
  the binding-*floor* axis; v18's `coherence-shift-trend` reads the same N on the
  *agreement* axis. But v13 — the two-round movement both descend from — never
  split those axes: it reports both `floor_movement` and `coherence_shift` per
  front, because a deal lead reconciling a package reads them together (*did this
  front erode, and did it also fracture? did the floor hold while the package
  quietly split? did anything go wrong on either axis?*). v19 restores that
  combined view for the N-round, document-free case, with one deal-level gate.
  - **The join (pure).** `src/report/coherence-arc.ts` —
    `compareCoherenceArc(rounds)` runs the two existing pure trajectory functions
    (`compareCoherenceTrajectory` from v17, `compareCoherenceShiftTrajectory` from
    v18) on the same rounds and joins their per-front results **positionally** on
    `dimension` (both pin fronts by the same `localeCompare`, so the arrays align
    index-for-index; a defensive dimension-equality check makes a broken join
    loud). Each `CoherenceArcFront` carries the floor fields (`floors`, `steps`,
    `net_floor_movement`, `trajectory`), the shift fields (`shifts`, `net_shift`,
    `shift_trajectory`), and the shared `coherences[]` sequence once. The arc
    carries all four count objects, the two component fingerprints **verbatim**
    (`trajectory_hash`, `shift_trajectory_hash` — byte-identical to what the two
    single-axis commands emit on the same inputs), and a namespaced `arc_hash` =
    SHA-256 over `{ trajectory_hash, shift_trajectory_hash }`.
    `arcRegressedOrFractured(arc)` is the combined gate predicate =
    `trajectoryRegressed(floor) || shiftTrajectoryFractured(shift)` — the
    deal-level "did anything go wrong on either axis" verdict neither single-axis
    command exposes. **Zero new posture math:** v19 composes two existing pure
    functions and needs nothing newly exported.
  - **The command.** `tools/cli/coherence-arc.ts` —
    `compareCoherenceArcArtifacts(texts, format?)` is the pure CLI core: it
    verifies all N artifacts and runs the v15/v16 cross-ladder guard across the
    whole sequence via the **shared `verifyCoherenceSequence` loader (unchanged
    from v18)**, then computes and renders the arc (markdown summary or
    `--format json`, `schema: vaulytica.posture-arc.v1`). `runCoherenceArc(argv)`
    is the handler: it reads the N files, prints the arc, and — under
    `--fail-on-regression-or-fracture` — exits 2 on a regression-or-fracture. A
    malformed/tampered round is a hard exit-1 error, prefixed `round N:`; a
    cross-ladder pair is refused, naming the two rounds; an unpinned (`v1`)
    artifact proceeds with a note. Dispatcher + `USAGE` wired.
  - **Not a flag on `coherence-trend`.** v18 Part XVI deferred a
    `coherence-trend --with-shift` flag precisely to keep that command
    single-purpose (one gate, one hash). v19 honors that: it is a separate
    command whose single purpose is the combined view, with its own single gate
    and its own single hash. The two single-axis commands are byte-for-byte
    unchanged in output and goldens.
  - **Tests (+17).** Arc identity disk-vs-in-memory; front-for-front join against
    the two single-axis trajectories; component-hash equality (the arc's
    `trajectory_hash`/`shift_trajectory_hash` equal the two commands' output
    byte-for-byte, cross-checked end-to-end); combined-gate parity
    (`= trajectoryRegressed || shiftTrajectoryFractured`); floor-only trip
    (regress while the package stays aligned); shift-only trip (fracture while the
    floor holds flat); both-quiet no-trip; determinism; ≥2-artifact requirement;
    cross-ladder refusal across the sequence (naming both rounds); unpinned-`v1`
    note; tamper rejection (round-prefixed); flat-and-stable front omitted from
    the summary. Every existing command's suite passes unchanged.

### Changed
- Nothing in existing behavior. v19 is purely additive — a new subcommand and one
  pure module that composes two existing pure functions; **no existing source
  file's behavior changes.** Every existing surface (`analyze`, `diff`, `compare`,
  `compare-coherence`, `coherence-trend`, `coherence-shift-trend`, `verify`) is
  byte-for-byte unchanged in output and goldens.

## [9.15.0] — 2026-06-15 — Document-free coherence-shift trajectory (spec-v18)

### Added
- **A `coherence-shift-trend` headless subcommand — the fracture/reconcile
  companion to v17's floor trajectory — that walks the same N ≥ 2 saved coherence
  artifacts and reports each front's *agreement* path across the whole
  negotiation (spec-v18, building v17 Part XVII open question #2).** v17's
  `coherence-trend` answers "did each front's binding *floor* climb, slide, or
  whipsaw?" — but the floor was never the only signal. Since v13, every
  cross-document movement has carried a second axis: did the package **fracture**
  (documents that agreed now disagree) or **reconcile** (a divergent front closed
  up)? A bundle can hold its floor steady while quietly fracturing, and that
  fracture is what a deal lead reconciling a multi-document package needs to see.
  v16/v17 archived each round's coherence kind but classified the trajectory on
  the floor only; v18 classifies the trajectory on that second axis.
  - **The classifier (pure).** `src/report/coherence-shift-trajectory.ts` —
    `compareCoherenceShiftTrajectory(rounds)` matches fronts by dimension across
    the union of all N coherences (pinned by `localeCompare`), builds each front's
    coherence kind at every round, classifies each consecutive step with the
    shared v13 `classifyShift` (now **exported** from `coherence-movement.ts` — no
    behavior change), computes the **net** shift (round 1 → round N), and reduces
    the steps to a `CoherenceShiftTrajectoryKind`: `steady-fracture` (≥1 fractured,
    0 reconciled steps) · `steady-reconcile` (≥1 reconciled, 0 fractured) ·
    `oscillating` (both directions — split apart and re-merge) · `stable` (no
    directional shift — a realign-only or appear-only front is `stable`, never a
    false oscillation, per §3 honesty). Carries a `shift_trajectory_hash`
    namespaced apart from every `coherence_hash`/`movement_hash`/`trajectory_hash`.
    `shiftTrajectoryFractured` is the gate predicate — true when any front is
    `steady-fracture` or `oscillating` (the package fractured at *some* step), the
    fracture/reconcile companion to v17's `trajectoryRegressed`.
  - **The command.** `tools/cli/coherence-shift-trend.ts` —
    `compareCoherenceShiftTrendArtifacts(texts, format?)` is the pure CLI core: it
    verifies all N artifacts and runs the v15/v16 cross-ladder guard across the
    whole sequence via the shared loader, then computes and renders the shift
    trajectory (markdown summary or `--format json`,
    `schema: vaulytica.posture-shift-trajectory.v1`). `runCoherenceShiftTrend`
    does the file IO and exit codes; `--fail-on-fracture` exits 2 when the package
    fractured at any round. A tampered round (errors prefixed `round N:`) or a
    cross-ladder pair (naming both rounds) is a hard exit-1 error.
  - **A shared sequence loader.** `tools/cli/coherence-sequence.ts` —
    `verifyCoherenceSequence(texts)` factors the parse + hash-verify +
    cross-ladder guard out of `coherence-trend.ts` so both trend commands share
    one verified-input path; `coherence-trend`'s output, errors, and exit codes
    are unchanged (its full test suite passes as-is).
  - **End-to-end demonstration.** A package that goes `aligned → divergent →
    aligned` across three rounds reads `net unchanged` (a first-vs-last diff hides
    the mid-deal fracture), but `coherence-shift-trend` classifies it
    `oscillating` and `--fail-on-fracture` exits 2 — the fracture/reconcile analog
    of v17's whipsaw gate.

### Unchanged (the five promises, re-verified)
- Deterministic (`shift_trajectory_hash` reproducible from the N artifacts on any
  machine), no AI, no server (N local files in, one summary out), citable (the
  artifacts carry v12's per-front coherence kinds — v18 adds no new claim), never
  drafts. Purely additive: a new subcommand and one pure module, plus a
  behavior-preserving loader extraction. Every existing command's output and
  golden is byte-for-byte unchanged; `coherence-movement.ts` changes only by
  exporting an existing function. Tests: **3,051** (was 3,035 — +16 across the new
  module and CLI suites).

## [9.14.0] — 2026-06-15 — Document-free coherence trajectory (spec-v17)

### Added
- **A `coherence-trend` headless subcommand that walks N ≥ 2 saved coherence
  artifacts and reports each front's binding-floor trajectory across the whole
  negotiation (spec-v17, building v16's explicitly-deferred sequence walker into
  the command that adds the signal pairwise diffs cannot).** v16's
  `compare-coherence` answers "round 3 → round 4." It cannot answer the question
  a deal lead asks across a long negotiation: *did the cap's binding floor climb
  steadily, erode steadily, or whipsaw — dip below floor mid-deal and recover?*
  A first-vs-last diff reports a recovered dip as `unchanged` and hides it; N−1
  independent pairwise diffs never say "this front moved in both directions
  across the deal." v17 walks the sequence as one object and classifies each
  front's path — the same relationship v11's trajectory has to v10's snapshot.
  - **The classifier (pure).** `src/report/coherence-trajectory.ts` —
    `compareCoherenceTrajectory(rounds)` matches fronts by dimension across the
    union of all N coherences (pinned by `localeCompare`), builds each front's
    floor and coherence kind at every round, classifies each consecutive step
    with the shared v11/v13 `classifyFloorMovement` (now **exported** from
    `coherence-movement.ts` — no behavior change), computes the **net** movement
    (round 1 → round N), and reduces the steps to a `FloorTrajectoryKind`:
    `steady-improvement` (≥1 improved, 0 regressed steps) · `steady-regression`
    (≥1 regressed, 0 improved) · `whipsaw` (both directions) · `flat` (no ranked
    movement — an appear-only or drop-only front is `flat`, never a false
    whipsaw, per §3 honesty). Carries a `trajectory_hash` namespaced apart from
    every `coherence_hash`/`movement_hash`. `trajectoryRegressed` is the gate
    predicate — true when any front is `steady-regression` or `whipsaw` (the
    floor regressed at *some* step), the faithful multi-round generalization of
    v13's `coherenceRegressed`.
  - **The command.** `tools/cli/coherence-trend.ts` —
    `compareCoherenceTrendArtifacts(texts, format?)` is the pure CLI core: it
    verifies all N artifacts (a tampered/corrupt round is a hard error, prefixed
    `round N:`), runs the v15/v16 cross-ladder guard across the **whole sequence**
    (any two ladder-pinned rounds with differing pins → refused, naming both
    rounds; any unpinned round → proceeds with a note), computes the trajectory,
    and renders the markdown summary (default) or its structured JSON
    (`schema: vaulytica.posture-trajectory.v1`). `runCoherenceTrend` is the
    handler: file IO + exit codes. Requires ≥ 2 artifacts (a single coherence has
    no trajectory). `--fail-on-coherence-regression` exits 2 on a floor that
    regressed at **any** step — strictly stronger than a first-vs-last diff, so a
    transient below-floor dip trips the gate even when the front recovered. The
    disk-sequence trajectory is byte-identical to the in-memory one (proven by
    test).
  - **Additive.** A brand-new subcommand + one pure module — every existing
    command (`analyze`, `diff`, `compare`, `compare-coherence`, `verify`) and
    every golden is byte-for-byte unchanged; `coherence-movement.ts` changes only
    by *exporting* an existing private function. No new posture math and no new
    on-disk format: the trajectory stays derived, recomputed on demand from the N
    auditable, ladder-pinned, hash-verified coherence inputs. 15 new tests
    (whipsaw detection, steady-improvement/regression, flat-on-appear-only,
    determinism, ≥2-artifact requirement, cross-ladder refusal naming both rounds,
    unpinned-v1 note, round-prefixed tamper rejection, gate-predicate parity).
    Suite 3,020 → 3,035.

## [9.13.0] — 2026-06-15 — Document-free coherence movement (spec-v16)

### Added
- **A `compare-coherence` headless subcommand that diffs two saved coherence
  artifacts with no documents on either side (spec-v16, building v14 Open
  Question #2 / the v15 "recompute from two coherence artifacts" deferral into
  the command that does it).** v14 let round one emit its coherence so round two
  could gate without round one's documents on disk — but round two still
  re-analyzed *its own* documents. v16 removes the documents from **both** sides:
  archive each round's kilobyte coherence artifact (from `analyze --posture
  --emit-coherence`), then `vaulytica compare-coherence round1.coherence.json
  round2.coherence.json` shows or gates the round-over-round binding-floor
  movement from the archive alone — no clause text, no re-ingestion, no engine
  run. The use case is a dashboard or audit log that stores each negotiation
  round's coherence and shows the delta without re-analysis.
  - **The command.** `compareCoherenceArtifacts(baseText, revisedText, format?)`
    is the pure, IO-free core: it verifies both artifacts via
    `parsePostureCoherenceJson` (a tampered/corrupt side is a hard error, prefixed
    `base:`/`revised:`), runs the spec-v15 cross-ladder guard **between the two
    artifacts** (both ladder-pinned + equal → verified; both pinned + different →
    refused; either unpinned → proceeds with a note), then diffs them with the
    same pure `compareCoherence` the `--baseline-coherence` path uses and renders
    the v13 movement summary (`--format markdown`, default) or its structured
    JSON (`--format json`). `runCompareCoherence` is the handler: file IO + exit
    codes. `--fail-on-coherence-regression` exits 2 when any front's binding
    floor regressed to a strictly worse stated rung — the same gate contract
    `analyze --fail-on-coherence-regression` ships, now over two artifacts. The
    disk-artifact movement is byte-identical to the in-memory diff (proven by
    test).
  - **Additive.** A brand-new subcommand — every existing command (`analyze`,
    `diff`, `compare`, `verify`) and every golden is byte-for-byte unchanged. No
    new posture math and no new on-disk format: the movement stays derived,
    recomputed on demand from the two auditable, ladder-pinned, hash-verified
    coherence inputs.

### Changed
- `renderCoherenceMovementSummary` moved from `tools/cli/run.ts` to
  `src/report/coherence-movement.ts` (beside its `buildCoherenceMovementJson`
  sibling) so both the `analyze --baseline*` path and `compare-coherence` render
  the movement from one definition with no cross-import between sibling CLI
  modules; `run.ts` re-exports it, so existing importers are unaffected.

## [9.12.0] — 2026-06-15 — Ladder-pinned coherence baselines (spec-v15)

### Added
- **A cross-ladder guard for saved coherence baselines (spec-v15, resolving
  spec-v14 Open Question #1 and the Part XVI "Cross-ladder verification"
  deferral).** v14 made the saved coherence artifact hash-verified for
  *integrity* (a tampered baseline is a hard error). But integrity is not
  identity: nothing stopped a team from gating round two against a baseline
  emitted under a **different playbook ladder**, producing a regression gate
  driven by a movement computed over two unrelated ladders. v15 closes that
  hole — the artifact now fingerprints the ladder its rungs sit on, and the
  consume path refuses a ladder mismatch.
  - **Thrust A — the ladder fingerprint (engine).** `ladderHash(playbook)` in
    `custom-interpreter.ts` is a stable SHA-256 over exactly what determines a
    tier: each negotiation position's `dimension` and its `ideal`/`acceptable`
    predicates (sorted by dimension, machine-independent), plus the named
    `thresholds` those predicates may reference. Per-tier `guidance` is
    **excluded** — advisory negotiation text never changes a document's tier, so
    re-wording it must not invalidate an archived baseline. A playbook with no
    `negotiation_positions` has no ladder and hashes to `null`.
  - **Thrust B — the pinned artifact + guard (headless).** A new
    `vaulytica.posture-coherence.v2` artifact (`COHERENCE_ARTIFACT_SCHEMA_V2`)
    carries a `ladder_hash` alongside the v14 fields. `buildPostureCoherenceJson`
    gained an optional ladder-hash argument: pass it and the artifact is a pinned
    `v2`; omit it and the bytes are byte-identical to v14's `v1`. The
    `ladder_hash` is **independent of `coherence_hash`** (which still covers
    `dimensions` only), so the v1 and v2 artifacts of one coherence share the
    same integrity hash. `parsePostureCoherenceJson` accepts both schemas,
    requires `ladder_hash` on `v2`, rejects a stray `ladder_hash` on `v1`, and
    returns `ladderHash: string | null`. The CLI `--emit-coherence` now pins the
    ladder automatically (the ladder is always present — it requires
    `--posture`/`--playbook-file`); `--baseline-coherence` computes this round's
    `ladderHash` and **refuses with exit 1** on a mismatch
    (`ladder mismatch — the artifact was computed against a different playbook
    ladder …`). A `v1` (unpinned) artifact still loads, with a clear note that
    cross-ladder verification is unavailable (v14's caller-owns-it contract).
  - **Additive.** No ladder hash ⇒ a `v1` artifact byte-identical to v14; the
    parser still accepts `v1`; every existing golden, round-trip, and the
    `compareCoherence`/`coherenceRegressed` math are unchanged. With neither emit
    nor consume flag the CLI is unchanged from v14.

### Changed
- The `analyze` command's `USAGE`/help text now lists `--emit-coherence`,
  `--baseline-coherence`, and the `--baseline`/`--baseline-coherence` mutual
  exclusion (they were wired in v14 but missing from the help block).

## [9.11.0] — 2026-06-14 — Saved coherence baselines (spec-v14)

### Added
- **A portable, hash-verified cross-document posture coherence artifact
  (spec-v14, resolving spec-v13 Open Question #2).** A deal lead can now gate
  round two of a negotiation against round one **without round one's documents
  on disk**. Round one emits its coherence once; round two diffs against the
  saved artifact. The diff is the same pure `compareCoherence` v13 ships — only
  the *source* of the baseline coherence changes.
  - **Thrust A — the artifact (engine).** `buildPostureCoherenceJson(coherence)`
    serializes a `PostureCoherence` to stable, pretty-printed JSON tagged
    `vaulytica.posture-coherence.v1` (the `coherence_hash`, the per-kind
    `counts`, and the full per-front, per-document rung set, in the pinned
    document order). `parsePostureCoherenceJson(text)` is the verifying inverse:
    it structurally validates the file, **re-derives the `coherence_hash` from
    the artifact's own dimensions**, and rejects any mismatch — a corrupted,
    truncated, or hand-edited baseline is a hard, legible error
    (`coherence_hash mismatch …`), never a silent gate input. `counts` is
    recomputed from the verified dimensions on load (the hash covers dimensions
    only). The fingerprint is factored into a single `coherenceHash` helper used
    both to stamp (in `bundlePostureCoherence`) and to verify (in the parser).
  - **Thrust B — emit & consume (headless).** `analyze --posture
    --emit-coherence <path>` writes the round's coherence artifact (a clear
    stderr note, not a silent no-op, when the round yields no cross-document
    coherence). `analyze --posture --baseline-coherence <coherence.json>` diffs
    against a saved, verified coherence instead of re-analyzing a baseline
    bundle (mutually exclusive with `--baseline`). `--fail-on-coherence-regression`
    now accepts **either** baseline source; the exit-2 regressed-binding-floor
    gate is unchanged.
  - **Additive.** Both flags are off by default — with neither set the CLI is
    byte-identical to v13, so every per-document `result_hash`, `coherence_hash`,
    `movement_hash`, and golden is byte-unchanged. A browser/DOCX surface is a
    principled deferral (the artifact is a CI/headless concern; the browser
    already does an in-session two-round comparison via v13 Thrust B).
  - **+8 tests** (suite 2,992 → 3,000 passing + 2 skips): seven coherence-artifact
    unit tests (round-trip identity, hash integrity, tamper rejection,
    wrong-schema rejection, malformed-JSON/non-object rejection, invalid
    tier/kind rejection, count recomputation) and one CLI integration test
    proving a disk-round-tripped coherence yields the same `movement_hash` as the
    in-memory `--baseline` diff. New [`docs/spec-v14.md`](docs/spec-v14.md).

## [9.10.1] — 2026-06-13 — Mobile overflow hardening (download status + uncovered-state line)

### Fixed
- **Long, space-free filenames no longer push the result card past the viewport
  on a narrow phone.** The post-download status line (`.download-status`) is
  filled by `saveBlob` with `Saved <filename>`, where the filename derives from
  the user's upload — names like
  `Master_Services_Agreement_..._FINAL_v12_executed.pdf` have no break
  opportunities. The element lacked `overflow-wrap`, so on a 320px screen the
  status text widened the card and reintroduced horizontal scroll (a regression
  the static-render `responsiveness-states` e2e never caught, since it renders
  states before any download has populated the line). Added
  `overflow-wrap: anywhere` to `.download-status`, and a dedicated e2e that
  injects the worst-case `Saved <long-filename>` text and re-asserts
  vertical-scroll-only at 320 / 390 / 768 / 1280px.
- **Jurisdiction "no overlay on file" line now wraps.** `.overlay-uncovered`
  (the honest coverage-gap sentence listing uncovered states) gained the same
  `overflow-wrap: anywhere` guard for safety against long state lists.

## [9.10.0] — 2026-06-13 — Cross-document posture movement in the browser + DOCX (spec-v13 Thrusts B & C)

### Added
- **Browser two-round bundle comparison (spec-v13 Thrust B, Step 190).** The
  bundle-complete view grows a "Compare a revised round…" affordance — offered
  only when the round produced a posture coherence (a positions-bearing custom
  playbook was active), exactly as v11's compare row is offered only on a single
  document. Picking the revised round's files re-analyzes them against the
  **same** active playbook, computes its v12 coherence, diffs it against the
  baseline round's via `compareCoherence`, and transitions to a new
  `bundle-comparison-complete` state. The state renders a mobile-safe per-front
  card: the left border reuses the v11 `pm-*` direction palette for the
  binding-floor movement (`Floor improved` / `Floor regressed` / …), and a
  `cm-shift-*` text color names the coherence shift (`Fractured` / `Reconciled` /
  `Realigned`). A floor transition line (`acceptable → below floor`) and the
  coherence-kind transition ride alongside. Advisory throughout — it reports
  where the binding floor that governs exposure moved on the team's own ladder,
  never a legal conclusion or which document legally governs.
- **Two-round deliverable DOCX + JSON (spec-v13 Thrust C, Step 191).** The
  comparison state offers a "Download two-round report (Word)" — the revised
  round's consolidated bundle DOCX with a trailing "Posture Movement (Across the
  Package)" section ([`src/report/bundle.ts`](src/report/bundle.ts)
  `renderPostureMovementSection`): one row per front (Front · Floor movement ·
  Binding floor base→revised · Coherence shift), color-coded by the binding-floor
  movement and carrying the `movement_hash` for verification. A structured
  movement JSON (`buildCoherenceMovementJson`) rides alongside as a second
  download. Both the DOCX section and the JSON are **additive** — threaded only
  when the two-round flow supplies a movement, so every existing per-document
  `result_hash`, `coherence_hash`, and bundle golden is byte-unchanged.

### Quality
- The new `bundle-comparison-complete` view-state is registered in the
  full-`DropzoneState` responsiveness + axe e2e (`responsiveness-states.spec.ts`):
  vertical-scroll-only at 320 / 390 / 768 / 1280 px and zero WCAG 2 AA violations
  in both the dark and light themes. The `cm-shift-*` foreground colors are
  theme-aware (the reconciled green darkens on the light surface) so they clear
  the 4.5:1 contrast floor on each theme.

### Notes
- spec-v13 is now complete end-to-end (Thrust A 9.9.0; Thrusts B & C 9.10.0).
  The fourth corner of the posture matrix — across documents, across versions —
  now has a headless surface, a CI gate, a browser card, and a Word deliverable,
  matching how v10–v12 each landed.

## [9.9.0] — 2026-06-13 — Cross-document posture movement (spec-v13 Thrust A)

### Added
- **Cross-document posture-movement engine (spec-v13 Thrust A, Step 187).** A new
  pure module [`src/report/coherence-movement.ts`](src/report/coherence-movement.ts)
  exports `compareCoherence(base, revised)`: given two v12 `PostureCoherence`
  objects — a deal package at a **base** round and at a **revised** round, both
  classified against the **same** team positions — it reports, per negotiation
  front (matched by **dimension**, not by document, so a `msa-v1.docx` →
  `msa-v2.docx` rename or an added document never confuses it), how the bundle's
  **binding floor** moved (`improved` / `regressed` / `unchanged` /
  `newly-stated` / `now-unstated`, reusing v11's exported `TIER_RANK`) and how
  the **coherence kind** shifted (`fractured` / `reconciled` / `realigned` /
  `unchanged`). Floor- and shift-count tallies and a `movement_hash` namespaced
  apart from every `result_hash`, `posture_hash`, and `coherence_hash`. A
  `coherenceRegressed(movement)` predicate mirrors v11's `postureRegressed` and
  v12's `hasDivergence`. This is the fourth corner of the posture matrix —
  v10 (single doc, single version), v11 (single doc, across versions), v12
  (across docs, single version), v13 (across docs, across versions).
- **Headless cross-round movement (spec-v13 Thrust A, Step 188).** The CLI
  [`analyze`](tools/cli/run.ts) command accepts `--baseline <path|glob|dir>`
  (requires `--posture`): it analyzes the baseline bundle against the **same**
  custom playbook, computes its v12 coherence, diffs it against the primary
  bundle's coherence via `compareCoherence`, and prints a "Cross-document posture
  movement (vs. baseline)" summary — the floor- and shift-count lines, one line
  per front whose floor moved or whose package fractured/reconciled (an unmoved
  front is omitted), and the `movement_hash`. A baseline that yields no coherence
  (fewer than two documents with a posture) is a hard error, not a silent no-op.
- **Coherence-regression CI gate (spec-v13 Thrust A, Step 189).** The CLI
  `analyze` command accepts `--fail-on-coherence-regression` (requires
  `--baseline`): it exits non-zero (code 2) when any front's binding floor moved
  to a strictly worse **stated** rung between the two rounds. The gate is the
  well-ordered floor worsening only; a front that dropped off the ladder
  (`now-unstated`) is reported but never trips it (spec-v13 §3 corollary 2 — a
  dropped front is not conflated with a rung regression; a team that wants to
  gate on it composes from `floor_counts`). Reported alongside `--fail-on` and
  `--fail-on-divergence`; any tripping sets exit 2.

### Notes
- Additive and back-compatible: an `analyze` run with no `--baseline` yields no
  movement, so every per-document `result_hash`, every `posture_hash`, every
  `coherence_hash`, and every bundle golden is byte-identical to 9.8.0.
- The movement is **advisory** (spec-v13 §3): it reports where the bundle's
  binding floor moved on the team's own ladder and whether the package fractured
  or reconciled — never that a term became legally adequate or enforceable, and
  never which document legally governs on a conflict (the v12 §3 corollary-3
  bright line, carried forward).
- Thrust B (a browser-UI two-round bundle card) and Thrust C (a DOCX section) are
  proposed (Steps 190–191); both wait on a two-bundle comparison surface that
  does not yet exist in the browser UI.

## [9.8.0] — 2026-06-13 — Posture coherence in the browser bundle + bundle DOCX (spec-v12 Thrusts B & C)

### Added
- **Per-document posture through the browser bundle pipeline (spec-v12 Thrust B,
  Step 184).** [`prepareBundle`](src/ui/pipeline.ts) now evaluates a v10
  negotiation posture for each document in a bundle when the active custom
  playbook defines `negotiation_positions` — every document classified against
  the **same** positions, independent of the matched built-in playbook that
  drives its per-document engine run (which is untouched). The postures ride on
  `BundlePerDocument.negotiation_posture` (their own `posture_hash`, outside
  every `result_hash`). [`runBundleReport`](src/ui/pipeline.ts) collects them and
  computes a [`bundlePostureCoherence`](src/report/posture-coherence.ts) when
  every document carries one (a bundle is always ≥2 documents).
  [main.ts](src/ui/main.ts) threads the active custom playbook into
  `runBundlePipeline` so the bundle path sees the positions.
- **Bundle-complete "Posture coherence" card (spec-v12 Thrust B, Step 185).** The
  bundle-complete UI state renders a mobile-safe coherence card: the per-kind
  counts (aligned / divergent / stated-by-one / unstated), one card per
  negotiation front showing the rung spread across the documents and the
  **binding floor** (the weakest stated rung + the document carrying it),
  color-coded by a `pc-*` left border (green aligned, red divergent, blue
  stated-by-one, grey unstated) reusing the v10 `np-*` overflow-wrap styles.
  Hidden when no coherence was computed. Verified vertical-scroll-only across
  320–1280px with zero axe WCAG 2 AA violations in both themes.
- **Consolidated bundle DOCX "Posture Coherence" section (spec-v12 Thrust C,
  Step 186).** [`buildBundleDocxReport`](src/report/bundle.ts) renders a trailing,
  optional "Posture Coherence" section: the per-kind counts + a color-coded table
  (Front · Coherence · per-document rung · binding floor). Omitted entirely when
  no `posture_coherence` is supplied, so every existing bundle golden is
  byte-unchanged. Advisory — it names the weakest document but never adjudicates
  which document legally governs on a conflict (spec-v12 §3 corollary 3).

### Notes
- Additive and back-compatible: a bundle run with no active posture playbook
  yields no coherence, so the bundle JSON, the consolidated DOCX, and every
  per-document `result_hash` and bundle golden are byte-identical to 9.7.0.
- In the bundle path the custom playbook contributes **only** its posture
  positions; the per-document engine run is still driven by each document's
  matched built-in playbook, and secondary-family activation continues to run
  for every bundled document (the single-doc "custom mode redefines rule
  semantics" skip does not apply here, since the custom playbook does not drive
  the bundle's engine run).

## [9.7.0] — 2026-06-13 — Cross-document posture coherence (spec-v12 Thrust A)

### Added
- **Cross-document posture coherence engine (spec-v12 Thrust A, Step 181).** A
  new pure module [`src/report/posture-coherence.ts`](src/report/posture-coherence.ts)
  exports `bundlePostureCoherence(documents)`: given one v10 `NegotiationPosture`
  per document — all classified against the **same** team positions — it reports,
  per negotiation front, whether the documents **agree** on the rung (`aligned`),
  **disagree** (`divergent`), are stated by only one (`single`), or stated by
  none (`unstated`). For every stated front it surfaces the **binding floor** —
  the weakest stated rung and the document(s) carrying it — since in a deal
  package the weakest document usually governs exposure. It reuses v11's now-
  exported `TIER_RANK` (so the rung order has one source of truth) and carries
  its own `coherence_hash`, namespaced apart from every document's `result_hash`
  and the bundle fingerprint. `unevaluable` stays unranked: an unstated front is
  never folded into a divergence and never lowers the floor (the spec-v10 §3
  honesty contract). A `hasDivergence(coherence)` predicate mirrors v11's
  `postureRegressed`.
- **Headless coherence over a bundle (spec-v12 Thrust A, Step 182).** The CLI
  `analyze` command, run with `--posture` over a bundle (a directory or glob
  resolving to ≥2 documents), now collects each document's posture and prints a
  "Cross-document posture coherence" summary after the per-document lines: the
  per-kind counts, one ⚠ line per divergent front (the rung spread + the binding
  floor + the document carrying it), and the `coherence_hash`. A single-document
  run emits no coherence (nothing to compare). The per-document JSON/SARIF/HTML
  is unchanged — the coherence is an additive bundle-level summary.
- **Divergence CI gate (spec-v12 Thrust A, Step 183).** The `analyze` command
  gains `--fail-on-divergence` (requires `--posture`): it exits non-zero (code 2)
  when any front is **divergent** — two or more documents stating the same front
  on different rungs. Per the §3 honesty contract the gate is the well-ordered
  spread only: a front only one document states (`single`) or no document states
  (`unstated`) is reported but never trips it. Reported alongside `--fail-on`;
  either tripping sets exit 2.

### Tests
- +15 tests: the coherence engine (every kind, the binding floor, `unevaluable`
  never ranked as the floor, determinism, document-order sensitivity, the
  single-document case, and the `hasDivergence` predicate — 13 tests) and the CLI
  `renderCoherenceSummary` (the counts line, ⚠ only for divergent fronts, the
  `coherence_hash` — 2 tests).

### Docs
- New [`docs/spec-v12.md`](docs/spec-v12.md) — Cross-Document Posture Coherence,
  the v4 cross-document axis of the v10 posture (sibling to v11's version axis).
  Thrust A shipped; the browser-UI bundle card and consolidated-DOCX section are
  proposed as Thrusts B/C (the bundle pipeline does not yet compute per-document
  postures).

## [9.6.0] — 2026-06-13 — Posture-movement CI regression gate (spec-v11 Thrust C)

### Added
- **Posture-movement regression gate (spec-v11 Thrust C, Step 180).** The
  headless `compare` command gains `--fail-on-regression` (requires `--posture`):
  it exits non-zero (code 2) when the posture movement holds any **regressed**
  dimension — a front that moved to a strictly worse rung on the team's own
  ladder. This turns the advisory movement into a hard CI gate, exactly as
  `--fail-on <sev>` does for the introduced-finding bucket; either tripping sets
  exit 2. Per the §3 honesty contract, the gate is the well-ordered rung
  worsening only: `now-unstated` (a term that dropped off the ladder) is reported
  but never trips it — a dropped front is not conflated with a rung regression. A
  team that wants to gate on a dropped term composes it from the JSON
  `posture_movement.counts`. A small exported `postureRegressed(pm)` predicate
  mirrors `introducedBreaches` for testability.

### Tests
- +6 tests: `--fail-on-regression` arg parsing (parses with `--posture`; rejected
  without it; defaults off) and the `postureRegressed` predicate (trips on a
  strict rung worsening; does not trip on improvement / unchanged / newly-stated;
  does not trip on now-unstated).

## [9.5.0] — 2026-06-13 — Posture movement in the Word comparison report (spec-v11 Thrust B)

### Added
- **Posture movement in the Word comparison report (spec-v11 Thrust B, Step
  179).** [`buildComparisonDocx`](src/report/compare-docx.ts) now renders a
  "Posture Movement" section into the DOCX comparison deliverable — the document
  a negotiator hands to a partner. It carries an advisory headline (the movement
  counts), the `movement_hash` for auditability, and a per-dimension table
  (Dimension · Movement · Base · Revised) with the movement cell color-coded
  (green improved / red regressed / amber dropped), reusing the single-document
  posture table's visual contract. The `PostureMovement` is threaded as a
  trailing optional argument (the v9/v10 surface-threading pattern), so the
  section is omitted when no movement is supplied and the page flow plus every
  existing comparison golden are unchanged. (The comparison deliverable is DOCX +
  JSON; there is no standalone-HTML *comparison* report, so Thrust B is DOCX-only
  by construction.)

### Tests
- +2 tests: the section renders every transition (improved / regressed /
  newly-stated / now-unstated), the `movement_hash`, and the short rung labels;
  it is omitted when no movement is supplied.

## [9.4.0] — 2026-06-13 — Negotiation posture movement (spec-v11 Thrust A)

### Added
- **Negotiation posture movement (spec-v11 Thrust A, Steps 176–178).** Extends
  the v10 Negotiation Posture along the v6 version-comparison axis: it reports
  how a team's posture *moved* between two drafts. When a counterparty sends a
  revised draft, the comparison now answers the round-over-round question —
  *which way did each front move?* — without a model and without a server. Fully
  additive: a comparison with no positions yields no movement, and the movement
  carries its own `movement_hash` namespaced apart from the comparison
  `result_hash`, so no existing golden or hash moves.
  - **Movement engine** (Step 176) — `comparePosture(base, revised)`
    ([`src/report/posture-movement.ts`](src/report/posture-movement.ts)): a pure,
    deterministic per-dimension transition classifier — **improved · regressed ·
    unchanged · newly-stated · now-unstated** (plus defensive *appeared /
    disappeared* for mismatched position sets). A single `TIER_RANK` table
    (ideal > acceptable > below-acceptable) decides improved vs. regressed;
    `unevaluable` is deliberately **unranked**, so "not stated" is never compared
    as better or worse than a stated rung — a counter that *adds* a below-floor
    term reads as `newly-stated`, never a false `regressed`.
  - **JSON + tab** (Step 177) — an additive `posture_movement` block in the
    comparison JSON (`buildComparisonJson`, trailing optional argument), and a
    mobile-safe "Posture movement" card in the comparison-complete tab (reuses
    the v10 `np-*` overflow-wrap styles + `pm-*` direction colors). The UI threads
    the base posture and the active custom playbook through `runComparison`, so
    the revised draft is classified against the *same* ladder as the base.
  - **Headless movement** (Step 178) — the CLI `compare` command accepts
    `--playbook-file <path>` + `--posture` (mirroring `analyze`): it classifies
    both drafts against the playbook's `negotiation_positions` and emits a
    `posture_movement` JSON block (or a Markdown table) — a CI redline gate can
    now show how each negotiation front moved between two versions.
- **Docs.** New [`docs/spec-v11.md`](docs/spec-v11.md); README gains a "Posture
  movement" section (with a movement-kind cheat sheet and a Mermaid diagram), a
  v11 row in the version table, and a CLI cheat-sheet entry; the threat model
  notes the new advisory surface.

### Tests
- +17 tests (2,922 → 2,939): the full movement-transition matrix, determinism of
  `movement_hash` (order-independent), the additive comparison-JSON block, CLI
  arg parsing (`--posture` requires `--playbook-file`) and Markdown rendering;
  the comparison-complete responsiveness e2e fixture gains an overflow-prone
  posture-movement card (vertical-scroll-only 320–1280px, WCAG 2 AA, both themes).

## [9.3.0] — 2026-06-13 — Negotiation posture: dimension breadth (spec-v10 Thrust C)

### Added
- **Negotiation posture — dimension breadth (spec-v10 Thrust C, Steps 173–175).**
  Widens the set of negotiable dimensions a `negotiation_position` (or any
  `custom_rule`) can assert on, each **measure-first**: wired only behind an
  extractor fixture proving the extraction is reliable on representative clause
  prose, never guessed. Fully additive — a playbook that does not use the new
  dimensions validates and runs exactly as before; no golden or `result_hash`
  moves.
  - **Temporal metrics** (Step 173) — two new `numeric_threshold` metrics:
    `cure_period_days` (the cure window for a breach) and
    `auto_renewal_notice_days` (the non-renewal notice window), both routed
    through the same `extractMetricValues` path the v6 metrics use.
  - **Financial metrics** (Step 174) — `indemnity_cap_amount` (indemnification
    cap as an absolute amount) and `uptime_sla_percent` (a service-level
    uptime/availability commitment, in percent).
  - **Mutuality predicate** (Step 175) — a new `clause_mutual` predicate kind:
    *is the indemnification / termination / confidentiality clause **mutual** or
    one-way?* It reuses the v6 `findClause` locator (`clause` anchors the
    default location; an explicit `pattern`/`section_heading` overrides it) and
    adds a bounded, deterministic reciprocity-marker scan — no model, no fuzzy
    logic. A located clause carrying "each party" / "both parties" / "mutual" /
    "respective" / … is mutual; one with none is reported one-way; a clause that
    is absent is honestly **unevaluable**, never a false "one-way" (§3 corollary
    2).
  - The published JSON Schema artifact ([`docs/v6/playbook.schema.json`](docs/v6/playbook.schema.json))
    mirrors the four new metrics and the seventh predicate kind, guarded by the
    schema-artifact test. The `acme-saas-buyer` example playbook gains three
    Thrust-C positions (cure period, uptime SLA, indemnification mutuality).
  - +18 tests (measure-first extractor fixtures for all four metrics across
    representative prose; `clause_mutual` compliant/one-way/unevaluable +
    pattern-override; Thrust-C posture ladders; the mutual-clause schema-enum
    guard). Suite 2,904 → 2,922. Version 9.2.0 → 9.3.0.

## [9.2.0] — 2026-06-13 — Negotiation posture: report & export (spec-v10 Thrust B)

### Added
- **Negotiation posture — report & export (spec-v10 Thrust B, Steps 170–172).**
  Deepens the v10 posture from a report *section* into the negotiator's actual
  worksheet, all render-side (**zero `result_hash` churn**):
  - **Standalone negotiation sheet** ([`src/report/negotiation-sheet.ts`](src/report/negotiation-sheet.ts),
    Step 170) — a self-contained, print-clean HTML sheet that regroups the
    positions by **action** rather than dimension: *escalate* (below floor) ·
    *push here* (at the floor) · *verify* (not stated) · *hold* (already ideal),
    in that priority order, so the most urgent fronts are at the top. Author
    strings are HTML-escaped; mobile-safe (an e2e asserts vertical-scroll-only
    at 320–1280px and zero WCAG 2 AA violations).
  - **Markdown + CSV posture export** ([`src/report/exports.ts`](src/report/exports.ts),
    Step 171) — `buildNegotiationPostureMarkdown` (a dimension · tier · finding ·
    guidance · section table) and `buildNegotiationPostureCsv` (RFC 4180 + the
    same formula-injection guard as the fix list, since a position's
    `dimension`/`guidance` is untrusted author text). Both download from the
    complete-state export row.
  - **Headless posture in the CLI** (Step 172) — `vaulytica analyze … --playbook-file <path>`
    loads and validates a custom playbook (a malformed file is a hard error with
    the validator's messages, never a silent no-op), and `--posture` evaluates
    its `negotiation_positions` against the document, printing a summary line
    (`Negotiation posture: N ideal, M acceptable, K below floor, J not stated`)
    and emitting the `negotiation_posture` JSON block — the same deterministic
    classification, in CI or a folder sweep. (Merging the playbook's custom
    *rules* into the headless run is a separate follow-up; `--posture` computes
    the posture only.)
  - +7 tests (Markdown/CSV structure + formula-injection guard; the sheet's
    action grouping + escaping + determinism; CLI posture via `analyzeFile`; the
    sheet responsiveness/a11y e2e). Suite 2,897 → 2,904. Version 9.1.0 → 9.2.0.

## [9.1.0] — 2026-06-13 — Negotiation Posture (spec-v10 Thrust A) + PDF annotations

### Added
- **Negotiation posture — the tiered-position ladder (spec-v10 Thrust A, Steps
  166–169).** Deepens the v6 bring-your-own-playbook axis from binary
  enforcement to a negotiation ladder. A custom playbook can now carry
  `negotiation_positions`: one entry per negotiable dimension, each an `ideal`
  and an `acceptable` predicate drawn from the **same** bounded v6 DSL the
  custom rules use, plus optional per-tier `guidance`. The engine reports which
  rung the draft meets — **ideal · acceptable · below-floor · not-stated** —
  classified **deterministically by the existing `evaluatePredicate`**, so
  there is no new fuzzy logic.
  - Schema: `negotiation_positions` on `CustomPlaybook` (Zod + the published
    [`docs/v6/playbook.schema.json`](docs/v6/playbook.schema.json) artifact),
    backward-compatible (optional field, `schema_version` unchanged). Validation
    rejects a tier clause predicate with neither `pattern` nor `section_heading`
    and a duplicate `dimension`; a posture-only `replace`-mode playbook is now
    valid.
  - Evaluator: `evaluateNegotiationPosture` ([`src/playbooks/custom-interpreter.ts`](src/playbooks/custom-interpreter.ts))
    — monotone (`ideal` strict, `acceptable` the floor); **below-floor only when
    both tiers are evaluable and both fail** (an unstated metric is honestly
    `unevaluable`, never a false walk-away — the v5/v6 honesty contract). Carries
    its own `posture_hash`, namespaced apart from the engine `result_hash`.
  - Surfaces: a `negotiation_posture` JSON block, a "Negotiation Posture"
    section in the DOCX and standalone HTML reports, and a mobile-safe
    "Negotiation posture" card in the complete-state tab — each shown only when
    the active custom playbook defined positions, so a position-free run renders
    identically to before. **Render-side, zero `result_hash` churn.**
  - Advisory, never a legal conclusion: a tier reports where the draft sits on
    the team's **own** ladder, never that a term is enforceable, adequate, or
    market.
  - +14 tests (tier classification across numeric / governing-law / clause
    ladders; schema validation; DOCX/HTML rendering + escaping; the e2e
    responsiveness stress fixture). The `saas-buyer` example playbook gains
    three worked positions. `docs/spec-v10.md` written. Suite 2,883 → 2,897.

- **PDF reviewer-annotation recovery in the pre-disclosure scan (spec-v9 §7).**
  Closes the last v9 Thrust-A deferral: the delivery scan's PDF path read only
  the Info-dictionary metadata and reported markup/comment recovery as a
  documented no-op. It now recovers **reviewer annotations** — sticky notes
  (`/Text`), free-text notes (`/FreeText`), and text markup (`/Highlight`,
  `/Underline`, `/StrikeOut`, `/Squiggly`) — from the **uncompressed** byte
  regions, surfacing each as a `CommentFact` (author from `/T`, a bounded
  excerpt from `/Contents`, literal or hex; a bare mark with no note reports its
  type, e.g. `[highlight]`), so `HANDOFF-002` now fires on a PDF carrying live
  reviewer markup, not just a DOCX. The parser reads the raw bytes (not pdf.js)
  to stay pure, bounded, and **ReDoS-free** (every regex linear; a search window
  clamped to the annotation's own object so a neighbouring object's fields are
  never pulled in); annotations or metadata inside a compressed object stream or
  an encrypted region are still not recovered, and the report's note now states
  that reach honestly rather than implying a clean bill. +4 tests (positive
  recovery, object-boundary isolation, pathological-blob totality/ReDoS guard,
  honest-note wording). Render-side / container-scoped — **zero `result_hash`
  churn**.

- **v9 output-surface completion — the Last Look surfaces now render in every
  report format.** Closes the two engineering-scoped deferrals documented at the
  9.0.0 release (spec-v9 Steps 153/159/163). The delivery (`HANDOFF-*`), closing
  checklist, and critical-dates surfaces previously rendered only in JSON / CLI /
  tab / Markdown / CSV / `.ics`; they now also render in the **DOCX** report, the
  standalone **HTML** report, and **SARIF** — all via a single optional
  `V9Surfaces` bundle ([`src/report/v9-surfaces.ts`](src/report/v9-surfaces.ts)),
  render-side, **zero `result_hash` churn** (each section is omitted when empty,
  so a document with no handoff facts / readiness gaps / derivable dates produces
  a byte-identical v8-era report):
  - **DOCX** — new "Clean to Send", "Ready to Sign — Closing Checklist", and
    "Critical Dates" sections (each a heading + table, omitted when empty).
  - **HTML** — the same three sections as bordered, mobile-safe card lists
    (every cell wraps; the standalone report still scrolls vertically only at
    320–1280px and clears WCAG 2 AA, verified by the deepened
    `html-report-responsive` e2e with overflow-prone v9 content).
  - **SARIF** — `HANDOFF-001…005` and `DATE-001…005` are now first-class SARIF
    `result`s with their own rule descriptors: handoff findings cite the
    container (no text region; `kind: "container"` logical location), derived
    deadlines surface at `note` level anchored to their section, and each carries
    its surface hash (`delivery_hash` / `critical_dates_hash`) as a
    `partialFingerprint` for cross-run dedupe. The output stays conformant
    (`sarifConformanceViolations` green). The closing checklist is a projection
    of findings already emitted, so it is intentionally **not** re-emitted as
    SARIF results.
  - Wired through `runReport` (one `V9Surfaces` bundle threaded into DOCX/HTML/
    SARIF) and the CLI `renderFormat` (`--delivery` / `--checklist` /
    `--critical-dates` now flow into `sarif`/`html` output, not just `json`).
  - +6 unit tests (html/sarif/docx structure + "byte-identical when absent")
    and the deepened HTML-report e2e. Suite 2,874 → 2,880.

## [9.0.0] — 2026-06-12 — The Last Look (spec-v9 complete)

### Added
- **Ready to Sign — execution-readiness reconciliation (spec-v9 Thrust B, Steps 155–159).**
  Deepens the `STRUCT-*` family from *detection* to *reconciliation* — three new
  always-on rules (launch set **112 → 115**), all internal-consistency only
  (they report the gap, never "validly executed"):
  - **`STRUCT-017` — signature-block completeness** (warning). Reconciles the
    declared contracting parties against the signature block and reports a
    declared party with no attributable line. Precision-first: fires only on a
    clearly multi-party-labeled block (`≥2` parties named) missing a further
    **corporate-suffix-named** party, dropping the defined-term / functional-role
    phantoms (`"Confidential Information"`, `"Receiving Party"`) the preamble
    extractor occasionally fabricates — **0 false positives across the
    341-fixture corpus**, while its unit tests prove it fires on the genuine
    "four-party agreement, three signature lines" case.
  - **`STRUCT-018` — attachment completeness** (warning). Reconciles every
    Exhibit / Schedule / Annex / Appendix / Attachment reference against the set
    present as a heading or title line, and reports referenced-but-absent (and
    present-but-unreferenced) attachments — the consolidated reconciliation view,
    distinct from `STRUCT-016`'s incorporation-risk lens.
  - **`STRUCT-019` — recited formalities** (warning). Where the document's own
    text recites notarization or witnessing, checks that the corresponding
    notary jurat / witness block is present. High precision; never asserts the
    formality is legally required.
  - **Closing Checklist** ([`src/report/closing-checklist.ts`](src/report/closing-checklist.ts)).
    Consolidates the readiness findings (`STRUCT-003`/`011`/`013`/`017`/`018`/`019`)
    and the send-readiness handoff items (`HANDOFF-001`/`002`) into one ordered,
    grouped artifact — Markdown and CSV exports, a JSON `closing_checklist` block,
    a CLI `--checklist` flag, and a tab "Ready to sign?" view. A render-side
    projection of findings the engine already produced; **zero `result_hash`
    churn** beyond the three new rules' mechanical execution-log re-baseline.
- **Tracked to Its Dates — the computed critical-dates register (spec-v9 Thrust C,
  Steps 160–164).** Turns the relative temporal terms the extractor already pulls
  into absolute, calendarable deadlines. New module
  [`src/report/critical-dates.ts`](src/report/critical-dates.ts):
  - **`deriveDate(reference, anchor)`** — pure calendar arithmetic, `anchor ± N
    {days|weeks|months|years}`, month-end-clamped (`Jan 31 + 1 month = Feb 28`)
    and leap-year-correct, proven by property tests (validity, monotonicity,
    month round-trip). Reads **no clock**. An undated anchor or a business-day
    count yields an **unresolved** "verify manually" item — never a guess. New
    additive `offset_unit` / `offset_count` / `offset_count_max` on
    `DateReference` carry the calendar unit the day-collapsed `offset_days` loses
    (extractor data, outside `result_hash` — zero golden churn).
  - **`DATE-001…005`** — auto-renewal notice, cure window, opt-out window,
    survival end, notice-period — classified from the clause context, with the
    responsible party drawn from the obligations extractor.
  - A canonically-sorted **register** with its own `critical_dates_hash`, a JSON
    `critical_dates` block, a deepened `.ics` (`buildCriticalDatesIcs`, with a
    render-only DISPLAY alarm on notice/opt-out/cure rows), a Markdown register
    (`buildCriticalDatesMarkdown`), a CLI `--critical-dates` flag, and a tab
    "Your calendar, computed" view.
  - **No-wall-clock metamorphic gate**
    ([`tests/integration/critical-dates-no-wallclock.test.ts`](tests/integration/critical-dates-no-wallclock.test.ts)):
    the same document under two different "today" values yields a byte-identical
    register, `critical_dates_hash`, `.ics`, and Markdown — only the *absolute*
    computed date is ever hashed; every relative-to-today view ("due in N days",
    "overdue", soonest-first) is render-only.
- **v9 close (Step 165).** [`docs/v9/README.md`](docs/v9/README.md) overview;
  threat-model Thrust B/C note; `RULE_TAXONOMY_VERSION` 7.0.0 → 9.0.0; spec-v9
  status table reconciled (all 18 steps shipped); README posture/test-count
  (2,829 → 2,874) and Thrust surface refresh. Version 8.1.0 → **9.0.0**.

### Notes
- The three new always-on `STRUCT-*` rules re-baseline the engine
  `result_hash` and `execution_log` mechanically across the golden corpus (355
  golden files regenerated). The new findings were audited to fire only on
  genuine readiness gaps; the regen is otherwise zero-judgment.

## [8.1.0] — 2026-06-09 — Clean to Send (spec-v9 Thrust A)

### Added
- **Clean to Send — the pre-disclosure scan (spec-v9 Thrust A, Steps 148–154).**
  A deterministic, in-tab read over a document's **original container bytes**
  (the DOCX/PDF you dropped, before mammoth/pdf.js flatten them) that recovers
  the facts the normalizing ingest discards and surfaces them as a new
  `HANDOFF-*` finding family and a `DeliveryReport`. The one document a lawyer
  must never upload to a cloud scrubber — a privileged, comment-laden redline —
  is exactly the one this catches, because nothing leaves the machine. New
  module [`src/delivery/`](src/delivery/):
  - **`HANDOFF-001` / `002` — residual tracked changes & comments** (critical).
    Parses `w:ins`/`w:del`/`w:move*` and `word/comments.xml`; reports the count,
    the author (itself a metadata leak), and a location-only excerpt.
  - **`HANDOFF-003` — hidden / non-printing content** (warning). `w:vanish` runs
    and deleted-but-retained `w:delText`; reports the recovered span so the user
    can decide. Never judges intent; never claims to catch *all* concealment.
  - **`HANDOFF-004` — authoring metadata** (info → warning → critical). Reads
    `docProps/core.xml`/`app.xml` and the PDF Info dictionary verbatim; flags a
    `Company`/`Manager`/`Template`-path naming an entity **absent from the
    document's own party set** as a likely cross-matter leak.
  - **`HANDOFF-005` — sensitive-data patterns** (warning → critical). SSN
    (structurally validated), EIN, payment-card (**Luhn**-validated), bank-routing
    (**ABA**-checksum), context-gated DOB, and lower-confidence email/phone.
    Every matched value is **masked** before it is stored — a hard invariant: the
    report warning about exposed PII never reproduces it.
  - **Additive by construction.** The `HANDOFF-*` findings carry their own
    `delivery_hash` over the container facts, **namespaced apart from** the engine
    `result_hash` (the v8 Step-146 "field outside the run" precedent), so a
    text-only or metadata-clean document yields an empty report and **no existing
    golden re-baselines**.
  - **Total & private.** `readContainer` never throws and never hangs on a
    malformed, truncated, oversized, or non-zip input — it resolves to typed
    facts or an honest "could not inspect" note (never a clean bill of health),
    under the v8 byte-cap / decompression-ratio / match-cap guards. All regexes
    are linear (the repo's ReDoS-free guarantee holds).
  - **Surfaces.** A `delivery` block in the JSON report, a CLI `--delivery` flag
    (with a one-line presence-only summary), and a prominent "Clean to send?"
    section in the tab's complete state. +29 tests (adversarial-container
    fixtures, totality contract, the masking invariant, PDF Info parsing).

### Fixed
- **ReDoS sweep of the whole extractor surface — no input can make extraction
  hang (spec-v8 Thrust A).** A systematic fuzz of every regex in `src/`
  (killable workers, 50k-char runs of each character class) found a cluster of
  super-linear backtracking beyond the two extractors fixed previously. None are
  caught by the input-size guards (a ~100-char paragraph triggers them) and all
  are reachable with characters that survive normalization. Each fix is verified
  byte-identical on real input (the full golden suite is unchanged) and linear
  on hostile input:
  - **Root cause — `normalize` now folds *all* Unicode whitespace** (`\s`, not
    just `[ \t\r\n]`). The extractors match with `\s` (which spans NBSP `U+00A0`,
    ideographic space, etc.), but those characters used to pass through intact, so
    a crafted run of thousands of NBSPs reached the extractors and drove several
    `\s*`-bearing patterns into O(n²). Folding them at the source fixes every
    whitespace-run vector at once (and makes a finding independent of whether a
    drafter typed a space or a non-breaking space). Zero fixtures contain such
    characters, so the corpus is byte-unchanged.
  - **`splitSentences` (obligations)** used `/[^.!?]+[.!?]+/g`, which is O(n²) on
    any paragraph with no `.!?` terminator (a long clause, or a hostile run) —
    the greedy run rescans from every start position. Replaced with an O(n)
    manual scan that emits byte-identical spans.
  - **Anchored edge-trims** (`/^[…]+|[…]+$/`) in the party and obligation
    extractors backtrack O(n²) on a long run of the trimmed characters (commas,
    dots) that does not reach the boundary. Replaced with linear `trimEdges` /
    `trimEnd` helpers (two-pointer scans).
  - **Bounded the remaining unbounded quantifiers** that a required-token suffix
    forces to backtrack across a run: `PARTY_DECL`'s name token (`{0,80}`), the
    amount `AMT` digit groups (`{1,40}`, comfortably above `MAX_AMOUNT_DIGITS`),
    the date count word (`\w{1,40}`), and the `\s*` gaps in `NUMERIC` /
    `RANGE_NUMERIC` / `WORD_FORM` (`\s{0,8}`). Every bound is far beyond any real
    value, so extraction is unchanged.
  The **fuzz-boundary gate** now drives the full `extractAll` surface over 50k
  runs of every character class (a ReDoS is a hang, not a throw, so the prior
  "never throws" property at 400 chars could not see it). +49 tests.
- **Catastrophic regex backtracking (ReDoS) in the amount and date extractors —
  the engine could be made to hang.** Three extractor patterns had a
  super-linear backtracking shape on adversarial input, defeating the spec-v8
  Thrust A "a tool that cannot be made to hang" guarantee (the input-size guards
  don't help — a ~100-character paragraph triggers it):
  - `amounts.ts` `WORD_FORM` used `(?:…|[-\s]+)+`, which degenerates to
    `([-\s]+)+` over a run of hyphens/spaces — **exponential** (verified:
    28 hyphens ≈ 0.8 s, each +4 ≈ 16×). A fill-in line like
    `ten ------------------` (common in templates, and hyphens survive
    normalization) would hang. Fixed to a single-char separator `[-\s]`
    (identical language and greedy match → zero golden churn; now linear —
    5,000 chars in 0.05 ms).
  - `dates.ts` `RELATIVE` / `RANGE_RELATIVE` used four adjacent unbounded `\s*`
    in the optional numeral chain — **polynomial** over a whitespace run. `\s`
    matches Unicode whitespace (NBSP `U+00A0`, etc.) that `normalize` does **not**
    collapse (it folds only `[ \t\r\n]`), so a crafted run of NBSPs was
    reachable (200 k chars ≈ 23 s before). Bounded each to `\s{0,8}` (the
    spec-v8 §5 "bound, never timeout" idiom; eight is far beyond any real
    inter-token gap, which is ≤ 2 post-normalization → byte-identical on every
    realistic input, verified across the golden suite → zero churn; now linear —
    200 k chars in 0.9 ms).
  +2 regression tests assert each extractor stays fast (< 1 s) on the
  adversarial run (under the old patterns these would not complete).
- **Headless CLI ingested a directory in host-locale order (non-deterministic
  reproduction).** `vaulytica analyze <dir>`'s `walkDir` sorted directory
  entries with a bare `localeCompare`, which depends on the host locale/ICU —
  so the same folder could be analyzed (and its per-file report lines printed,
  its output files written, its `--fail-on` evaluated) in a *different order* on
  a machine with a different `LANG`. The sibling glob branch already used
  code-unit `.sort()`, so `analyze dir/` and `analyze 'dir/*.ext'` could even
  disagree on order. Switched the walk to a code-unit comparator (locale- and
  ICU-independent, identical to the glob branch). The build-time playbook
  bundler (`tools/build-extended-playbooks.ts`) carried the same bare
  `localeCompare` over playbook ids; pinned it the same way (regenerating
  `playbooks/extended.json` is byte-identical — the IDs already sorted the same).
  The static **locale-pin guard** now also scans `tools/cli/` — the published
  CLI is a distribution surface that runs the same engine and so carries the
  same reproducibility contract as the shipped `src/` bundle; previously the
  guard only covered `src/`, which is how this slipped through. +2 tests
  (`resolveInputs` directory ordering proves uppercase sorts before lowercase,
  which `localeCompare` would not do).
- **Local Playwright e2e couldn't reach its own preview server (IPv4/IPv6
  mismatch).** `vite preview` defaults to binding `localhost`, which on a
  dual-stack machine resolves to IPv6 `::1`, but the Playwright `webServer`
  polls `127.0.0.1` (IPv4) — so the server-ready wait timed out at 60 s and
  `npx playwright test` never ran locally (it only ran in deploy CI, which hits
  the deployed site via `VAULYTICA_E2E_BASE_URL`). Forced the preview to
  `--host 127.0.0.1` so it binds the address Playwright polls. With this, the
  full e2e suite runs locally; the **responsiveness + accessibility gates were
  then verified empirically** for the first time in this environment — all 34
  responsiveness/a11y tests pass (live app + every `DropzoneState` at
  320/390/768/1280 px with zero horizontal overflow, axe WCAG 2 AA in both
  themes). CI-only `VAULYTICA_E2E_BASE_URL` path is unaffected.
- **GitHub Action install would have broken `tsx` on the runner
  (`--ignore-scripts`).** Self-reviewing the freshly-shipped Action: the install
  step used `npm ci --ignore-scripts`, which skips **esbuild**'s `postinstall`
  (`node install.js`) — and `tsx` (the CLI's runtime loader) depends on esbuild,
  which fails at runtime when its binary is left unconfigured. Switched to
  `npm ci --omit=dev`, which runs esbuild's postinstall while still skipping the
  dev-only `sharp` native build and Playwright. Verified in an isolated install
  that `--omit=dev` yields a working `tsx`. A test now pins `--omit=dev` and
  forbids `--ignore-scripts`, so the regression can't recur.
- **Trimmed `*.test.ts` from the publishable npm tarball.** Added `!**/*.test.ts`
  to the `files` allow-list — the package no longer ships test files (601 → 472
  files), while keeping `_test-fixtures.ts` (the CLI's `loadStarterDkbSync` lives
  there, not a `.test.ts`). The earlier "noted pre-publish refinement" is done.

### Added
- **Distribution surface: a `vaulytica` binary + a GitHub Action (spec-v8 §22).**
  The deferred "publish the CLI" item — the engineering half, not the
  credentialed `npm publish` itself. New `bin/vaulytica.mjs`, a thin `node
  --import tsx` launcher so the TypeScript CLI is invokable as a plain binary
  (no fragile pre-bundle of the WASM/worker ingest deps), with exit codes
  propagated for CI gating. `package.json` is now publish-ready: a `vaulytica`
  `bin`, a `files` allow-list shipping the engine + CLI + starter DKB +
  playbooks, npm metadata (keywords/repository/homepage), and `tsx` moved to
  `dependencies` (so `npx vaulytica` works) — still `private: true` so an
  accidental publish is refused. New composite **GitHub Action** (`action.yml`)
  runs the engine in any repo's CI: `analyze` (→ SARIF for code-scanning upload)
  or `compare` (a redline gate), with `fail-on` propagating the non-zero exit.
  The DKB ships with the tool, so a CI analysis opens **no socket** — nothing
  leaves the runner. New [`docs/ci-integration.md`](docs/ci-integration.md) with
  the workflow recipes, the `npx` usage, and the maintainer publish steps. +7
  tests (bin launcher smoke + exit-code propagation, `action.yml` validity,
  package-metadata consistency).
- **`vaulytica compare <base> <revised>` — headless version comparison (extends
  v8 Thrust C "reach").** Comparison was the one major feature with no headless
  entry point; the CLI did `analyze | diff | verify` but not `compare`. New
  `tools/cli/compare.ts` (wired into the `run.ts` dispatcher) analyzes both
  documents over the parity-proven Node engine, runs `compareRuns` +
  `buildClauseDiff`, and emits either a Markdown summary (a finding-delta table
  plus the inline word-level redline — `~~removed~~` / `**added**` — of every
  rewritten clause) or `--format json` (the machine-readable comparison with
  `clause_diff`). `--fail-on critical|warning|info` exits non-zero (code 2) when
  the revision *introduced* a finding at or above the threshold — so a pull
  request can be gated on "did this revision create new exposure?" with the
  redline attached as the artifact. `--confirm-pairing` permits a cross-family
  compare (mirrors the UI refusal). DKB ships with the tool → no socket.
  Build/CI-only (the corpus guard still holds: `tools/` may import `src/`, never
  the reverse). +10 tests (arg parsing, the introduced-bucket gate, the Markdown
  redline, and a real-engine end-to-end over two temp files).
- **Inline word-level redline within rewritten clauses (completes the Part XVIII
  redline).** The clause redline reported *which* clauses were rewritten but
  showed the whole old vs whole new paragraph — noisy for a one-word edit. Each
  `changed` pair now carries a `word_diff`: a second deterministic token-LCS
  (`diffWords` in `src/report/clause-diff.ts`) that marks the exact words struck
  and added (segments reassemble exactly to the base and revised texts; bounded
  by `MAX_WORD_DIFF_TOKENS`, `null` past it so the renderer falls back to the
  two full texts). The comparison Word report renders it as a true inline
  redline — strikethrough for removed words, underline for added — and the
  comparison JSON carries the `word_diff` segments for machine consumption. Still
  outside the comparison `result_hash` (zero golden churn). +7 tests.
- **Clause-level redline for version comparison (spec-v8 Part XVIII).** The
  comparison feature diffed two `EngineRun`s and told you which *findings*
  resolved / introduced / persisted, but never showed the *clause text* that
  moved. New `src/report/clause-diff.ts` (`buildClauseDiff`) computes a
  deterministic, paragraph-level text diff of the two documents — which clauses
  were **rewritten, added, or removed** — via an LCS alignment over the
  documents' own normalized text, pairing a replaced block into a single
  `changed` entry. It is **bounded** (spec-v8 §5): past a cell ceiling
  (`MAX_CLAUSE_DIFF_CELLS`) it degrades to a set-based membership diff and sets
  `truncated`, never an unbounded allocation. Surfaced in the comparison Word
  report (a "Document Redline" section with base-vs-revised tables, capped rows
  + an honest "and N more" footer), the comparison JSON (an additive
  `clause_diff` field), and a one-line UI summary in the comparison-complete
  state. It is a *verbatim* diff — no generated language, never a suggested edit
  — and lives **outside** the comparison `result_hash`, so it churned no
  comparison golden (the model-clause/overlay precedent). +18 tests across the
  algorithm (insertion/deletion/rewrite/move/whitespace/empty/bound/determinism),
  the JSON and DOCX wiring, and the UI summary. This was the last substantial
  deferral in spec-v8 Part XVIII.

### Fixed
- **Set-based redline fallback miscounted a repeated clause (multiset bug).**
  Found self-reviewing the freshly-shipped redline. The oversized-document
  fallback `setDiff` (`src/report/clause-diff.ts`) used a `count > 0` membership
  test: when a boilerplate clause appeared `b` times in base and `r` times in
  revised with `r < b`, all `r` revised copies were marked unchanged but the
  surplus `b − r` base copies were never reported as removed — silently wrong
  counts, only on the truncated path (documents past the alignment ceiling).
  Reworked to proper multiset semantics — `min(b, r)` matched, the surplus on
  each side surfaced as added/removed. +1 test over a 5×-vs-3× repeated clause.
- **DKB cache fallback could serve a corrupt record as "latest."**
  `readLatestCache` (`src/dkb/loader.ts`) — the offline fallback that picks the
  newest cached DKB out of IndexedDB when the exact requested version is missing
  — sorted records with string `localeCompare` and served the maximum. A string
  sort is not the DKB's version order: a garbage/corrupt version key like
  `zzz-corrupt` sorts *after* a valid `v2026-06-07-local` (`'z' > 'v'`) and would
  be chosen, feeding the engine a corrupt knowledge base. Switched to the
  project's own `compareDkbVersions`, which parses the `vYYYY-MM-DD-<hash>` /
  `v0.0.x-` forms and treats an unparseable version as **oldest** — so a valid
  record always outranks a corrupt one. Well-formed current versions are
  date-ordered identically, so behavior is unchanged for the normal path; this
  hardens the corrupt-cache edge (v8 §5 posture). Runtime/IndexedDB-only → zero
  golden churn; +1 test pinning the corruption-safety ordering.

### Security
- **Neutralized CSV formula injection (CWE-1236) in the fix-list and obligations
  exports.** Both CSVs carry verbatim clause text (the obligations ledger emits
  the obligation action / trigger / source clause) and custom-playbook rule
  titles — all untrusted. `csvField` did RFC 4180 quoting but did not guard the
  formula-injection class: a cell whose first character is `=`/`+`/`-`/`@` (or a
  leading tab/CR) is interpreted as a **formula** when the file is opened in
  Excel or Google Sheets, so a clause crafted as `=HYPERLINK("http://evil",…)`
  could execute on the reviewer's machine. `csvField` now prefixes such a cell
  with a single quote (the OWASP mitigation) so a spreadsheet renders it as
  inert text. Zero golden churn (no fixture cell began with a formula trigger);
  +2 tests over the `=`/`+`/`-`/`@` triggers.

### Fixed
- **`$`-replacement patterns in a custom-playbook citation URL corrupted the
  standalone HTML report's bibliography link.** The bibliography links a URL by
  `String.replace`-ing it inside the already-escaped entry text
  (`src/report/html.ts`). With a **string** replacement, a special-replacement
  pattern (`$&`, `$'`, or the dollar-backtick prefix) in the replacement string
  is expanded — so a
  user-supplied custom-playbook citation URL like
  `https://policy.example.com/s?a=$&b=1` had the matched URL spliced into its own
  `href` (e.g. `…s?a=https://policy.example.com/…`), producing a broken,
  unfollowable citation link — in the v8 §10 "custom playbook is hostile input"
  surface. (Not XSS — the spliced substring is already HTML-escaped, and the
  `safeHref` http(s)-only guard still holds; it is link **corruption**.) Switched
  to a **function** replacer, which inserts the markup verbatim. Render-side →
  zero `result_hash` churn. Added a regression test asserting a `$`-laden
  bibliography URL renders into an intact `href`, verified to fail against the
  string replacer.
- **Pinned every `toLocaleString` to `"en-US"` and added a static locale-pin
  guard (determinism hardening, round 2).** A follow-up sweep found the
  number-formatting twin of the `localeCompare` bug: eight `Number.toLocaleString()`
  calls with **no locale argument**, so a number like `1234567` renders
  `"1,234,567"` on an en-US host but `"1.234.567"` on a German one. Four of them
  (`engine/consistency/rules/v4/cross-doc-rules.ts`) format the **finding title
  and description** of the aggregate-liability and indemnity-cap cross-doc rules
  — text that is serialized into the `EngineRun` and hashed, so a bundle analyzed
  on a non-en host produced a **different `result_hash`**. Pinned all eight
  (cross-doc rules + the three oversize-input error messages in
  `ingest/limits.ts` / `ingest/multi.ts` / `playbooks/custom-playbook.ts`) to
  `"en-US"`, matching the existing `report/v3/insurance.ts` precedent; en-US
  output is byte-identical, so **zero golden churn**. Also pinned three more
  `localeCompare` sites in `extract/definitions.ts` (defined-term / circular-term
  ordering) that the prior manual grep missed. New **static locale-pin guard**
  in `tests/integration/determinism-guard.test.ts` scans all shipped `src/` and
  fails if any `localeCompare`/`toLocaleString` omits an explicit `"en"`/`"en-US"`
  locale — the repeated-run determinism test can't catch this class (the host
  locale is constant within a process), which is how two such bugs reached `main`.
- **Pinned every `localeCompare` sort to the `"en"` locale (determinism
  hardening).** Twelve stable-ordering sorts across `src/` (playbook match
  tie-break in `matcher.ts`, secondary-family ordering in
  `playbook-candidates.ts`, currency-mode pick in the v4 consistency
  `_helpers.ts`, deadline/`.ics` ordering in `exports.ts`, portfolio row order
  in `portfolio.ts`, custom-playbook error/unevaluable ordering, DKB version
  pick in `loader.ts`) called `String.prototype.localeCompare` with **no locale
  argument** — so collation fell back to the host's runtime locale (ICU/`LANG`).
  For the determinism thesis that is a latent footgun: a tie-break or a
  finding-feeding sort that orders differently under a French vs. English locale
  can move `result_hash` across machines. Several of these feed the engine run
  (`matcher` decides which playbook wins a score tie; `_helpers` picks the
  dominant currency that a finding quotes). Pinning to `"en"` makes the
  collation host-independent; ASCII ids/codes sort identically, so **zero golden
  churn** (full suite byte-unchanged, 2,702 → 2,703 only from the new ICS test).
- **`icsFold` folded `.ics` content lines by character count, not octets (RFC
  5545 §3.1).** The deadline-calendar line folder sliced at 73/72 *characters*
  while its own contract said "≤75 octets" — correct for ASCII but able to emit
  a line **over** the 75-octet limit on multi-byte clause text (accented terms,
  a `€` symbol, an emoji in a filename), which strict calendar parsers reject.
  Rewrote it to fold on **UTF-8 octet boundaries** without splitting a code
  point (`octetLength` / `splitByOctets` helpers). Pure-ASCII lines fold
  identically (zero golden churn); multi-byte text now stays within the limit.
  Added a test that a 270-octet euro-sign summary folds to ≤75-octet lines and
  unfolds back to intact UTF-8. Found in the same low-coverage audit pass.
- **Hardened the second reusable regex-exec-loop helper against the zero-width
  hang (audit follow-up).** Swept every manual `while ((m = re.exec(text)))`
  loop in `src/` for the same infinite-loop class fixed in `allMatches`. The
  ~20 one-off extractor/rule loops all use fixed, literal-anchored regexes
  (require `$`, a keyword, `\d+`, etc.) that provably can't match empty — left
  as-is. The one other *reusable* helper, `extractMetricValues`'s `all()` in
  `custom-interpreter.ts` (a growing set of metric patterns flows through it),
  got the same `lastIndex` step-past guard for consistency / future-proofing,
  even though today's patterns all require `\d+`. Zero behaviour change (56
  playbook tests unchanged).
- **`allMatches` could hang the tab on a zero-width regex (latent unbounded-work
  vector).** The shared rule helper `allMatches` (`src/engine/rules/_helpers.ts`)
  ran `while ((m = re.exec(text)))` with a global regex; a zero-width match
  (e.g. a rule regex like `/x?/` or `/\b/`) does not advance `lastIndex`, so the
  loop spins **forever** — a synchronous hang of the browser tab, exactly the
  unbounded work spec-v8 §5 forbids. No shipped rule triggers it today (the two
  callers, STRUCT-016 / RISK-002, require literal text), but it's a hang waiting
  for any future rule that passes an empty-matchable pattern. Added the standard
  `lastIndex` step-past guard; added `_helpers.test.ts` pinning termination on
  `/\b/`, `/x?/`, `/a*/`. Zero churn for the current callers (1,104
  rule/golden tests unchanged). Found by auditing low-branch-coverage modules.
- **Extractors could throw an uncaught `RangeError` on a deeply-nested tree
  (spec-v8 §5/§7 residual).** The extractor walkers (`src/extract/walk.ts`,
  `forEachParagraph` / `forEachSection`) recursed on `section.children` with no
  bound — `extractAll` (a public function) blew the call stack at a few thousand
  levels of nesting. spec-v8 §7 had listed `walk.ts` among the walkers to guard,
  but Step 128 only made `normalize` / `countWords` iterative; the extractor
  walkers stayed recursive. Production never hit this (ingest flattens to
  `MAX_SECTION_DEPTH` before extraction), but the §5 contract forbids a public
  function throwing an uncaught exception. Rewrote both walkers as **iterative
  pre-order DFS** (explicit stack) — byte-identical traversal order (zero golden
  churn; 1,110 extract/golden tests unchanged), now total to any depth (verified
  to 100k). Added a fuzz-boundary test pinning extractor stack-safety on a
  50,000-deep tree. Found by auditing the lowest-branch-coverage shipped modules.

### Documentation
- **Refreshed the README product screenshot (it was stale by two export
  formats).** `docs/images/report-mobile.png` predated the v8 UI wiring, so it
  showed only 4 export buttons; the app now offers 6 (it was missing **HTML
  report** and **SARIF**), and the link/overlay colours had since changed.
  Regenerated it from the *current* `renderState` + page CSS via a new, isolated
  generator (`tools/screenshots/capture.spec.ts`, `npm run screenshots`) so the
  product shot stays faithful as the UI evolves — and updated the alt text to
  list all seven export formats. The generator lives outside `tests/e2e`, so it
  is never run by the e2e suite or vitest; it is invoked on demand.

### Accessibility
- **Bring-your-own-playbook panel sub-states are now responsiveness/a11y-gated
  (fixed two real bugs).** The panel's JS-rendered error / loaded / warning
  sub-states aren't part of the `DropzoneState` union, so they were never
  tested. New `tests/e2e/playbook-panel-a11y.spec.ts` renders them with the real
  page CSS and found: (1) the **invalid-playbook error message** — the text that
  tells you *why* your playbook was rejected — used `var(--critical, #b00020)`,
  but `--critical` was **undefined** so it fell back to a dark-red `#b00020` at
  ~2.7:1 on the dark theme's near-black surface (barely legible) → defined
  `--critical` per theme (dark: a bright `#ff6b6b` ≥ 6:1; light: `#b00020`); (2)
  validation errors echo user-supplied ids (rule ids, metric names) that can be
  long unbreakable tokens and **overflowed a 320 px phone** → `overflow-wrap:
  anywhere` on `.playbook-status` (inherited by the lists/summary). Both pass
  responsiveness + axe in both themes now.
- **Rich complete-state content is now responsiveness/a11y-gated.** The
  exhaustive `responsiveness-states.spec.ts` complete-state fixture was minimal
  — it never rendered the jurisdiction-overlay block, compliance-frame chips,
  custom-playbook provenance, or the detected-family chip, so those elements
  (long statute citations, link colours) were untested. Enriched the fixture to
  stress all of them (and taught the harness to expose `globalThis.document` for
  the renderers that build nodes via the global, as the browser/vitest do). It
  caught a real light-theme contrast bug the minimal fixture missed: the
  jurisdiction-overlay citation link (`.overlay-cite`) used the raw brand mint
  `var(--accent)` (~2.7:1 on the cream surface) → switched to the `--link` token
  (AA on both themes). Complete state now passes responsiveness + axe in both
  themes with its full content rendered.
- **Marketing landing page is now WCAG 2 AA in both themes (gated).** The live
  axe sweep `disableRules(["color-contrast", "region"])` and only runs the dark
  theme, so the full landing page's contrast was never gated. A new
  `tests/e2e/landing-responsive-a11y.spec.ts` renders the real `site/index.html`
  via `page.setContent` (no server), pins each theme via `data-theme`, runs axe
  with **color-contrast enabled**, and checks no horizontal overflow at
  320–1280 px. It found two real, never-tested defects: (1) the
  bring-your-own-playbook panel had `aria-label` on a role-less `div`
  (`aria-prohibited-attr`) → added `role="group"`; (2) **every link in the light
  theme** rendered the brand mint (`#00a883`) at ~2.7:1 on the cream surfaces
  (links are `var(--accent)` text) — introduced a `--link` token (dark: the
  bright mint on near-black; light: a darker on-brand teal `#00735a` ≥ 5:1) so
  link text clears AA while buttons keep `--accent`.
- **Standalone HTML report is now responsive and WCAG 2 AA clean.** The
  shareable single-file report (spec-v8 §21) overflowed a 320 px phone by
  ~924 px — a long underscore-joined filename in the `<h1>` (and finding
  titles) was an unbreakable token with no wrap. Set `overflow-wrap: anywhere`
  on the report `body` (it inherits, so every heading / rule-id / SHA-256 proof
  value / citation URL wraps). An axe sweep also found the freshness label
  (`.fresh` `#777` = 4.47:1) just under AA; darkened to `#6b6b6b` (~5:1). New
  `tests/e2e/html-report-responsive.spec.ts` pins both (responsiveness +
  zero axe violations) via `page.setContent` (no server).
- **Fixed WCAG 2 AA contrast + a missing progressbar name across the app's
  non-default states/theme.** The live axe gate only scans the empty + complete
  states in the default (dark) theme; rendering the **full** `DropzoneState`
  union in **both** themes surfaced real, never-tested issues: the light-theme
  `--muted` (`#6b7280`, ~4.3:1 on the cream surface) failed AA for every muted
  label (sub-text, card meta, toggles) → darkened to `#5b626f`; the
  low-confidence card's confidence number was dimmed by `opacity: 0.75` to
  ~3.9:1 → removed the dim; the low-confidence family label used `opacity: 0.65`
  → switched to the (AA-tuned) muted colour, preserving the "faint" intent
  accessibly; the comparison DKB-mismatch warning (`#a86700` normal text) failed
  on dark → theme-aware amber; and the `analyzing` progressbar had no accessible
  name → added `aria-label`. `responsiveness-states.spec.ts` now also runs axe
  per state × theme, so these can't regress.

### Fixed
- **Mobile horizontal-overflow on long contract filenames (3 view-states).** A
  long, underscore-joined filename (e.g. `Master_Services_Agreement_..._v12_
  executed.pdf`) is a single unbreakable token; `.dropzone-title` (complete /
  analyzing states), `.dropzone-sub` (comparison "base → revised" line), and
  `.bundle-rejected-filename` (skipped-file list) had no `overflow-wrap`, so on
  a 320 px phone the filename pushed the card 100–400 px past the viewport —
  horizontal scroll. Added `overflow-wrap: anywhere` to all three. The existing
  responsiveness e2e never caught this because it drops a *short*-named fixture.

### Added
- **Exhaustive responsiveness gate over every view-state.** New
  `tests/e2e/responsiveness-states.spec.ts` renders the **full** `DropzoneState`
  union (empty · analyzing · complete · comparison · bundle · error) via the
  real `renderState` + the real page CSS through Playwright `page.setContent`
  (no server needed — so it runs anywhere), at 320 / 390 / 768 / 1280 px, with
  overflow-*stressing* fixtures (very long filenames, many per-doc cards, long
  skip reasons / error messages). This is what surfaced the overflow bugs above;
  it complements the live-app `responsiveness.spec.ts` (which pins empty +
  complete against the deployed site).

### Security
- **Neutralized a `javascript:`/`data:` URL XSS vector in the shareable HTML
  report.** `z.string().url()` accepts `javascript:alert(1)` and `data:` URLs
  (the URL constructor parses them), so a custom-playbook citation `url` could
  ride into the standalone HTML report — which spec-v8 designs to be *emailed*
  — as an active `<a href>`, executing in a recipient's browser on open.
  Two-layered fix: (1) the custom-playbook **schema now rejects any citation
  URL that is not http(s)** at load, with a clear message — protecting every
  output format at the input boundary; (2) the HTML renderer **only emits an
  http(s) `href`** and falls back to inert escaped text for any other scheme
  (defense-in-depth for the artifact that executes on open), keeping the URL
  visible/verifiable but non-executable. DKB citations were never affected
  (build-time and vetted). Threat-model updated.
- **Extended the URL-safety guard to the DOCX (the other shareable rich
  format), via one shared `isHttpUrl` predicate.** The DOCX citation-index
  built an `ExternalHyperlink` for any `source_url`; a non-http(s) scheme is now
  rendered as inert text (no hyperlink relationship is created) just like the
  HTML report. Factored the HTML `safeHref` and the custom-playbook schema
  refine onto the same `src/dkb/url-safety.ts` predicate, so the input-boundary
  schema guard and both output-boundary render guards share one canonical
  policy. `http` is allowed alongside `https` (the DKB carries a legitimate
  `http://` UK OGL license URL); only the scheme is constrained.

### Fixed
- **CLI bare-glob resolution.** `vaulytica analyze '*.docx'` (a quoted glob with
  no directory, so the shell doesn't expand it) silently matched nothing: the
  old `slice(0, lastIndexOf("/"))` produced a bogus directory (`*.doc`) for a
  slashless pattern, so `readdir` failed. Extracted `splitGlob` + `globToRegExp`
  as pure, unit-tested helpers — a slashless glob now resolves against `.`.
- **CLI `verify --playbook` argument ordering.** `verify --playbook <id> <report>
  <original>` mis-assigned the report path (the flag value leaked into the
  positional list under a filter-by-prefix parse). Replaced with a sequential
  parser that consumes the flag's value, so `--playbook` works before or after
  the positionals (and an unknown flag now errors instead of being treated as a
  path). Also guarded `run.ts`'s top-level dispatcher so importing it (for the
  new unit tests) does not execute the CLI.

### Added
- **SARIF 2.1.0 structural-conformance gate (closes the spec-v8 §20 test
  promise).** Step 141 shipped the SARIF export but its test only checked the
  `$schema` *string*; §20 promised validation against the schema. Added an
  exposed, dependency-free `sarifConformanceViolations(log)` that pins the
  ingestion-critical SARIF 2.1.0 invariants GitHub Code Scanning actually
  enforces — the `level` enum, an in-range `ruleIndex` consistent with its
  `ruleId`, string-valued `partialFingerprints`, non-empty `message.text` and
  `artifactLocation.uri`, absolute `helpUri` — with **negative tests** proving
  the checker has teeth (a dangling index, a bad level, a non-string
  fingerprint, a malformed URI are each caught). Real output conforms across
  fixtures (cited, URL-less custom, empty, multi-finding-per-rule). Full
  validation against the OASIS-*published* JSON Schema stays deferred for the
  offline/posture reason citation reachability is (§19) — the authoritative
  schema can't be fetched in-tab, and vendoring a copy and calling it "the
  published schema" would be dishonest; spec §20 + docs reconciled to describe
  the conformance check accurately.
- **Unified `vaulytica` CLI dispatcher — `analyze | diff | verify` (surfaces
  the playbook diff).** The CLI (`npm run cli -- <command>`) now dispatches
  three subcommands over the same parity-proven engine instead of only
  `analyze`. New `diff <a.json> <b.json> [--format markdown|json]
  [--exit-code]` surfaces `diffPlaybooks` (spec-v8 Step 144) — until now a
  shipped builder with **no entry point** — as a reviewable terminal/CI
  command (`--exit-code` is a `git diff`-style CI primitive that exits 1 when
  two custom playbooks differ). `verify <report.json> <original>` folds the
  reproducibility verifier (Step 145) into the same dispatcher. `analyze`
  is unchanged. New `tools/cli/diff.ts` (pure, unit-tested `formatPlaybookDiff`
  + the `runDiff` handler); `run.ts` refactored from a single-command script
  into a dispatcher with a `--help` usage banner. Added an `npm run cli`
  script (the `analyze` script is kept as a back-compat alias). Build/CI-only;
  `src/` never imports it.
- **v8 reach formats reachable from the tab (UI wiring).** The SARIF 2.1.0
  export and the standalone single-file HTML report (spec-v8 Steps 141–142)
  are now offered as one-click downloads in the complete-state export row
  ("HTML report", "SARIF") beside the existing fix-list / CSV / obligations /
  `.ics` links, and the bundle-complete state gains a "Download everything
  (.zip)" link — the spec-v8 §25 "everything" archive (consolidated DOCX +
  bundle JSON + per-document fix-list / CSV / `.ics` / JSON in one ZIP). Until
  now these v8 builders shipped but were unreachable from the browser, so the
  README's "one-click exports … SARIF … single-file HTML" claim was ahead of
  the UI; this closes that gap. `runReport`/`runBundleReport` build the blobs
  from the same run (no re-analysis); the export row's `flex-wrap` layout keeps
  the two new buttons from introducing any horizontal scroll on mobile. The
  parity test now also asserts the browser pipeline emits a non-empty,
  script-free HTML report and a `application/sarif+json` blob.

## [8.0.0] - 2026-06-08 — Hardening & Reach (spec-v8 complete)

### Added
- **Citation formatter breadth (spec-v8 Thrust B, Step 136).** `citationFamily()`
  classifies a citation `source` into `us-statutory` / `eu` / `standard` /
  `secondary` / `other`, each tied to a real DKB citation. Only US-statutory
  forms take a Bluebook parenthetical year (EU regs / ISO-NIST standards /
  secondary sources embed their own identifying year); pinpoint subsections
  (`45 C.F.R. § 164.410(a)(1)`) are preserved verbatim, never truncated to the
  base section. Pinned-string fixtures per family. Render-side → zero churn.
- **Citation freshness signal (Step 137).** `freshnessSignal()` surfaces the
  retrieval date (and publication date when genuinely known); the bibliography
  renders `(published YYYY-MM-DD)` only when `source_published_at` is present —
  **never fabricated**, absent when unknown (the honesty gate). Date-only, never
  a computed elapsed "age" (a clock read would break determinism). Additive →
  zero golden churn.
- **Never-truncate / always-wrap citations (Step 138).** `breakLongTokens()`
  splits long citation URLs into wrap-friendly DOCX runs (bibliography +
  citation-index hyperlink) and the HTML report uses `overflow-wrap: anywhere`;
  a DOCX structure test asserts the full citation source + URL render with no
  ellipsis. The split segments rejoin to the original exactly.
- **Citation integrity tool (Step 139).** Build-only `tools/citation-check`:
  per-commit URL well-formedness (pure; `npm run citation:check`) + scheduled
  reachability (`--reachability`, network, mocked in test). `accuracy-corpus-
  guard` extended to assert `src/` never imports it.
- **Cross-format citation-completeness gate (Step 140).**
  `tests/integration/citation-completeness.test.ts` asserts every cited
  finding's resolvable URL survives into **every** finding-bearing format —
  DOCX, JSON, Markdown, CSV, SARIF, HTML — and the URL-less custom case renders
  cleanly. The executable form of the §14 inline-everywhere contract.
- **SARIF 2.1.0 export (spec-v8 Thrust C, Step 141).** `buildSarif` /
  `buildSarifJson` / `sarifBlob` — rule→`reportingDescriptor` (citation →
  `helpUri`), finding→`result` (severity→level, section→`logicalLocation`,
  offset→`region`), finding-id + `result_hash` → `partialFingerprints` for
  cross-run dedupe; deterministic canonical JSON. Render-side → zero churn.
- **Standalone single-file HTML report (Step 142).** `buildHtmlReport` —
  self-contained, all CSS inlined, **no `<script>`**, no external resource;
  cover proof fields, severity-grouped findings, inline citations with wrapped
  URLs + freshness, bibliography, clause-evidence, verbatim posture block;
  mobile-responsive and print-clean. Deterministic; escapes HTML metacharacters.
- **Node API + headless CLI (Step 143).** `tools/cli/api.ts` (`analyzeText` /
  `analyzeFile`) + `vaulytica analyze <path|glob|dir> --playbook --format
  json,sarif,html,md,csv --out --fail-on` over the parity-proven pipeline
  (`runIngested` factored out of `runDocument` so binary ingest reuses the exact
  downstream the parity test pins). DKB ships with the tool — no socket. CLI
  parity test asserts `analyzeText` ≡ `runDocument` byte-for-byte.
- **Playbook diff (Step 144).** `diffPlaybooks(a, b)` + `diffPlaybooksMarkdown`
  — structural diff of two custom playbooks (metadata, built-in rule selection,
  severity/skip overrides, thresholds, required clauses, custom-rule add /
  remove / edit). Pure, deterministic.
- **Reproducibility verifier (Step 145).** `verifyReproducibility(saved,
  original)` re-derives the `result_hash` via the parity-proven pipeline and
  reports what diverged — input / engine / DKB / unexplained; `explainReproResult`
  narrates. `tsx tools/cli/verify.ts <report.json> <original.txt>`.
- **Export enhancements (Step 146).** Bundle "everything" archive
  (`include_per_document_exports`: per-document fix-list + CSV, and ICS / JSON
  when `extracted` / `ingest` are threaded). `buildClauseEvidence` coverage
  surface — which findings pin a verbatim quoted clause span vs. a bare match —
  as a `clause_evidence` JSON field (outside the run → zero churn) + an HTML
  section.

### Changed
- Version bumped to **8.0.0** (Step 147). `RULE_TAXONOMY_VERSION` stays `7.0.0`
  — v8 adds no rules, so the rule vocabulary is unchanged. Spec statuses,
  threat-model ("v8 — hardening & reach surface"), `docs/v8/README.md`, and the
  README posture / test-count (2,621 → 2,674) / Thrust-C surfaces reconciled.

### Added (earlier in this cycle)
- **Inline-everywhere citations (spec-v8 Thrust B, Step 135).**
  The Markdown fix-list now renders authorities as clickable `[source](url)`
  links and the CSV gains a dedicated `authority_url` column — the action-item
  artifacts a user pastes into a ticket/spreadsheet stay verifiable instead of
  stripped to a bare name. Render-side fix in `formatCitation` /
  `formatBibliographyEntry`: a cited custom-playbook rule with no URL now renders
  cleanly as `Policy 4.2` (was `"Policy 4.2 — "` with a dangling em-dash) and
  `[N] Policy 4.2 (cited — Team policy)` (was `[retrieved ; license: …]` with a
  blank date). A citation-completeness meta-test asserts every cited finding's
  URL survives into the Markdown + CSV exports (extends to SARIF/HTML in Thrust
  C). All render-side → zero `result_hash` churn; only the export-test goldens
  re-baselined (mechanical, reviewed).
- **Input-boundary hardening (spec-v8 Thrust A, Steps 127–134).** Every public
  ingest/extract/playbook entry point now fails safely on hostile input —
  rejects deterministically or degrades to a bounded result, never crashes,
  hangs, or exhausts memory. New `src/ingest/limits.ts`: `MAX_DOCUMENT_BYTES`
  (50 MB) + `MAX_PASTE_CHARS` (20M) → typed `InputTooLargeError` before parsing;
  `MAX_SECTION_DEPTH` (64) makes `normalize` flatten deep trees iteratively
  (a 20,000-deep hostile tree no longer overflows the stack) and `countWords`
  iterative; `MAX_OCR_PAGES` (500) bounds the OCR loop with an honest skipped-
  pages warning. `extractZipEntries` guards via fflate's pre-inflation filter —
  `MAX_COMPRESSION_RATIO` (200×) + cumulative-uncompressed budget → typed
  `ArchiveTooLargeError` before a zip bomb expands; nested `.zip` rejected.
  `amounts.ts` drops 50+-digit / NaN / Infinity amounts (`MAX_AMOUNT_DIGITS`).
  Custom-playbook caps (`MAX_PLAYBOOK_JSON_BYTES` pre-parse, `MAX_CUSTOM_RULES`,
  per-string caps). `BUNDLE_CROSS_DOC_TOP_N` (100) caps the cross-doc appendix
  with an honest footer (full set stays in JSON). A `fast-check` fuzz boundary
  gate (`tests/integration/fuzz-boundary.test.ts`) proves the whole public
  surface returns-or-typed-throws and terminates on arbitrary input — the
  boundary analog of v7's metamorphic suite. All guards are pure functions of
  the input (determinism holds — bounds, never timeouts) and zero-churn against
  the goldens. See [`docs/spec-v8.md`](docs/spec-v8.md) + [`docs/v8/robustness-and-fuzzing.md`](docs/v8/robustness-and-fuzzing.md).
- **Mutation testing (spec-v7 Steps 123–124).** Added Stryker
  (`@stryker-mutator/core` + `vitest-runner`, dev-only) scoped to the date and
  amount extractors, a `npm run mutation` script, and a scheduled/on-demand
  `.github/workflows/mutation.yml` (weekly + `workflow_dispatch`, **never** the
  per-push gate). Committed baseline **55.65%** mutation score, raised from the
  first measured 51.26% by a survivor-fix pass (pinned unit→day conversion +
  `before`-direction signing in dates; scale-suffix multiplication + range
  currency inheritance in amounts). Regression-only `thresholds.break = 48`.
  See [`docs/v7/mutation-baseline.md`](docs/v7/mutation-baseline.md). Generated
  reports (`reports/`, `.stryker-tmp/`) are gitignored.
- **Property-based + metamorphic follow-ups (spec-v7 Steps 118/119).** A
  crossref resolve/flag property (a reference to an existing section always
  resolves; a held-out non-existent one always flags) and two metamorphic
  relations (reordering independent clauses keeps the fired-rule set but changes
  the result_hash; when order IS the defect, STRUCT-002 flips as the only date
  crosses the top-quartile boundary). Test-only; no `src/`/`result_hash` impact.

## [7.0.0] — 2026-06-05

**v7 "Depth & Proof"** — make the engine more correct on real documents (Thrust A) and prove the logic sound under inputs no author wrote down (Thrust B), without touching the deterministic / no-AI / no-server / citable / lints-not-drafts posture. See [`docs/v7/README.md`](docs/v7/README.md) and [`docs/v7/testing-architecture.md`](docs/v7/testing-architecture.md).

### Added (Thrust A — depth, Steps 103–108, 110, 113–114)
- **Extraction recall (Steps 103–108).** Dates: fiscal periods (`fiscal-period` type), broadened citable anchor-alias set + "Date Hereof", disjunctive/range deadlines (`offset_days_max`), documented `TWO_DIGIT_YEAR_PIVOT`. Amounts: range amounts (`range_max`), per-unit qualifiers (`per_unit`), deferred `$`-currency override. Parties: alias/role chains (`aliases`), `dba` operating names, two-column signature-field capture. Obligations: prohibitive/permissive boundary modals, nested-trigger decomposition (`nested_triggers`), scope exclusion (`obligor_exclusion`). Definitions: definition-by-`reference`, `scope`-gated defs, circularity detection (`circular_terms`). Crossrefs/jurisdictions: trailing sub-reference (`sub_ref`), governing-law `fallback_jurisdiction` precedence. All new fields optional and outside `result_hash`.
- **Three cross-document families (Step 110).** `CROSS-TERM-001` (termination-alignment), `CROSS-CARVEOUT-001` (liability-cap carveout mismatch), `CROSS-CURRENCY-001` (payment-currency mismatch); V4_CROSS_RULES 10 → 13, each with a bundle fixture.
- **Ingest robustness (Step 113).** Per-page text-density OCR trigger (`assessTextLayer`) so a searchable header over a scanned body OCRs the body; per-word confidence `[uncertain]` markers (`markLowConfidence`) + ingest warning.
- **Report/export fidelity (Step 114).** JSON `provenance` (DKB/engine/rule-taxonomy versions); portfolio `executive_summary` (rolled-up severity counts + per-document digest); `.ics` verify-manually events for unresolved deadlines. All outside the run.

### Added (Thrust B — proof, Steps 120, 125)
- **Node↔browser pipeline parity (Step 120).** `tools/accuracy/parity.test.ts` drives a shared fixture through both `runReport` (browser) and `runDocument` (Node accuracy harness) and asserts a byte-identical `EngineRun` — making v5's "the harness reuses the real pipeline" claim executable.
- **Responsiveness-as-a-test (Step 125).** `tests/e2e/responsiveness.spec.ts` asserts `scrollWidth ≤ clientWidth` per view-state at 320/390/768/1280 px — the manual responsiveness audit becomes a CI gate.

### Changed
- **`result_hash` re-baseline (Step 106, reviewed).** The new prohibitive/permissive modals surface previously-missed negative covenants; six goldens gained/raised an OBLI-005 "negative covenants" finding (line-reviewed — OBLI-005 only). Eleven bundle goldens got a mechanical `consistency.execution_log_count` bump 17 → 20 with no new findings on any pre-existing bundle.
- **Version 6.0.0 → 7.0.0** (Step 126). `ENGINE_VERSION` stays 0.1.0 (it feeds `result_hash`); the new `RULE_TAXONOMY_VERSION` is "7.0.0", stamped only into report provenance.

### Deferred (with reasons)
- **Step 109** (classifier live-routing) — held behind the v5 corpus; a routing change must be measured against real annotated documents.
- **Step 111** (50-state overlay + non-solicitation) — per-state enforceability is attorney-gated legal data under the v5 honesty contract.
- **Step 112** (rule-catalog depth) — a new always-on rule re-baselines every single-document golden's `execution_log` and needs a citable DKB source.
- **Steps 123–124** (Stryker mutation testing) — slow; belongs on a scheduled/on-demand job off the per-push path.

### Earlier v7 increments (Steps 115–122)
- **Schema fuzz + round-trip for the DKB (spec-v7 Step 121).** Added
  `src/dkb/schema-fuzz.test.ts` (+29 tests): every DKB artifact round-trips
  through `parse → serialize → parse`, the wrong top-level type is rejected, and
  a battery of single-field mutations (bad enum, missing-required, out-of-range,
  malformed URL/hash/ISO-datetime) is each rejected — testing that the schemas do
  their real job of *refusing* corruption, not just accepting valid input.
- **Per-rule completeness gate, measure-first (spec-v7 Step 117).** Added
  `tests/integration/rule-completeness.test.ts` (+2 tests): aggregates execution
  logs across the golden corpus to assert every always-on launch rule runs
  (112/112), and enforces a regression-only floor on how many launch rules are
  seen both to fire and to stay silent (measured 63/111/62 of 112; floors
  60/108/59). 49 launch rules have no positive case in the corpus yet — a now-
  visible gap and the ratchet's next target. Test-only; no `src/`/`result_hash`
  impact.
- **Metamorphic invariant testing (spec-v7 Step 119).** Added a suite
  (`tests/integration/metamorphic.test.ts`, +3 tests) asserting that a document
  and a copy with non-semantic whitespace noise produce the same `result_hash`
  and finding set, and that inserting a whitespace-only paragraph changes nothing.
  Tests what the engine *means*, not just that it is deterministic.

### Fixed
- **Determinism leak: heading whitespace bled into the result_hash.** The
  metamorphic suite caught it immediately — `normalize` collapsed whitespace in
  run text but stored section headings verbatim and advanced the offset cursor by
  the raw heading length, so two documents identical except for extra spaces/tabs
  in a heading produced different `result_hash`es. Fixed in `src/ingest/normalize.ts`
  by collapsing heading whitespace the same way run text is collapsed. **Zero golden
  churn** (real headings are clean single-spaced, so the collapse is a no-op for
  them; all 26 golden hashes unchanged) — the fix strictly adds whitespace-invariance.

### Added
- **Property-based testing (spec-v7 Step 118).** Added `fast-check` + a property
  suite (`tests/integration/property-based.test.ts`, +5 properties) over generated
  `DocumentTree`s — a new test *kind* that proves invariants over inputs no author
  enumerated: the normalizer is idempotent and assigns exact, non-overlapping
  offsets and drops empties; any US-dollar amount and any valid ISO date round-trips
  through its extractor. A fixed seed keeps the generated inputs identical on every
  machine/run (a non-deterministic gate is forbidden here). Raised coverage slightly
  (the properties exercise edge paths the example tests missed). Test/dev-dep only.

### Fixed
- **ESLint no longer lints generated coverage output.** Running `npm run coverage`
  before `npm run lint` left `coverage/` on disk and `eslint .` scanned it; added
  `coverage/` to the `eslint.config.js` global ignores (alongside `dist/`).
- **Property tests get a generous timeout.** Generating hundreds of recursive trees
  exceeds vitest's 5s default under V8 coverage instrumentation; the property file
  sets `testTimeout: 30_000` (same lesson as the pdfjs cold-load test) so the gate
  goes red on a real counterexample, never on a slow runner.

### Added
- **Report-structure validation (spec-v7 Step 122).** The DOCX report — the
  artifact a user cites — was tested only for ZIP validity + MIME type. Added 5
  tests (`src/report/docx.test.ts`) that unzip the generated `word/document.xml`
  and assert the report *says the right things*: the cover/audit-trail carry the
  title + engine/DKB versions + file fingerprint + result hash; findings render
  grouped Critical → Warning → Info (ordering anchored on the unique per-finding
  severity badges); cited findings render a `Sources: [n]` line + a Bibliography
  section; and the verbatim determinism/privacy/non-advice posture block is
  present. Also pins the JSON report's `{ run, ingest }` envelope shape and
  well-formed findings. Test-only; pins existing mature behavior (no `src/`,
  `result_hash`, golden, or responsiveness impact). Tests 2,502 → 2,507.
- **Code-coverage measurement + regression gate (spec-v7 Steps 115–116).** The
  suite had 161 files / 2,502 tests but **no coverage tooling or gate**. Added
  `@vitest/coverage-v8` + an `npm run coverage` script + a coverage block in
  `vitest.config.ts` scoped to the shipped `src/` bundle (build/CI-only harnesses
  and test scaffolding excluded). First measured baseline: statements 85.5% ·
  branches 72.4% · functions 87.1% · lines 87.5%. Regression-only floors (a couple
  points under each measured value — lines 85 · functions 85 · statements 83 ·
  branches 70) are wired into `.github/workflows/ci.yml` (coverage runs in place of
  the plain test step, which the cross-OS matrix keeps for determinism). The floors
  fail the build on a *drop*, never block on an aspiration — the same measure-first
  discipline the v5 accuracy scoreboard uses; a ratchet raises them as coverage
  climbs (branches is the next target). README "Build & verify" gains a coverage
  cheat-sheet. Config/CI/dev-dep only; no `src/`, `result_hash`, golden, or
  responsiveness impact.
- **spec-v7 — "Depth & Proof" (`docs/spec-v7.md`).** A full specification
  continuing the global step numbering from v6's Step 102 → Steps 103–126 (24
  steps), grounded in a codebase + test-surface audit. Two thrusts: **(A) Depth**
  — close v6 Step 98 extraction recall extractor-by-extractor, wire the measured
  `dkb/v4/sub-domain-features.json` classifier table into live routing (the
  dead-artifact gap, gated behind v5 + a reviewed golden re-baseline), more
  `CROSS-*` families, employment overlays → 50 states + a non-solicitation family,
  and deepen the thin rule categories. **(B) Proof** — the test *kinds* the suite
  lacks today (verified: 161 files / 2,502 tests, determinism pinned, but no
  coverage gate, no per-rule positive+negative completeness guarantee, and no
  property/metamorphic/mutation/parity/schema-fuzz/report-structure tests): vitest
  V8 coverage + regression-only gate, a per-rule completeness meta-test, fast-check
  property tests, a metamorphic invariant suite, Node↔browser pipeline parity,
  schema fuzz + round-trip, DOCX/JSON report-structure validation, Stryker mutation
  testing, and e2e/a11y expansion incl. responsiveness-as-a-test. Posture-clean and
  measure-before-gate throughout; makes the **testing ≠ accuracy** distinction
  explicit (Thrust B proves internal logic; v5 proves the legal premise). README
  version table + specs index updated. Doc-only; the spec is a plan, unimplemented.
- **Bundle per-doc multi-family activation** (spec-v6 multi-family, the noted
  follow-up). A composite document — an MSA embedding a DPA exhibit, say — is
  now scanned with **every** family it clearly contains when it arrives inside a
  multi-document bundle, not just its primary matched playbook. Previously this
  "don't-miss-anything" behavior ran only for a document dropped **by itself**;
  the same file produced a thinner report inside a deal folder. Now identical
  either way. Each document's per-doc DOCX/JSON download inside the bundle, the
  consolidated bundle report (an "Also checked (other detected families)" block
  in the DOCX; `secondary_families` on each `documents[]` entry in the JSON),
  and each multi-doc card in the bundle-complete view all surface the secondary
  families. Purely additive: the primary per-doc `run`/`result_hash`, the bundle
  fingerprint, and every golden are byte-unchanged; single-family bundles
  serialize identically to before. Secondary families run **only** their gated
  rules (no duplication of the launch rules that already ran). +6 tests.

### Fixed
- **spec-v4.md status was stale — said "not yet implemented" for shipped code.**
  v4 has been complete and shipped (version 4.0.0) for some time — 730 rules, 16
  sub-domains, bundle ingest, the classifier — yet its spec header still read
  "specification, not yet implemented," which would tell a reader the whole
  surface is vaporware. Updated to an accurate ✅-complete status mirroring
  spec-v5/v6, including the Part VII open-question state. Also added a matching
  status line to spec-v3.md (shipped 3.0.0), which had none. Doc-only.

### Changed
- **README — performance / first-paint load-path section.** Added a
  "Performance — the first-paint path is tiny on purpose" section quantifying
  what the README previously only asserted (a whole engine that "runs entirely
  in your browser"). Documents the eager first-paint set (≈29 KB gz: the
  self-contained `index.html`+inline-CSS plus the `main`+runtime entry — **zero**
  vendor chunks, verified against the built `dist/index.html` preload set) versus
  the lazy chunks loaded per interaction (pipeline/engine + format-specific parser
  on file drop; report + `vendor-docx` on export; tesseract only on a scanned
  PDF), the `modulePreload`-filtering design decision that keeps pdfjs off the
  critical render path, and the Lighthouse CI budget (FCP ≤ 1.8 s, TTI ≤ 2.0 s,
  perf ≥ 0.85, a11y ≥ 0.95) that fails the build on regression. All numbers taken
  from the live `vite build` output and `lighthouserc.json`. Doc-only; no `src/`,
  `result_hash`, or responsiveness impact.
- **README — cross-document consistency cheat sheet.** The headline "1,062
  rules" and the rule cheat-sheet count only *single-document* rules; the engine
  also runs **17 cross-document consistency rules** (`CROSS-*` + `CC-*`) on
  folder/`.zip` bundles — conflicting governing law, indemnity-cap stacking,
  defined-term drift across the set, BAA↔MSA scope, etc. That capability was
  mentioned only in passing under v6; added a cheat-sheet table documenting all
  of it. Verified against the live `ALL_CONSISTENCY_RULES` (exactly 17). Headline
  stats re-confirmed accurate (1,062 = 112+220+730; 35 overlays). Doc-only.

### Added
- **Documentation link-integrity guard** (`tests/integration/docs-links.test.ts`).
  Walks every authored `.md` file and fails if any relative link doesn't
  resolve to an existing file — turning the prior one-off 29-link fix into a
  permanent CI gate so stale references can't creep back. Strips fenced/inline
  code first so *illustrative* link syntax in examples isn't flagged;
  leading-slash links resolve from the repo root (as GitHub renders them); and
  it compares the on-disk canonical case (`realpathSync.native`) so wrong-case
  links — which "resolve" on case-insensitive macOS but 404 on GitHub/Linux —
  are caught on any OS. On its first run it caught exactly such a bug: the
  README's "Architecture" link pointed at lowercase `docs/architecture.md`
  while the file was misnamed `docs/ARCHITECTURE.md`. Verified to fire (both a
  missing-file and a wrong-case link injected into a doc fail the test).

### Fixed
- **README "Architecture" doc link 404'd on GitHub.** `docs/ARCHITECTURE.md`
  was renamed to lowercase `docs/architecture.md` to match the README link,
  CONTRIBUTING's prose, and the lowercase convention of every other doc (the
  mismatch was invisible on case-insensitive macOS).
- **OCR orchestration tests** (`src/ingest/ocr.test.ts`, +6). `ocr.ts` was the
  last ingest entrypoint with no coverage. The real engine (tesseract.js WASM +
  a downloaded language model) and canvas rasterization can't run headless, so
  they're mocked — this does **not** verify OCR accuracy (that needs a real
  device), but it pins the logic we own: the per-page loop, the `\n\n`
  page-separator contract downstream paragraph detection depends on, the
  progress callback cadence, and that the worker is always `terminate()`d —
  even when recognition throws — so the engine never leaks. Every ingest
  entrypoint now has a unit test.
- **PDF text-extraction regression tests** (`src/ingest/pdf.test.ts`). The
  `ingestPdfBuffer` → pdfjs path — the primary ingest route — had **zero**
  automated coverage: the suite stayed green regardless of whether pdfjs parsed
  anything, which made a pdfjs major bump unverifiable. New tests build a
  structurally-valid PDF in-process (correct `xref` offsets, real text layer)
  and assert the real pdfjs engine extracts it, hashes deterministically, and
  returns no warnings. This is what made the pdfjs 4→6 bump below a *verified*
  change rather than a hopeful one.

### Fixed
- **Latent buffer-detach fragility in PDF ingest.** `ingestPdfBuffer` hashed the
  source bytes *after* `getDocument`, but pdfjs takes ownership of the
  ArrayBuffer and may detach it (it does under pdfjs's Node fake-worker; the
  browser's copying worker happened to leave it intact). The hash now runs
  *before* the buffer is handed to pdfjs — same bytes, identical hash, no
  `result_hash`/golden change — making the path robust in any environment and
  testable headless.

### Changed
- **Doc-integrity sweep — fixed 29 broken internal markdown links.** A scan of
  all 64 tracked markdown files found stale relative links, almost all from the
  spec files having moved into `docs/` (root/nested references kept the old
  paths and wrong `../` depths). Also corrected one stale filename
  (`ccpa-civ-code.ts` → the consolidated `state-privacy.ts`) and a fragile
  leading-slash link. Re-scan confirms 0 broken links. Markdown-only.
- **`no-console` lint guard on the shipped `src/` bundle.** CONTRIBUTING
  promised "console is restricted," but the ESLint config never enforced it.
  `src/` already carries **zero** `console.*`, so the rule is added with no
  churn — a regression guard that keeps stray debug logs (noise, and a
  potential info-leak of document content to DevTools in a "nothing leaves the
  tab" tool) out of the deployed code. Scoped to non-test `src/`; `tools/`,
  `dkb/`, and tests log freely. CONTRIBUTING's code-style note corrected to
  state the actual enforcement precisely (warnings vs errors; ESLint vs `tsc`).
- **README — "What you can drop in" ingest cheat sheet.** A new section + table
  documents how each input is handled (digital PDF → pdf.js text extraction;
  scanned PDF → lazy OCR fallback; DOCX → mammoth; pasted text; folder/`.zip` →
  bundle mode with cross-document consistency), the deterministic source hash,
  and the in-tab privacy posture — closing the "can I use this on *my*
  documents?" gap the prior one-box flowchart left. Verified against the live
  ingest code (`allowOcr: true` is wired in `pipeline.ts`; `.zip` unpacks via
  fflate). Doc-only.
- **Major dependency modernization: pdfjs-dist 4 → 6** (`^4.2.67 → ^6.0.227`,
  GA, skipping 5). Verified against the new text-extraction tests: pdfjs 6
  still ships the `legacy/build/pdf.mjs` entry we import, and extraction is
  byte-correct. **Honest cost:** the non-eager `vendor-pdfjs` chunk grew
  112.77 → 146.03 KB gzipped (+33 KB) — total gzipped JS is now ~713 KB against
  the 1065 KB ceiling (bundle-size test green), and pdfjs loads only when a PDF
  is dropped (excluded from modulepreload), so first-paint is unaffected
  (Lighthouse green). **OCR-path caveat:** the scanned-PDF fallback
  (`ocr.ts`, which renders pages to a canvas for tesseract.js) is not
  headless-testable and is **left unchanged** — pdfjs 6 reworked `render`
  (`canvas` is now primary, `canvasContext` backwards-compatible with `canvas`
  defaulting from the context), and our `canvasContext`-only call remains
  supported; real-device validation of the OCR fallback stays pending (a
  pre-existing gap, not a regression). 0 vulnerabilities. (Last deferred major:
  tesseract.js 5→7 — the OCR engine, same untestable-headless path.)
- **Major dependency modernization: ESLint 9 → 10** (`eslint ^9.39 → ^10.4`,
  `@eslint/js ^9 → ^10`, `globals ^16 → ^17`). The flat config carries over
  unchanged. ESLint 10 promotes two rules into `js.configs.recommended` that
  surfaced 5 genuine findings, all **fixed** (not disabled): `no-useless-
  assignment` flagged dead default-initializers that both the `try` and `catch`
  always overwrite (in the two engine runners + the accuracy pipeline loader) —
  removed, since the variable is definitely-assigned after the try/catch and the
  initializer was never read (behavior-preserving, no `result_hash` change);
  `preserve-caught-error` flagged two golden test-helper re-throws that dropped
  the original error — now attach `{ cause: e }`, improving the error chain when
  a playbook fails schema validation. ESLint 10 requires Node `^20.19 ||
  ^22.13 || >=24`, satisfied by CI's `node-version: 22` (installs the latest
  22.x) and `.nvmrc`. typescript-eslint@8.60 (peer `eslint ^10`) emits no
  unsupported-version warning. Gate green (lint 0 problems + typecheck + 2486
  tests + build), clean `npm ci`, 0 vulnerabilities. (Remaining deferred
  majors: pdfjs-dist 4→6, tesseract.js 5→7.)
- **Major dependency modernization: TypeScript 5.9 → 6.0** (`^5.4.5 → ^6.0.3`,
  GA). Zero code changes — `tsc --noEmit` passes clean. The codebase was
  already TS-6-ready: the tsconfig carries none of the long-deprecated options
  TS 6.0 turns into errors (`importsNotUsedAsValues`, `preserveValueImports`,
  `keyofStringsOnly`, ES3 targets, …), `target`/`module` are modern
  (ES2022/ESNext), and the existing `strict` + `noUncheckedIndexedAccess`
  settings already satisfy 6.0's stricter checks. Only `npm run typecheck`
  (tsc) and the linter (typescript-eslint, whose `<6.1.0` peer range covers
  6.0 — no unsupported-version warning) consume the `typescript` package; vite
  and tsx transpile via esbuild, so there is no transpile or runtime change.
  Gate green (lint + typecheck + 2486 tests + build), clean `npm ci`, 0
  vulnerabilities. (Remaining deferred majors: eslint 9→10 + globals 16→17,
  pdfjs-dist 4→6, tesseract.js 5→7.)
- **Major dependency modernization: zod 3 → 4** (`^3.23.4 → ^4.4.3`). The
  validation library underpinning every DKB / playbook / accuracy / custom-rule
  schema is now on the current major (zod 3 will eventually lose maintenance).
  The bare `"zod"` import resolves to zod 4's recommended **classic** API, which
  retains `.url()` / `.strict()` / `.finite()` / `.nonnegative()` (none flagged
  `@deprecated`) and the two-arg `z.record(key, value)` form the codebase
  already used — so the **only** code change was the one API zod 4 removed:
  `z.ZodIssueCode.custom` → the string literal `"custom"` (4 `superRefine`
  sites, the form the zod 4 migration guide recommends; fully covered by the
  custom-playbook validation tests). All 2486 tests, typecheck, and build pass.
  **Honest cost:** zod 4 classic is *larger* than zod 3, not smaller — the
  `vendor-zod` chunk grew 12.98 → 19.39 KB gzipped (+6.4 KB). The smaller-core
  benefit only comes from `zod/mini`'s functional API, which would mean
  rewriting every schema (out of scope). The increase is well within the bundle
  budget (total ~705 KB gzipped vs the 1065 KB ceiling) and `vendor-zod` is a
  non-eager chunk, so first-paint (the eager `main` entry) is unaffected.
  0 vulnerabilities. (Other deferred majors unchanged: eslint 9→10, typescript
  5.9→6.0, pdfjs-dist 4→6, tesseract.js 5→7.)
- **Dependency hygiene pass.** `@types/node` `^20 → ^22` to match the Node 22
  runtime baseline (the *supported floor*, not the newer `^25`, so the types
  never permit an API the CI runtime lacks). Refreshed every in-range
  patch/minor to current: `docx` 9.6.1→9.7.1, `vite` 8.0.13→8.0.16, `vitest`
  4.1.6→4.1.8, `tsx` 4.21.0→4.22.4, `happy-dom` 20.9.0→20.10.1, `js-yaml`
  4.1.1→4.2.0. `npm audit` reports **0 vulnerabilities**; the full gate
  (lint + typecheck + 2486 tests + build) and a clean `npm ci` stay green —
  notably the `docx` minor did not perturb any report test (the DOCX tests
  assert structure/content, not bytes). **Deferred majors** (each a real
  breaking-change migration, left for a deliberate individual pass): `eslint`
  9→10 / `globals` 16→17 (the ecosystem still settling on v9), `typescript`
  5.9→6.0, `zod` 3→4, `pdfjs-dist` 4→6, `tesseract.js` 5→7.
- **Linting: migrated ESLint 8 (EOL) → ESLint 9 flat config.** ESLint 8 reached
  end-of-life in October 2024 and its legacy `.eslintrc` system pulled the
  deprecated `inflight`, `rimraf@3`, and `@humanwhocodes/config-array` /
  `object-schema` transitive packages (the `npm install` deprecation warnings).
  `.eslintrc.cjs` → `eslint.config.js` (flat config); `eslint@^8 → ^9.39`;
  the separate `@typescript-eslint/{parser,eslint-plugin}@^7` → the unified
  `typescript-eslint@^8.60` meta-package; `eslint-config-prettier@^9 → ^10`
  (using its `/flat` export); added `@eslint/js@^9` and `globals@^16`. The
  config is **behavior-preserving** — same ignores, same browser+node globals
  (the old `env` block), same two rule overrides (`no-unused-vars` warn with
  `^_` ignore, `no-explicit-any` warn). typescript-eslint v8's recommended set
  surfaced **0 new errors**. ESLint 9's default `reportUnusedDisableDirectives`
  flagged 5 dead `// eslint-disable-next-line no-console` comments (the
  `no-console` rule was never enabled) in tools/tests that legitimately log;
  removed. A fresh `npm install` now emits **zero** deprecation warnings, and
  `npm ci` resolves cleanly. (ESLint 10 exists but typescript-eslint's mature
  support targets v9; revisit once the v10 ecosystem settles.)
- **CI: migrated every GitHub-published action off the deprecated Node 20
  runtime.** GitHub is forcing Node 20 actions to Node 24 by 2026-06-16; all
  five workflows now pin the current Node-24 majors —
  `actions/checkout@v4 → v6`, `actions/setup-node@v4 → v6`,
  `actions/cache@v4 → v5` (dkb-rebuild), `actions/upload-artifact@v4 → v7`
  (deploy + lighthouse failure paths). No API changes affect our usage:
  `setup-node`'s new auto-caching is inert because we set `cache: "npm"`
  explicitly and ship no `packageManager` field; `cache`/`upload-artifact`
  inputs are unchanged; GitHub-hosted runners exceed the new minimum runner
  version. Third-party actions (`cloudflare/wrangler-action`,
  `peter-evans/create-pull-request`) are unchanged — they run only in
  secret-gated/scheduled jobs, not the public gate.
- **Project Node baseline raised 20 → 22 LTS** (`.nvmrc`, `package.json`
  `engines` `>=20 → >=22`, every workflow `node-version`/matrix entry). Node 20
  reached end-of-life on 2026-04-30; the suite already passes on Node 25
  locally and on 20 in CI, so Node 22 is safely bracketed. `result_hash` is
  Node-version-independent (SHA-256 over canonical JSON), so determinism is
  unaffected.

### Added
- **v5 Step 75 — legal-basis ledger scaffolding + `tier` on `Rule`/`Finding`**
  (spec-v5 Part III). New `RuleTier` (`established` / `prevailing-practice` /
  `opinion`) is added as an **optional** field on `Rule` and `Finding`;
  `makeFinding` copies it through only when set, so an unsigned rule omits the
  field and `result_hash` is byte-unchanged (same additive discipline as the
  existing `source?` marker — verified zero golden churn). The ledger schema +
  loader live in `tools/accuracy/legal-basis.ts` (build-and-CI-only; `src/`
  never imports it), with an honestly-empty machine mirror at
  `docs/legal-basis/ledger.json` and a documented protocol in
  `docs/legal-basis/README.md`. `tierForRule` bakes in spec-v5 §14: an
  `unsound` verdict surfaces no tier (the rule is retired, not shown) and a
  `disputed` verdict caps the tier at `opinion`. A machine-mirror test
  (`tests/integration/legal-basis-ledger.test.ts`) enforces schema validity,
  no duplicate `rule_id`, rule + DKB referential integrity, and — load-bearing
  — that **every inline `Rule.tier` is backed by a signed ledger entry**, so a
  surfaced tier badge can never be author-asserted. No attorney has signed yet
  (Steps 76/77 are human-gated); the ledger reports an honest 0-of-N coverage.

### Changed
- README.md gains real product imagery (`docs/images/hero.png`,
  `docs/images/report-mobile.png`) — actual headless renders of the
  shipped UI (dark-theme landing hero; the `complete`-state result
  card at a 390 px phone width) — and a one-word accuracy fix in the
  project layout ("four document states" → "six-state result machine",
  matching the `empty`/`analyzing`/`complete`/`comparison-complete`/
  `bundle-complete`/`error` machine). Images live under `docs/`, so
  they touch neither the deployed bundle nor the Lighthouse budget.
  Headline counts re-verified against live code (1,062 rules; 35 state
  overlays; 2,468 tests; v6.0.0). Doc-only; no test impact. Full-surface
  responsiveness (no horizontal scroll, 320–1280 px, all six view
  states) was re-verified empirically — see `BUILD_PROGRESS.md`.

## [6.0.0] — 2026-06-01

The 4.0.0 → 6.0.0 release. The package version jumps straight from 4.0.0 to
6.0.0: v5 (Ground Truth) is specified and its measurement infrastructure is
built, but its published accuracy numbers are human-gated, so it never took a
standalone package bump; v6 (Workflow) is the release that closes out the
sequence. The `ENGINE_VERSION` that feeds `result_hash` is deliberately
**unchanged at `0.1.0`** — every v6 surface is additive and lives outside the
`EngineRun`, so no existing report hash moved. The full per-step rationale
accumulated under `[Unreleased]` during the build is preserved as the detail
sections beneath this summary.

### v6 — Workflow (Steps 87–102)

Six feature parts, each passing the five-part posture filter (deterministic ·
no AI · no server · citable · lints-not-drafts):

- **Part I — Version comparison (Steps 89–90).** Drop a base and a revised
  document; get a deterministic finding-delta (resolved / introduced /
  unchanged / carried-clean) with a comparison hash
  `SHA-256(base_hash + revised_hash + canonical(delta))`, a compare UI, and a
  DOCX/JSON comparison report.
- **Part II — Bring-your-own playbook (Steps 91–94).** A team encodes its own
  positions as a user-authored `.json` playbook, validated **client-side** against
  a public versioned schema (`docs/v6/playbook.schema.json`; authoritative Zod
  in `src/playbooks/custom-playbook.ts`) — declarative data, never executable
  code. A bounded six-predicate DSL interpreter (`src/playbooks/custom-interpreter.ts`)
  evaluates it with no `eval` and no network; predicates it cannot evaluate are
  reported, never guessed. Load-a-playbook UI (augment vs replace; findings
  carry `source: custom-playbook` provenance and cite the team's own authority);
  authoring guide + two worked examples. A privacy guard test asserts zero
  egress across the full load→validate→enforce path.
- **Part III — Findings to action (Steps 87–88).** Export the fix-list (Markdown
  + CSV), the obligations ledger (CSV), and deadlines as an `.ics` calendar with
  notice windows computed deterministically (`term end − notice period`);
  ambiguous dates are listed "verify manually," never guessed.
- **Part IV — Model-clause references (Steps 95–96).** For a finding whose rule
  has an associated public model clause, the rule card points to an attributed
  reference into Common Paper / Bonterms / the EU SCCs (source URL + license) —
  a reference, never a generated redline. `src/dkb/model-clauses.ts`; surfaced
  outside the `EngineRun`, coverage published honestly.
- **Part V — Portfolio risk matrix (Step 97).** A deal-folder bundle gains a
  documents × key-checks grid (liability cap · auto-renewal · governing law ·
  data-processing terms · breach-notice) plus rollups; a rule that did not run
  renders an honest grey `N/A`, never a wrong "Risk." `portfolio_fingerprint`
  extends the bundle fingerprint; a 50-row scale guard reports the true total.
- **Part VI — Depth (Steps 99–101).** The sub-domain classifier's feature table
  was re-engineered, lifting top-1 accuracy **70.7% → 100%** (75/75) on the
  labeled golden corpus and resolving the four named confusions — still a
  hand-authored, inspectable table, no model. The cross-document consistency
  engine grew **7 → 10** CROSS-\* families (defined-term *usage* drift,
  indemnity-cap stacking, confidentiality survival-period conflict).
  Jurisdiction overlays: **35** per-(family × state) state-law deltas across the
  three families where state law dominates — employment non-compete (15 states),
  residential-lease deposit (10), lending usury (10) — surfaced as a citable
  reference layer outside the `EngineRun`, with honest `uncovered_states`.
- **Full-catalog wiring + multi-family activation.** The live pipeline now
  serves the v3+v4 playbook catalog (`playbooks/extended.json`) and runs all
  **1,062** rules (LAUNCH 112 + V3 220 + V4 730), family-gated via
  `selectMatchCandidates` so a plain NDA is unaffected, and a composite document
  runs every family it clearly contains. (Before this, only the 112 launch rules
  fired in production — the other 950 gated to playbook ids that were never
  served.)
- **Step 98 (extraction recall)** is deliberately deferred behind v5 measurement
  (spec-v6 Part IX #7).

### v5 — Ground Truth: measurement infrastructure (Steps 67, 69, 71, 83)

The accuracy & validation harness that measures the engine against real
contracts it did not write, built and unit-tested under `tools/accuracy/`
(`npm run accuracy`): corpus scaffolding + provenance + deterministic PII
redaction (67); the gold-annotation schema + Cohen's κ inter-annotator
agreement + annotation protocol (69); the full-catalog Node pipeline (the same
`ingest → extract → classify → engine` path the browser uses) + closed-world
TP/FP/FN/TN + precision/recall/F1 (macro + micro) + a reproducible SHA-256
scoreboard (71); and the privacy/determinism guards asserting no `src/` file
imports `tools/accuracy` or `corpus/`, so corpus bytes never reach the deployed
bundle (83). The committed scoreboard honestly reports `status: empty` — no
precision/recall number is published until real license-clean documents and
credentialed-attorney annotation land (human-gated Steps 68/70/73–77/85).

### Changed
- `package.json` version bumped from `4.0.0` to `6.0.0`; `ENGINE_VERSION`
  unchanged at `0.1.0` (feeds `result_hash`, so bumping it would churn every
  golden).

### Detail — entries accumulated under `[Unreleased]` during the v4-follow-up → v6 build

The entries below were logged incrementally during the post-4.0.0 build
sequence and are preserved here so the per-step rationale is part of the
6.0.0 release record.

### Changed
- README.md + marketing site (`site/index.html`) updated to reflect
  the current rule counts: v1 launch is 112 rules (was "~80"),
  v3 adds 220, v4 adds 730, total is 1,000+ (was "~145"). Four
  stale references corrected: `README.md` headline, the schema.org
  `SoftwareApplication.featureList` entry, the `SoftwareApplication.description`
  text, the on-page "What I check" paragraph, and the architecture-
  diagram inline SVG label.
  - No static-HTML tests pin the counts, so this is doc-only with
    no test impact.

### Added
- Single-doc JSON report surfaces `playbook_deprecated` +
  `playbook_superseded_by` alongside `run` / `ingest` (closes the
  single-doc ↔ bundle JSON parity gap on deprecation; the bundle
  JSON has carried the per-entry fields since 943d114). Fields are
  emitted only when the matched playbook carries `deprecated: true`
  in its JSON, so JSON output for non-deprecated playbooks is
  byte-identical to prior output.
  - [`src/report/json.ts`](src/report/json.ts) `buildJsonReport`
    gains an optional third `playbook?: Playbook` parameter. The
    fields live alongside `run` / `ingest` (not inside `run`)
    because adding to the run would change `result_hash`.
  - [`src/ui/pipeline.ts`](src/ui/pipeline.ts): both single-doc
    pipeline call-sites thread the matched playbook into
    `buildJsonReport`.
  - [`src/report/docx.test.ts`](src/report/docx.test.ts): +3 tests
    (deprecated path, explicitly non-deprecated, playbook arg
    omitted).

- DOCX audit-trail Playbook line surfaces deprecation. Mirrors the
  annotation already on the cover (commit edc1ff9) so the in-report
  audit trail is self-consistent — a reviewer scrolling to the
  Audit Trail section sees the same legacy hint as the cover.
  - [`src/report/docx.ts`](src/report/docx.ts) `renderAuditTrail`
    appends `— legacy; superseded by <id>` (or `— legacy`) to the
    Playbook line when `playbook.deprecated === true`.
  - [`src/report/docx.test.ts`](src/report/docx.test.ts): the
    existing deprecated-cover test now also asserts the substring
    appears at least twice in `word/document.xml` (once in the
    cover, once in the audit trail).

- UI complete-state and bundle-complete cards surface playbook
  deprecation (closes the user-visible feedback loop for the v2 NDA
  deprecation — single-doc DOCX cover landed in edc1ff9, bundle
  DOCX + JSON landed in 943d114; this commit lands the on-page
  affordance).
  - [`src/ui/states.ts`](src/ui/states.ts): complete-state gains
    optional `playbook_deprecation?: { superseded_by?: string }`.
    When present, the reasoning line is appended with
    "Legacy playbook — superseded by <id>." (or "Legacy playbook."
    when `superseded_by` is absent). Multi-doc card `documents[]`
    gains optional `playbook_deprecated?: boolean`; when true the
    card's playbook label is suffixed " (legacy)".
  - [`src/ui/main.ts`](src/ui/main.ts): both single-doc and bundle
    paths thread `result.playbook.deprecated` +
    `result.playbook.superseded_by` end-to-end. The narrow
    inline-type for the single-doc helper widened to include the
    two optional Playbook fields.
  - [`src/ui/states.test.ts`](src/ui/states.test.ts): +4 tests
    (single-doc with successor, single-doc no successor,
    single-doc back-compat omits the suffix, multi-doc card
    annotation across mixed states).

- Bundle DOCX + JSON surface per-document playbook deprecation
  (spec-v3 §27 follow-up; companion to the single-doc DOCX cover
  addition in commit edc1ff9). When a deprecated playbook matched
  for any document in a bundle, the per-document subsection's
  "Playbook:" line in the bundle DOCX is annotated with
  "— legacy" or "— legacy; superseded by <id>", and the bundle
  JSON's `documents[]` entry carries optional `playbook_deprecated`
  + `playbook_superseded_by` fields. Non-deprecated bundles
  serialize byte-identically to prior output.
  - [`src/report/bundle.ts`](src/report/bundle.ts):
    `BundleDocument` gains optional `playbook_deprecated?: boolean`
    + `playbook_superseded_by?: string`; `BundleJsonDocument`
    mirrors them. The DOCX renderer reads them on the per-doc
    Playbook line; the JSON emitter sets them per-entry when
    `playbook_deprecated === true`.
  - [`src/ui/pipeline.ts`](src/ui/pipeline.ts): the bundle pipeline
    threads `d.playbook.deprecated` + `d.playbook.superseded_by`
    into each `BundleDocument` so production bundles carry the
    signal end-to-end.
  - [`src/report/bundle.test.ts`](src/report/bundle.test.ts): +2
    tests covering DOCX annotation (mix of deprecated +
    superseded_by, deprecated alone, non-deprecated) and JSON
    emission shape.

- DOCX cover surfaces playbook deprecation. When a deprecated
  playbook matches (e.g. v2 `mutual-nda`), the Playbook line on the
  cover now reads
  `Mutual Non-Disclosure Agreement (mutual-nda v1.0.0) — match
  confidence 0.92 — legacy; superseded by mutual-nda-deep`. A
  reader of the report alone — without the playbook JSON open — can
  see they were analyzed against a legacy playbook and which one
  supersedes it.
  - [`src/report/docx.ts`](src/report/docx.ts) `renderCover` reads
    the optional `deprecated` + `superseded_by` Playbook fields.
    Non-deprecated playbooks render byte-identically to before.
  - [`src/report/docx.test.ts`](src/report/docx.test.ts) +2 tests:
    deprecated-path asserts the suffix appears in `word/document.xml`,
    non-deprecated path asserts neither "legacy" nor "superseded by"
    appears.

### Changed
- v4 bundle MSA + SOW fixtures pinned via `.playbook` sidecars so they
  route to `msa-general` / `sow` instead of NDA / SaaS playbooks.
  Adopts the v3 golden-harness pattern (pin per-doc playbook on
  bundle fixtures so the bundle test focuses on the consistency
  engine's cross-doc semantics, not on playbook routing).
  - 8 `tests/golden/v4/bundles/*/msa.txt.playbook` (all → `msa-general`).
  - 4 `tests/golden/v4/bundles/*/sow.txt.playbook` (all → `sow`).
  - All 8 bundle goldens at `tests/golden/v4/bundle-expected/`
    regenerated; only `per_document.result_hash` and
    consistency `result_hash` changed.

### Deprecated
- v2 `mutual-nda` and `unilateral-nda` playbooks are now marked
  `deprecated: true` in their JSON, with `superseded_by` pointing to
  the v3 `mutual-nda-deep` / `unilateral-nda-deep` successors.
  - [`src/playbooks/types.ts`](src/playbooks/types.ts) `Playbook` type
    and Zod schema gain optional `deprecated` + `superseded_by`
    fields.
  - [`playbooks/mutual-nda.json`](playbooks/mutual-nda.json) and
    [`playbooks/unilateral-nda.json`](playbooks/unilateral-nda.json)
    carry the new fields. The ids are intentionally unchanged so the
    13+ stable callsites in src/ and tests/ continue to work and the
    v2 launch-surface engine-run hashes stay byte-identical.
  - [`src/playbooks/matcher.ts`](src/playbooks/matcher.ts) gains a
    tiebreak: when two playbooks score the same `raw_score`, a
    non-deprecated playbook beats a deprecated one before the
    lexicographic id tiebreak fires.
  - Surfaces a real improvement on the v4 bundle MSA fixtures
    (clean-msa-baa / missing-companion-dpa / precedence-clash): the
    MSAs were previously tying at 0.8 between `mutual-nda` and
    `saas-vendor` and lex-order would pick `mutual-nda` for an MSA;
    the deprecation demotion now picks `saas-vendor` for the tie.
    Three bundle goldens regenerated.
  - Closes the remaining Step 27 follow-up flagged at
    `BUILD_PROGRESS.md` (the "deprecate v2 mutual-nda /
    unilateral-nda" item; the auto-detect re-pointing half was
    already done via `FAMILY_TO_PLAYBOOK["nda-deep"]` +
    `resolveNdaDeepVariant`).

### Added
- v3 `detectV3Family` defined-term signals across the remaining
  contract-style detectors (the form-style detectors — SCC, UK IDTA,
  ACORD-25 — keep their `void extracted;` shims by design because the
  underlying documents are pre-printed regulator / industry forms with
  no meaningful definitions section).
  - [`src/ui/v3/auto-detect.ts`](src/ui/v3/auto-detect.ts) `detectNdaDeep`
    emits `Confidential Information defined` (weight 2) and `Discloser /
    Recipient defined` (weight 1) from `extracted.definitions.entries`.
  - `detectMsaDeep` emits `Services defined` + `Order Form / SOW
    defined` (weight 1 each).
  - `detectVendorSecurity` emits `Customer / Personal Data defined` +
    `Security Measures defined` (weight 1 each).
  - `detectAiAddendum` emits `Model / Foundation Model defined` +
    `Training Data / Output defined` (weight 1 each).
  - All signals are additive — no existing weights change, no fixtures
    regenerated, no goldens shifted. The `source: "definition"`
    classification matches what `detectBaa` / `detectDpaEu` /
    `detectDpaUsState` already use.
  - [`src/ui/v3/v3-ui.test.ts`](src/ui/v3/v3-ui.test.ts): 4 new tests,
    one per detector, each with body text intentionally sparse enough
    that the definition signal carries non-redundant weight.

### Changed
- v3 `detectV3Family` now routes the `nda-deep` family to either
  `mutual-nda-deep` or `unilateral-nda-deep` based on symmetry
  signals, instead of unconditionally suggesting the mutual variant.
  Both playbooks now ship at v1.0.0 with distinct compliance-matrix
  columns (mutual symmetry vs. discloser / receiver role framing);
  the prior hard-coded mapping meant a document self-titled "One-way
  NDA" would still suggest the mutual playbook and render the wrong
  matrix column on accept.
  - [`src/ui/v3/auto-detect.ts`](src/ui/v3/auto-detect.ts): new
    `resolveNdaDeepVariant(text)` helper scores mutual-vs-unilateral
    title and role-framing cues and picks the matching playbook.
    Ties default to mutual (the safer fallback — mutual rules include
    a symmetry check the unilateral playbook does not, so misrouting
    a unilateral document under mutual produces a correctable
    false-positive surface; the inverse silently misses a rule).
    Resolver signals are appended to the detection audit trail.
  - Family id (`nda-deep`), `V3_FAMILY_LABELS["nda-deep"]`, fixtures,
    goldens, and consistency-engine `kindOf` resolver all unchanged
    — only `suggested_playbook` gains a second possible value.
  - [`src/ui/v3/v3-ui.test.ts`](src/ui/v3/v3-ui.test.ts): 3 new tests
    pinning mutual-route, unilateral-route, and tie-fallback cases.

### Fixed
- Replaced two `github.com/clay-good/vaulytica/blob/main/spec-v4.md`
  citation URLs with canonical anchors on `https://vaulytica.com`.
  Both citations belong to self-referential disclaimer rules
  (EST-060, REG-040) that previously cited the project's own spec
  via a mutable branch in GitHub's code-hosting UI — not something a
  partner can sign off on. The inline citation text in each rule's
  `source` field already names the exact spec section (§6.N for
  EST-060, §6.P for REG-040), so the auditable reference is now
  self-contained in the citation row.
  - [`src/engine/rules/v4/trust-estate/rules.ts`](src/engine/rules/v4/trust-estate/rules.ts)
  - [`src/engine/rules/v4/regulatory-prose/rules.ts`](src/engine/rules/v4/regulatory-prose/rules.ts)
  - 10 v4 golden fixtures regenerated; `result_hash` drift contained
    to exactly the two affected rules.

### Added
- DOCX report: real parties / dates / amounts / definitions /
  jurisdictions tables in the Extracted Data Appendix, and the
  obligor / modal / action / trigger ledger in the Obligations
  Ledger (closes the long-standing Step 9 follow-up noted in
  `BUILD_PROGRESS.md`).
  - [`src/report/docx.ts`](src/report/docx.ts) `buildDocxReport` now
    accepts an optional sixth parameter `extracted?: ExtractedData`.
    When threaded, `renderExtractedAppendix` renders parties (name /
    role / entity type / formation jurisdiction), dates (raw / type /
    ISO / anchor + offset), amounts (raw / currency / amount / word
    form), defined terms (term / definition / use count + an unused-
    terms line), and jurisdictions (clause kind / raw text /
    normalized id). `renderObligationsLedger` renders the full
    obligor / modal / action / trigger-qualifier table instead of the
    finding-derived two-column summary. Without `extracted`, the
    legacy counts-only appendix and finding-derived ledger render
    unchanged.
  - [`src/ui/pipeline.ts`](src/ui/pipeline.ts) threads
    `prepared.extracted` (single-doc) and `extracted` (bundle path)
    through to `buildDocxReport`.
  - [`src/report/docx.test.ts`](src/report/docx.test.ts) adds 2 tests:
    one verifying the enriched DOCX is larger than the baseline when
    extracted data is provided, one pinning the legacy counts-only
    fallback path.

### Added
- Compliance-frame UI toggle re-run (closes the remaining
  v3-o follow-up; spec-v3 §61).
  - [`src/ui/pipeline.ts`](src/ui/pipeline.ts) is now factored into
    two phases. `prepareDocument` does the slow ingest + DKB load +
    extract + playbook match and returns a `PreparedDocument`.
    `runReport` does the engine run + report build against a
    prepared payload (frame-aware via `options.active_frames`).
    `runPipeline` chains them and returns `result.prepared`
    alongside the report so the UI can retain it.
  - [`src/ui/main.ts`](src/ui/main.ts) `runFile` builds a re-run
    closure that calls `runReport` directly when chips toggle —
    no PDF re-parse, no DKB re-fetch. Rapid toggles are coalesced
    via a pending-frame slot so an in-flight re-run never queues
    a backlog.
  - [`src/ui/states.ts`](src/ui/states.ts) `complete` state accepts
    `on_frames_change?: (active_frames) => void`. The chip-toggle
    handler invokes it with the *current union* of active frames
    after each flip, sourced from a closure-shared `Set`.
  - [`src/ui/states.test.ts`](src/ui/states.test.ts) gains one test
    that drives a 3-step toggle sequence (HIPAA off, GDPR on, HIPAA
    back on) and asserts the callback receives the expected unions.

### Added
- Engine-side compliance-frame rule filtering (spec-v3 §61, the named
  follow-up to LAUNCH row v3-o).
  - [`src/ui/frame-filter.ts`](src/ui/frame-filter.ts) (new) ships the
    pure functions `framesForRule(ruleId)` and `filterRulesByFrames(rules,
    activeFrames)`. The frame ↔ rule-id-prefix map covers every rule
    family currently in v3: BAA-* → HIPAA, DPA-* → GDPR, USDPA-* → all 8
    US state privacy statutes (CCPA + VCDPA + CPA + CTDPA + UCPA + TDPSA
    + OCPA + DPDPA), TRANSFER-* → GDPR + UK-GDPR, ADDENDA-010..016
    (AI Addendum) → NIST-AI-RMF + EU-AI-Act, ADDENDA-019
    (FTC Click-to-Cancel) → FTC-ROSCA, ADDENDA-020 (privacy policy) →
    GDPR + CCPA. The vendor-security and EULA ADDENDA ranges + every
    V1 launch / V3 deep / V4 prefix are intentionally unframed —
    they're playbook-bound, not regulator-bound, so toggling HIPAA off
    must not silence the missing-party-name check. Longer prefixes
    win in the lookup (USDPA- vs DPA-).
  - [`src/ui/frame-filter.test.ts`](src/ui/frame-filter.test.ts) (new)
    24 unit tests covering every mapping, the union semantics for
    multi-frame activation, the unframed-prefix invariant, and a
    purity check (the input array is not mutated).
  - [`src/ui/pipeline.ts`](src/ui/pipeline.ts) `runPipeline` and
    `runBundlePipeline` now accept an `options.active_frames` parameter
    typed as `ReadonlyArray<ComplianceFrame>`. When omitted, the full
    LAUNCH + V3 rule set runs (preserves existing behavior for every
    caller in the tree today). When supplied, the rule set is filtered
    through `filterRulesByFrames` before the engine runs.
  - Wiring the chip-toggle UI in the complete state to call the
    pipeline with the new frames + caching the per-doc ingest is the
    remaining piece for the v3-o follow-up.
- Test coverage for the v4 bundle-pipeline expansion helper.
  [`src/ui/pipeline.test.ts`](src/ui/pipeline.test.ts) (new) pins
  `expandBundleInputs` across 6 paths: multi-file passthrough,
  unsupported-extension filtering, zip-bundle unpack, zip
  determinism (sorted entry order), single-non-zip edge case, and
  empty-zip handling. The bundle pipeline was shipped without unit
  coverage in commit 6f20dc5; this closes the gap.
- Shared v3 family-label module. [`src/ui/v3-labels.ts`](src/ui/v3-labels.ts)
  (new) carries `V3_FAMILY_LABELS` + `familyDisplayLabel`, consumed by
  both `main.ts` (eager bundle, no heavy deps) and `pipeline.ts`
  (dynamic chunk). Removes the duplicated table that previously lived
  in `main.ts` alongside the pipeline's own copy. Unit tests in
  [`src/ui/v3-labels.test.ts`](src/ui/v3-labels.test.ts) pin the table
  coverage against the auto-detect family ids and the
  `familyDisplayLabel` fallback contract.

### Changed
- Bundle DOCX cover now surfaces the v3 detected family for each
  per-document subsection rather than the bare playbook id.
  [`src/ui/pipeline.ts`](src/ui/pipeline.ts) `runBundlePipeline` sets
  `BundleDocument.detected_family` via `familyDisplayLabel(family,
  playbook.name)`, so a BAA shows "Business Associate Agreement (BAA)"
  in the consolidated report while a Mutual NDA (family "unknown" at
  the v3 detector level) still shows "Mutual NDA".

### Added
- v3 family detection in the bundle path (extends LAUNCH row v3-o to
  multi-doc). [`src/ui/pipeline.ts`](src/ui/pipeline.ts) `runBundlePipeline`
  now calls `detectV3Family` per document and exposes `v3_detection`
  on each `BundlePerDocument`. [`src/ui/states.ts`](src/ui/states.ts)
  `bundle-complete` state adds an optional
  `[data-role="bundle-detected-families"]` line that lists the human-
  readable detected families when at least one document is non-
  "unknown". Unit coverage added in [`src/ui/states.test.ts`](src/ui/states.test.ts):
  2 new tests (rendered, hidden-when-empty).
- Static a11y hardening (LAUNCH rows h / v4-f).
  [`tests/integration/static-html.test.ts`](tests/integration/static-html.test.ts)
  gains 5 new assertions: monotonic heading hierarchy (no h1 → h3
  jumps), exactly one `<h1>`, every native `<button>` has an
  accessible name (text content or aria-label), every form control
  has a label association (aria-label / aria-labelledby /
  `<label for>`), every `<a>` has a non-empty accessible name.

### Fixed
- Heading hierarchy: the source catalog cards under "Where the rules
  come from." were `<h4>` directly under the section's `<h2>`,
  skipping `<h3>`. Promoted to `<h3>` (12 cards) and the matching
  CSS selectors `.source-card h4` / `.source-card h4 span` retargeted
  to `h3`. Caught by the new monotonic-heading test.

### Added
- v3 UI hookup — Step 33 DOM wiring (LAUNCH row v3-o; spec-v3 §§60–61).
  [`src/ui/pipeline.ts`](src/ui/pipeline.ts) now calls the pure
  `detectV3Family` + `defaultFramesForPlaybook` modules and surfaces
  `v3_detection` + `v3_frames` on `PipelineResult`. [`src/ui/states.ts`](src/ui/states.ts)
  renders a "Detected: <family>" pill (`[data-role="v3-family"]`,
  carries a `data-confidence` integer percent), a compliance-frame
  chip row (`[data-role="compliance-frame-chips"]`, one `role="switch"`
  button per `ALL_FRAMES` entry, `aria-checked` mirrors the playbook
  defaults, Space + Enter flip the chip — matches the existing
  `tests/e2e/v3/a11y-keyboard.spec.ts` probe), and a one-line hint at
  `[data-role="compliance-frame-hint"]` for playbooks with no default
  frames. [`src/ui/main.ts`](src/ui/main.ts) carries the family-id →
  human-label table. Unit coverage in [`src/ui/states.test.ts`](src/ui/states.test.ts):
  5 new tests (family-chip render, hidden-when-unknown, chip-row
  aria-checked, Space + Enter toggle, hint visibility). Engine-side
  filtering on toggle is a follow-up; chip toggles are presentational
  at this hookup.
- v4 folder ingest UI hookup (LAUNCH row v4-o; spec-v4 §8 step 1).
  [`src/ui/dropzone.ts`](src/ui/dropzone.ts) now ships a second hidden
  `<input type="file" webkitdirectory multiple>` alongside the existing
  multi-file picker, plus a "choose a folder…" affordance in the empty-
  state template (`[data-role="folder-pick"]`). Folder drag-drop is
  handled in the `drop` listener via `DataTransferItem.webkitGetAsEntry()`
  and a new exported `collectFilesFromEntries` recursive walker. Both
  paths filter to `.pdf` / `.docx` before dispatching through the same
  `onFiles` channel, so `runBundlePipeline` is unchanged. Unit coverage
  added in [`src/ui/dropzone.test.ts`](src/ui/dropzone.test.ts): probe
  selector match, click-routing for the folder affordance, change-event
  filtering of non-PDF/DOCX entries, and a nested-tree walker test.
- v4 multi-doc UI hookup (LAUNCH row v4-d → 🟡 partial; spec-v4 §8 / §11).
  [`src/ui/dropzone.ts`](src/ui/dropzone.ts) now exposes
  `input[type="file"][multiple]` and accepts `.pdf,.docx,.zip`; multi-file
  drops + single-`.zip` drops route through a new `onFiles` callback so the
  pipeline owns the bundle branch (single-file behavior is unchanged).
  [`src/ui/pipeline.ts`](src/ui/pipeline.ts) ships `runBundlePipeline`
  which expands inputs (multi-file or single zip via `extractZipEntries`),
  plans the bundle via `planBundle`, runs the per-doc engine and cross-doc
  consistency against `ALL_CONSISTENCY_RULES`, and emits the consolidated
  bundle DOCX + bundle JSON via `buildBundleDocxReport` /
  `buildBundleJsonBlob`. [`src/ui/states.ts`](src/ui/states.ts) adds a
  `bundle-complete` state with `[data-role="bundle-download"]` and
  `[data-role="bundle-json-download"]` buttons plus a cross-document
  finding summary. Unit coverage: [`src/ui/dropzone.test.ts`](src/ui/dropzone.test.ts)
  (multi-file routing, zip routing, accept-list, fallback to single-file
  when `onFiles` is omitted) and [`src/ui/states.test.ts`](src/ui/states.test.ts)
  (bundle-complete render + zero-finding copy). The forward-compatible
  skip in [`tests/e2e/v4/no-network.spec.ts`](tests/e2e/v4/no-network.spec.ts)
  lifts automatically once the page is served from `dist/`. Folder-picker
  (`webkitdirectory`) affordance is the remaining piece for row v4-o.

### Fixed
- `PlaybookSchema` (`src/playbooks/types.ts`) now accepts the v3 playbook
  shape — `expected_clauses` / `expected_defined_terms` as `string[]`
  and `sources` as structured citation objects — coercing each to the
  canonical engine shape. Previously 15 of the 19 v3 playbooks failed
  Zod validation and were silently swallowed by the v3 golden harness,
  causing v3 fixtures to run under v2 fallback playbooks and their
  v3-scoped rules to never fire. All 19 v3 + 15 v4 goldens regenerated.

### Added
- Seed v3 fail-fixture corpus under [`tests/golden/v3/fixtures/`](tests/golden/v3/fixtures/):
  `baa-missing-subcontractor-flow-down-fail.txt`,
  `mutual-nda-deep-missing-dtsa-fail.txt`,
  `dpa-controller-processor-missing-documented-instructions-fail.txt`,
  `ai-addendum-training-without-optin-fail.txt`. Each exercises a
  load-bearing critical rule (BAA-018, NDA-D-001/002, DPA-007,
  ADDENDA-011 respectively). Pinned by new
  [`tests/golden/v3/fixture-sanity.test.ts`](tests/golden/v3/fixture-sanity.test.ts).
- Expand the v3 fail-fixture corpus from 4 to 7 (LAUNCH row v3-b):
  `vendor-security-addendum-missing-incident-window-fail.txt` (ADDENDA-004),
  `scc-module-2-modified-clauses-fail.txt` (TRANSFER-003 critical),
  `dpa-ccpa-service-provider-no-business-purpose-fail.txt` (USDPA-020
  critical). Sanity test now pins 7 fail-fixtures.
- Expand the v3 fail-fixture corpus from 7 to 10 (LAUNCH row v3-b):
  `unilateral-nda-deep-missing-term-fail.txt` (NDA-D-003),
  `msa-vendor-deep-no-liability-cap-fail.txt` (MSA-006),
  `uk-idta-addendum-modified-mandatory-clauses-fail.txt` (TRANSFER-015
  critical). Sanity test now pins 10 fail-fixtures.
- Expand the v3 fail-fixture corpus from 10 to 13 (LAUNCH row v3-b):
  `eula-no-license-grant-or-prohibitions-fail.txt` (ADDENDA-017),
  `scc-module-3-missing-clause-15-fail.txt` (TRANSFER-008 critical),
  `dpa-processor-subprocessor-missing-deletion-or-return-fail.txt`
  (DPA-013 critical). Sanity test now pins 13 fail-fixtures.
- Expand the v3 fail-fixture corpus from 13 to 16 (LAUNCH row v3-b):
  `baa-subcontractor-missing-return-or-destruction-fail.txt`
  (BAA-010 critical),
  `msa-customer-deep-missing-ip-indemnity-fail.txt` (MSA-001),
  `dpa-multi-state-us-missing-deletion-or-return-fail.txt`
  (USDPA-015 critical). Sanity test now pins 16 fail-fixtures.
- Expand the v3 fail-fixture corpus from 66 to 69 (LAUNCH row v3-b)
  with three new fail-fixtures spanning three distinct v3 rule families
  (TRANSFER, NDA-deep, MSA-deep) — each exercises a load-bearing rule
  not previously covered end-to-end:
  `scc-module-2-missing-clause-14-fail.txt` (TRANSFER-007 — "Clause
  14 — Local Laws and Practices Assessment" replaced by a generic
  "Destination-Country Conditions Statement" paragraph; every
  `clause 14`, `local laws and practices`, `transfer impact
  assessment`, and `TIA` anchor stripped, breaking the Schrems II
  TIA hook),
  `mutual-nda-deep-non-solicit-no-carve-out-fail.txt` (NDA-D-020
  warning — non-solicit clause added without the
  general-solicitation / public-job-postings safe-harbor language;
  the rule's negative lookahead for `general\s+solicitation` /
  `not\s+specifically\s+directed` / `general\s+advertis` fires
  within the 300-char window), and
  `msa-vendor-deep-indemnity-carved-out-of-cap-fail.txt` (MSA-005
  info — Section 8(b) "Carveouts" tightened so that "cap shall not
  apply to indemnification" sits inside the rule's 80-char
  proximity window, surfacing the commercially-contested
  cap-carve-out choice for explicit review). Sanity test now pins
  69 fail-fixtures.
- Expand the v3 fail-fixture corpus from 63 to 66 (LAUNCH row v3-b)
  with three new fail-fixtures spanning three distinct v3 rule families
  (DPA-GDPR, BAA, ADDENDA) — each exercises a load-bearing rule not
  previously covered end-to-end:
  `dpa-controller-processor-missing-art32-36-assistance-fail.txt`
  (DPA-012 — Section 9 "Assistance with Articles 32 to 36
  Obligations" replaced by a generic "Cooperation on Operational
  Matters" paragraph; every `Articles 32 to 36` and `assist ...
  (breach|security|DPIA)` anchor is stripped per GDPR Art. 28(3)(f)),
  `baa-missing-administrative-safeguards-fail.txt` (BAA-014 warning —
  Safeguards narrowed from "administrative, physical, and technical
  safeguards … 45 CFR §§ 164.308, 164.310, and 164.312" to
  "physical and technical safeguards … 45 CFR §§ 164.310 and 164.312";
  every `administrative safeguards` and `164.308` anchor stripped
  while "Security Rule" is retained so BAA-013 still passes), and
  `vendor-security-addendum-missing-named-encryption-fail.txt`
  (ADDENDA-008 warning — Section 2 rewritten to remove every named
  encryption standard, replacing AES-256 / TLS 1.2 / TLS 1.3 /
  FIPS 140-3 references with generic "industry-standard symmetric
  ciphers" and "a current version of the Transport Layer Security
  protocol"). Sanity test now pins 66 fail-fixtures.
- Expand the v3 fail-fixture corpus from 60 to 63 (LAUNCH row v3-b)
  with three new fail-fixtures spanning three distinct v3 rule families
  (BAA, NDA-deep, MSA-deep) — each exercises a load-bearing rule not
  previously covered end-to-end:
  `baa-missing-access-to-phi-fail.txt` (BAA-006 — the "Access,
  Amendment, Accounting" header is rewritten as "Amendment, Accounting";
  every `access to PHI`, `right of access`, and `164.524` anchor is
  stripped and the surviving prose uses "inspect or obtain a copy" so
  none of BAA-006's three present_patterns match — leaving the
  covered entity without a contractual hook to satisfy individuals'
  right of access under § 164.524 per 45 CFR
  § 164.504(e)(2)(ii)(E)),
  `mutual-nda-deep-unusual-governing-law-fail.txt` (NDA-D-018 info —
  governing law re-pointed from Delaware to Wyoming and venue to
  Cheyenne; NDA-D-017 still passes but Wyoming sits outside the
  viable-jurisdiction whitelist so NDA-D-018's `laws\s+of\s+...`
  present_pattern fails and the rule fires as a soft warning that an
  atypical jurisdiction may produce unpredictable NDA enforcement),
  and
  `msa-vendor-deep-one-sided-consequential-waiver-fail.txt` (MSA-008
  info — Section 8(c)'s "IN NO EVENT SHALL EITHER PARTY BE LIABLE
  TO THE OTHER PARTY" rewritten as "VENDOR SHALL NOT BE LIABLE TO
  CUSTOMER", every "neither party"/"each party"/"mutual" scoping
  stripped; MSA-008's present_pattern requires a mutual scoping
  anchor within 160 chars of a consequential-damages token, so the
  one-sided phrasing fails to match and the rule fires). Sanity
  test now pins 63 fail-fixtures.
- Expand the v3 fail-fixture corpus from 57 to 60 (LAUNCH row v3-b)
  with three new fail-fixtures spanning three distinct v3 rule families
  (BAA, NDA-deep, TRANSFER) — each exercises a load-bearing rule not
  previously covered end-to-end:
  `baa-missing-phi-amendment-fail.txt` (BAA-007 — the "Access,
  Amendment, Accounting" section is rewritten as "Access, Accounting";
  every "amendment", "amend.*PHI", and "164.526" anchor is stripped
  and the surviving sentence references only § 164.524 and § 164.528,
  with the commercial substitute deliberately avoiding both "amend"
  and "amendment" so neither alternation in BAA-007's present_patterns
  matches — leaving an amendment request bottlenecked at the BA with
  no contractual hook to satisfy § 164.526),
  `mutual-nda-deep-missing-governing-law-fail.txt` (NDA-D-017 —
  Section 8 is rewritten as "Dispute Resolution; Venue"; every
  "governing law", "governed by the laws", and "laws of the State of /
  country of" anchor is stripped and the surviving clause designates
  only a forum, explicitly disclaiming any substantive-law selection
  and deferring conflict-of-laws to the forum court — exposing the
  parties' substantive expectations to whichever forum-state
  conflict-of-laws regime picks up the case),
  `scc-module-2-missing-clause-11-fail.txt` (TRANSFER-006 warning —
  the "Clause 11 — Redress" heading is replaced by a generic
  "Customer Service Contact Point" paragraph; every "Clause 11"
  anchor and every "redress" token is stripped — the contact-point
  obligation survives in prose but the SCC clause-numbering and the
  statutory term are lost, breaking automated compliance lookups
  and internal SCC cross-references back to Clause 11).
  Sanity test now pins 60 fail-fixtures.
- Expand the v3 fail-fixture corpus from 54 to 57 (LAUNCH row v3-b)
  with three new fail-fixtures spanning three distinct v3 rule families
  (TRANSFER, MSA, DPA-GDPR) — each exercises a load-bearing rule not
  previously covered end-to-end:
  `scc-module-2-missing-clause-9-fail.txt` (TRANSFER-005 — SCC Module 2
  with the "Clause 9 — Use of Sub-Processors" heading replaced by a
  generic "Downstream Vendor Management" paragraph; every "clause 9"
  anchor is absent, breaking the prior-authorisation regime and the
  Art. 28(4) sub-processor flow-down hook),
  `msa-vendor-deep-missing-gross-negligence-indemnity-fail.txt` (MSA-004
  warning — indemnification covers only IP-infringement and Customer-
  violation claims; the gross-negligence, wilful-misconduct, and
  data-protection indemnity prong is entirely absent, leaving the
  counterparty unprotected for the highest-impact conduct categories),
  `dpa-controller-processor-missing-data-subjects-fail.txt` (DPA-005 —
  Section 2 enumerates types of personal data only; every "categories
  of data subjects" anchor is stripped and Annex I is retitled without
  a subjects enumeration, failing the GDPR Art. 28(3) introductory
  paragraph requirement).
  Sanity test now pins 57 fail-fixtures.
- Expand the v3 fail-fixture corpus from 51 to 54 (LAUNCH row v3-b)
  with three new fail-fixtures spanning three distinct v3 rule families
  (TRANSFER, DPA-GDPR, BAA) — each exercises a load-bearing rule not
  previously covered end-to-end:
  `scc-module-2-missing-clause-8-fail.txt` (TRANSFER-004 — SCC Module 2
  with the "Clause 8 — Data Protection Safeguards" heading stripped;
  all obligations survive in prose but no "clause 8" anchor remains,
  breaking automated compliance lookup and internal SCC cross-references),
  `dpa-controller-processor-missing-dsr-assistance-fail.txt` (DPA-011 —
  Section 8 rewritten to strip every "assist the controller", "data
  subject rights", and "Chapter III" anchor; processor has no explicit
  GDPR Art. 28(3)(e) obligation to assist with access, erasure,
  portability, and objection requests),
  `baa-missing-security-rule-compliance-fail.txt` (BAA-013 critical —
  Safeguards section rewritten to drop all "Security Rule", "164.30X",
  and "administrative … physical … technical" anchors; a generic
  "appropriate safeguards" clause does not satisfy 45 C.F.R.
  § 164.314(a)(2)(i)'s explicit Security Rule mandate).
  Sanity test now pins 54 fail-fixtures.
- Expand the v3 fail-fixture corpus from 48 to 51 (LAUNCH row v3-b)
  with three new NDA-deep fail-fixtures — each exercises a load-bearing
  NDA-D rule not previously covered end-to-end:
  `mutual-nda-deep-missing-return-attestation-fail.txt` (NDA-D-014 —
  return-or-destroy clause present but written certification requirement
  stripped; discloser has no contractual proof of destruction after
  relationship ends),
  `mutual-nda-deep-missing-injunctive-relief-fail.txt` (NDA-D-015 —
  injunctive-relief / irreparable-harm clause replaced by generic
  "Remedies" section; discloser must prove inadequate-remedy-at-law from
  scratch in any emergency motion),
  `mutual-nda-deep-missing-no-license-clause-fail.txt` (NDA-D-021 —
  no-license clause omitted entirely; aggressive receiver could argue
  an implied license arose from disclosure).
  Sanity test now pins 51 fail-fixtures.
- Expand the v3 fail-fixture corpus from 45 to 48 (LAUNCH row v3-b)
  with three new fail-fixtures across three distinct v3 rule families —
  each exercises a load-bearing rule not previously covered:
  `baa-missing-unreasonable-delay-language-fail.txt` (BAA-022 —
  Reporting section rewritten to keep only the 60-calendar-day outer
  bound from discovery, stripping every "without unreasonable delay"
  anchor; HIPAA's 45 C.F.R. § 164.410(b) requires *both* the inner
  "without unreasonable delay" standard *and* the 60-day cap),
  `dpa-multi-state-us-missing-subcontractor-written-contract-fail.txt`
  (USDPA-018 critical — Section 7 (Sub-Processor Management) rewritten
  to require only prior notification and vetting; "written contract" /
  "same obligations" anchors stripped, leaving the controller without
  the equivalent-obligations guarantee Va. Code § 59.1-579 requires),
  `msa-vendor-deep-missing-indemnity-procedure-fail.txt` (MSA-002 —
  Section 7(c) Indemnification Procedure stripped; no "promptly notify",
  "control of the defense", or "settlement … consent" anchor remains,
  leaving the indemnitor without ability to control its own defense and
  exposing it to moral-hazard and collusive-settlement risk).
  Sanity test now pins 48 fail-fixtures.
- Expand the v3 fail-fixture corpus from 42 to 45 (LAUNCH row v3-b)
  with three new fail-fixtures across three distinct v3 rule families —
  each exercises a load-bearing rule not previously covered:
  `mutual-nda-deep-missing-independent-development-exclusion-fail.txt`
  (NDA-D-009 — "independently developed" prong removed from Section 2
  Carveouts; the final sentence affirmatively ropes in information
  generated by the Receiving Party's own personnel, so ordinary parallel
  R&D by exposed staff could be captured as a breach),
  `baa-missing-breach-discovery-trigger-fail.txt` (BAA-021 — breach-
  notification clock runs from "confirmation and written assessment"
  rather than from "discovery of the breach", stripping every "discovery
  of the breach" anchor; shifting the trigger post-discovery can cause
  the covered entity to blow the 45 C.F.R. § 164.410 60-day statutory
  cap before the BA's clock even starts),
  `dpa-multi-state-us-missing-compliance-demonstration-fail.txt`
  (USDPA-019 critical — Section 3 (Virginia VCDPA Processor Obligations)
  drops the "make available all information necessary to demonstrate
  compliance" sentence and Section 12 renames to "Attestation" with
  "adherence" language, removing every "demonstrate compliance" anchor
  required by Va. Code § 59.1-579 and equivalent state statutes).
  Sanity test now pins 45 fail-fixtures.
- Expand the v3 fail-fixture corpus from 39 to 42 (LAUNCH row v3-b)
  with three new fail-fixtures across three distinct v3 rule families —
  each exercises a load-bearing rule not previously covered:
  `mutual-nda-deep-missing-third-party-exclusion-fail.txt` (NDA-D-008 —
  "third party lawfully obtained" carve-out removed from Carveouts; last
  sentence reincorporates information from any "external party not under a
  separate NDA", closing the standard third-party-channel safe harbour),
  `msa-vendor-deep-missing-force-majeure-fail.txt` (MSA-022 — force-majeure
  clause rewritten as vendor-only "Excused Performance" with no bilateral
  "neither party" / "either party" framing; commercially abnormal one-sided
  scope leaves Customer without relief for its own force-majeure events),
  `baa-missing-cure-infeasible-termination-fail.txt` (BAA-012 — Term and
  Termination section rewrites to cure-period + insolvency termination only,
  stripping every "cure is not feasible" / "infeasible to cure" anchor; HHS
  guidance expects BAAs to permit exit when a HIPAA breach cannot be cured).
  Sanity test now pins 42 fail-fixtures.
- Expand the v3 fail-fixture corpus from 36 to 39 (LAUNCH row v3-b)
  with three new fail-fixtures across three distinct v3 rule families —
  each exercises a load-bearing rule not previously covered:
  `mutual-nda-deep-missing-prior-knowledge-exclusion-fail.txt`
  (NDA-D-007 — "already known / prior to disclos" exclusion removed from
  Section 2 Carveouts, replaced with an affirmative sentence that sweeps
  in information regardless of when the Receiving Party came to know it),
  `msa-vendor-deep-missing-sla-fail.txt` (MSA-016 — no SLA, uptime, or
  availability commitment reference anywhere in an otherwise complete
  vendor-form MSA; customer has no contractual remedy for downtime),
  `dpa-controller-processor-missing-art32-security-measures-fail.txt`
  (DPA-009 critical — Section 6 rewritten to a vague general-security-
  commitment paragraph, stripping every reference to "Article 32",
  "technical and organisational measures", "encryption",
  "pseudonymisation", CIA-R, restore-availability, and regular-testing).
  Sanity test now pins 39 fail-fixtures.
- Expand the v3 fail-fixture corpus from 33 to 36 (LAUNCH row v3-b)
  with three new fail-fixtures across three distinct v3 rule families —
  each exercises a load-bearing rule not previously covered:
  `dpa-controller-processor-missing-compliance-demonstration-fail.txt`
  (DPA-014 critical — Section 11 replaced with internal-records-only
  clause, stripping every "demonstrate compliance" / audit-cooperation
  anchor required by GDPR Art. 28(3)(h)),
  `dpa-multi-state-us-missing-audit-cooperation-fail.txt` (USDPA-017
  critical — audit-cooperation clause replaced with annual security-
  program clause, stripping every "allow and cooperate with reasonable
  assessments" / assessor anchor),
  `msa-vendor-deep-missing-compliance-noninfringement-warranty-fail.txt`
  (MSA-014 — no comply-with-laws or non-infringement warranty clause
  present; Section 6 covers only workmanlike performance and malware-
  free deliverables). Sanity test now pins 36 fail-fixtures.
- Expand the v3 fail-fixture corpus from 30 to 33 (LAUNCH row v3-b)
  with three new fail-fixtures across three distinct v3 rule families —
  each exercises a load-bearing rule not previously covered:
  `baa-missing-accounting-of-disclosures-fail.txt` (BAA-008 critical —
  "accounting of disclosures" / 164.528 anchor stripped from the
  Individual Rights section),
  `msa-vendor-deep-missing-service-warranties-fail.txt` (MSA-013 —
  Section 6 rewritten to a flat AS-IS disclaimer stripping workmanlike /
  conformance-to-documentation / no-malicious-code warranty families),
  `mutual-nda-deep-missing-public-domain-exclusion-fail.txt` (NDA-D-006 —
  "publicly available" / "public domain" carve-out removed from the
  Carveouts section). Sanity test now pins 33 fail-fixtures.
- Expand the v3 fail-fixture corpus from 27 to 30 (LAUNCH row v3-b)
  with a fourth failure-mode fixture per already-covered playbook —
  exercising a distinct load-bearing rule that prior fixtures did not:
  `baa-missing-breach-notification-fail.txt` (BAA-019 critical —
  Reporting section rewritten to drop the "breach of unsecured PHI" /
  164.410 anchor, leaving the notification obligation legally
  ambiguous),
  `mutual-nda-deep-missing-ci-definition-fail.txt` (NDA-D-005 —
  "Confidential Information means …" definition block removed so
  confidentiality scope is undefined),
  `msa-customer-deep-missing-data-return-fail.txt` (MSA-021 —
  data-portability / return-on-termination section stripped, leaving
  customer locked out of its own data). Sanity test now pins 30
  fail-fixtures.
- Expand the v3 fail-fixture corpus from 24 to 27 (LAUNCH row v3-b)
  with a third failure-mode fixture per already-covered playbook —
  exercising a distinct load-bearing rule that prior fixtures did not:
  `baa-missing-termination-for-breach-fail.txt` (BAA-011 critical —
  termination-for-material-breach right stripped, leaving only
  convenience and insolvency termination),
  `msa-vendor-deep-missing-cap-carveouts-fail.txt` (MSA-007 —
  Section 8(b) cap carve-outs block removed so aggregate cap absorbs
  fraud / wilful-misconduct / IP-indemnity / confidentiality claims),
  `mutual-nda-deep-missing-perpetual-trade-secret-fail.txt` (NDA-D-004
  — perpetual trade-secret carve-out stripped, leaving a flat
  three-year term). Sanity test now pins 27 fail-fixtures.
- Expand the v3 fail-fixture corpus from 21 to 24 (LAUNCH row v3-b)
  with a second failure-mode fixture per already-covered playbook —
  exercising a distinct load-bearing rule that prior fixtures did not:
  `msa-customer-deep-missing-termination-clause-fail.txt` (MSA-018 —
  termination-for-material-breach / cure-period clause removed),
  `mutual-nda-deep-missing-return-or-destruction-fail.txt` (NDA-D-013
  — return-or-destruction section stripped entirely),
  `dpa-multi-state-us-missing-confidentiality-duty-fail.txt`
  (USDPA-016 — "bound by confidentiality" anchor replaced with generic
  access-control language). Sanity test now pins 24 fail-fixtures.
- Expand the v3 fail-fixture corpus from 18 to 21 (LAUNCH row v3-b)
  with a second failure-mode fixture per already-covered playbook —
  exercising a distinct load-bearing rule that prior fixtures did not:
  `baa-missing-hhs-books-records-fail.txt` (BAA-009 critical — 45
  C.F.R. § 164.504(e)(2)(ii)(H) HHS Secretary books-and-records
  availability),
  `dpa-controller-processor-missing-personnel-confidentiality-fail.txt`
  (DPA-008 critical — GDPR Art. 28(3)(b) personnel confidentiality
  commitment),
  `msa-vendor-deep-missing-background-foreground-ip-fail.txt`
  (MSA-011 — commercial drafting baseline background/foreground IP
  allocation). Sanity test now pins 21 fail-fixtures.
- Expand the v3 fail-fixture corpus from 16 to 18 (LAUNCH row v3-b):
  `saas-tos-no-click-to-cancel-fail.txt` (ADDENDA-019 — phone-only
  cancellation strips every FTC Click-to-Cancel / ROSCA anchor),
  `privacy-policy-lint-missing-disclosures-fail.txt` (ADDENDA-020 —
  vague boilerplate strips every CCPA § 1798.130 / GDPR Art. 13–14 /
  data-subject-rights anchor). Sanity test now pins 18 fail-fixtures.
  The remaining v3 playbook without a fail-fixture (`coi`) carries no
  v3 presence rules; coverage will land alongside the ACORD-25
  spatial extractor.

---

## [v4.0.0] — 2026-05-17

v4 expands the catalog from contracts (v1) and regulated agreements (v3) to all logically-operative legal documents — 16 sub-domains, 700+ new rules, multi-document ingest (folder / zip / multi-file drop), and a cross-document consistency engine. UI surface unchanged per spec-v4 §18. Determinism contract preserved.

### Added

- **v4 Step 61 — Test corpus expansion** (spec-v4.md Part VI).
  New v4 golden-test harness at `tests/golden/v4/` mirroring
  `tests/golden/v3/`: `_pipeline.ts` loads LAUNCH + v3 + every v4
  playbook and runs `LAUNCH_RULES + V3_RULES + V4_RULES`;
  `golden.test.ts` is the single-doc harness; `bundle.test.ts` is
  the multi-doc harness driving `runEngineMulti` +
  `CONSISTENCY_RULES` (spec-v4.md §§10–11). 15 single-doc fixtures
  (one per v4 sub-domain B–P) with `.playbook` sidecars; 5
  multi-doc bundles (party-name-conflict, governing-law-mismatch,
  effective-date-paradox, cap-mismatch, clean-msa-baa) exercising
  the CROSS-* rule families. Three sanity guards per fixture
  (golden match, two-run determinism, v4-playbook + ≥1 finding).
  Regeneration via `VAULYTICA_REGEN_GOLDEN=1`. 62 new tests;
  1124/1124 + 2 skips.
- **v4 Step 60 — DKB build pipeline (v4 fetchers)** (spec-v4.md §13).
  Eight v4 source families wired under `dkb/build/v4/fetchers/`
  emitting v3 DKB nodes (spec §12: v3 schema reused, no v4-specific
  node type): `nvca` (NVCA model legal documents — SPA, IRA, Voting,
  ROFR/Co-Sale, COI, Term Sheet); `dgcl` (DGCL §§ 102, 109, 141, 211,
  251, 262); `mbca` (ABA MBCA §§ 2.02 / 7.01–7.02 / 8.01 / 10.03);
  `ucc-article-2/3/9` (Cornell LII — § 2-201, § 2-314, § 2-316,
  § 3-104, § 3-305, § 9-203, § 9-108, § 9-502); `aia` (A101 / A102 /
  A201 / A401 / G701 / G702-G703 catalog); `frcp` + `fre` (Rules
  37(e), 41, 408, 502); `state-landlord-tenant` (CA / NY / TX / FL /
  IL); `state-trust-will` (CA / NY / TX / FL / IL). 19 fetcher ids
  registered in `V4_FETCHERS`. Snapshot fixtures vendored at
  `dkb/fixtures/v4/snapshots/{sha256(source_url)}.txt`. Step-20
  staleness gate covers v4 nodes unchanged because they pass through
  the v3 `V3DkbNodeListSchema`. 31 new tests; 1062/1062 + 2 skips.
- **v4 Step 44 — consolidated bundle report renderer** (spec-v4.md §11).
  New `src/report/bundle.ts` ships `buildBundleDocxReport`,
  `buildBundleJson` / `buildBundleJsonBlob`, `buildBundleZip`, and
  `bundleFingerprint`. The DOCX includes cover (bundle fingerprint,
  document count, engine + DKB versions, ISO date), executive summary
  (per-document + cross-document severity counts), per-document
  subsections capped at `BUNDLE_TOP_N = 10` findings each, the full
  cross-document consistency appendix, a deduped citation
  bibliography, the full audit trail (per-doc + cross-doc execution
  logs with elapsed times), and the standard determinism / privacy /
  non-advice disclaimer block. The bundle zip pins per-entry mtime to
  2000-01-01 UTC so the zip envelope is byte-identical across runs.
  Bundle JSON shape: `{ runs, cross_doc_findings, bundle_fingerprint,
  dkb_version, engine_version }`. The `fflate` dep introduced in Step
  41 for zip ingest is reused for the §11 zip output path — one
  library, two paths. 13 new unit tests; 864/864 passing.

## [v3.0.0] — 2026-05-16

The **compliance & regulated-agreement expansion** release. v3 extends
v2 with 220 new rules across HIPAA, GDPR / UK GDPR, eight US state
privacy laws, EU SCCs, the UK IDTA + Addendum, Swiss Addendum,
international privacy regimes, trade-secret law, commercial-law
overlays, insurance norms, and the AI / vendor-security / EULA / ToS /
privacy-policy / COI surfaces. Same posture as v2: browser-only, no AI,
no telemetry, no server.

### Headline additions

- **220 new rules** across seven rulesets — BAA (45), DPA-GDPR (55),
  DPA-US-state (25), MSA-deep (30), NDA-deep (25), Transfer (20),
  Addenda (20). `V3_RULES` ships alongside `LAUNCH_RULES`; the runner
  filters by playbook so v2's `result_hash` is preserved.
- **Nine v3 extractors** under `src/extract/v3/` covering role
  classification, PII / PHI category detection, cross-border transfer
  mechanisms, security-measures inventory, breach-notification timing,
  audit-rights extraction, subprocessor inventory, insurance schedules,
  and DTSA whistleblower-notice detection.
- **Cross-document consistency engine** at `src/engine/consistency/`
  with seven cross-document rules (BAA permitted-uses no broader than
  MSA, DPA purpose matches MSA services, DPA data categories not
  broader than MSA, BAA term aligns with MSA, governing-law alignment,
  notice-clause alignment, order-of-precedence consistency). The
  engine accepts up to four documents in one bundle, mirrors the v2
  determinism contract (SHA-256 over canonicalized run JSON with
  volatile fields blanked), and emits findings that cite every
  contributing document with the conflicting text from each.
- **DOCX report extensions** under `src/report/v3/`: compliance-matrix
  section with Pass / Partial / Fail / N/A cell shading and screen-
  reader-friendly table semantics; cross-border transfer summary page;
  subprocessor inventory page; insurance summary page; two-document
  consistency appendix; citation-depth verification appendix with
  Word `ExternalHyperlink` click-through; per-page footer carrying
  engine version + DKB version + result hash + "Citations as of [date]".
  All conditional on the corresponding input being present; the v2
  API is unchanged.
- **DKB v3 expansion** with six new node types (`regulator_model_form`,
  `statutory_clause_requirement`, `transfer_mechanism`,
  `subprocessor_requirement`, `insurance_norm`, `consistency_check`),
  source-pinning protocol with content-hash-at-pin, weekly staleness
  detector with explicit ack-or-fail gate, and 24 new fetchers covering
  the full v3 source catalog (eCFR Title 45; HHS sample BAA; OCR
  resolutions; CCPA + 7 US state-privacy statutes; GDPR; EU SCCs
  2021/914 with all four modules; UK GDPR; UK IDTA; UK Addendum; Swiss
  revFADP + Addendum; EDPB guidelines; PIPEDA; LGPD; APPI; PIPL).
- **v3 UI primitives** at `src/ui/v3/` — pure detection scorer over 12
  document families, compliance-frame chip-row defaults per playbook
  (DPA → GDPR + CCPA on; BAA → HIPAA on; MSA → all off with a hint),
  immutable multi-document state reducer with `MAX_DOCUMENTS = 4`, and
  centralized empty-state and error-state copy.
- **v3 documentation** — seven new docs under `docs/v3/`: overview,
  adding-a-baa-rule, adding-a-dpa-rule, adding-a-playbook, regulators
  (full source catalog), two-document-mode, compliance-matrix.
- **v3 threat-model expansion** — new section in `docs/threat-model.md`
  covering DKB integrity, the staleness gate, the citation surface,
  the "consensus practice" AI-addendum disclaimer, and the explicit
  non-promise of universal regulator coverage.
- **v3 launch checklist** in `LAUNCH.md` with 15 v3-specific items
  tracked end-to-end.
- **v3 golden-output harness** at `tests/golden/v3/` running
  `LAUNCH_RULES ∪ V3_RULES`, with sidecar-driven playbook forcing,
  byte-identical-in-process determinism check, and one starter BAA
  fixture committed and baselined.
- **v3 bundle-size guard** at `tests/integration/bundle-size.test.ts`
  enforcing eager-entry ≤ 50 KB gzipped and total payload ≤ v2 + 600 KB.
- **v3 Playwright specs** at `tests/e2e/v3/` — no-network privacy
  guard and keyboard-accessibility coverage (with forward-compatible
  probes for the v3 chip row + multi-doc cards).

### Changed

- `package.json` version bumped from `1.0.0` to `3.0.0`. (v2 is
  represented by spec-v2.md and the v2 launch entry but never received
  its own package version bump — going straight to 3.0.0 keeps the
  spec-and-package versions aligned.)
- `README.md` "What I check" gains a v3 line pointing to
  `docs/v3/overview.md`.
- DOCX report builder `buildDocxReport` takes an optional fifth
  `v3?: V3ReportInputs` argument; v2 callers are unchanged.

### Citations

Every v3 rule cites a specific regulator subdivision or a DKB-pinned
practitioner source. Every citation in every report renders as a
Word `ExternalHyperlink` in the citation-index appendix. The DKB
staleness gate is wired and exits non-zero on unacknowledged drift.

### Detail (per spec-v3 build step)

The entries below were accumulated under `[Unreleased]` during the
v3 build sequence (spec-v3 Part IX, Steps 18–39). They are preserved
here so the per-step rationale is part of the v3.0.0 release record.

- **v3 documentation (spec-v3 Step 35):** seven new markdown documents under `docs/v3/` cover the full v3 surface — `overview.md` (audience, scope, what's new vs. v2), `adding-a-baa-rule.md` (HIPAA-anchored rule walkthrough with the BAA-NNN presence/language factories), `adding-a-dpa-rule.md` (GDPR Art. 28 + US-state-privacy walkthrough with the generic `_regulated-rule.ts` factory), `adding-a-playbook.md` (v3 playbook schema additions — `regulator_frame`, `applicable_jurisdictions`, `companion_playbooks`, `compliance_matrix_columns` — with per-family column conventions), `regulators.md` (the full source catalog with canonical URLs grouped by US-HIPAA-privacy / EU / UK / Switzerland / international / trade-secret / commercial-law / insurance / AI-consensus-practice), `two-document-mode.md` (when to use, the seven shipped consistency rules, how findings are shaped, the determinism contract, how to add a CC-NNN rule), and `compliance-matrix.md` (anatomy of the matrix, what Partial means, how to cite the matrix in an audit, what the matrix does not say). `README.md` gains the v3 line; `docs/threat-model.md` gains a v3-specific section covering DKB integrity, the staleness gate, the citation surface, the "consensus practice" AI-addendum disclaimer, and the explicit non-promise that v3 covers every regulator. All gates green: typecheck clean, lint clean, **788/788 tests + 2 skips**, build green.
- **Threat-model v3 expansion (spec-v3 Step 38):** new "v3 additions" section in `docs/threat-model.md` covering five new attack surfaces and trust assumptions that v3 introduces — DKB integrity, the staleness gate, the citation surface, the "consensus practice" AI-addendum disclaimer, and the explicit non-promise that v3 covers every regulator in every jurisdiction. The section closes with a "what v3 still does not protect against" enumeration consistent with the v2 threat model.
- **v3 extractors (spec-v3 Step 30, 9 modules):** all nine placeholder stubs under `src/extract/v3/` are now real, deterministic, pure functions. `role-classifier.ts` walks each paragraph in document order and pulls roles by priority (`definition` > `recital` > `clause-usage`), keyed to a 12-role controlled vocabulary (covered-entity / business-associate / subcontractor / controller / processor / sub-processor / joint-controller / third-party / service-provider-ccpa / contractor-ccpa / service-recipient / service-supplier). `pii-category.ts` catalogs HIPAA's 18 identifiers + GDPR Art. 9 special categories + Art. 10 criminal convictions + CCPA sensitive personal information, plus a separate "special categories" flag that fires on the umbrella phrase. `transfer-mechanism.ts` classifies SCC modules 1–4 + UK IDTA + UK Addendum + Swiss Addendum + Adequacy + BCR + Art. 49 + DPF, suppresses unspecified-SCC when a more-specific module hit the same paragraph, and infers location by precedence `annex > attachment > hyperlink > by-reference > recital-only > inline`. `security-measures.ts` normalizes a 17-slug controlled vocabulary (encryption-at-rest / encryption-in-transit / MFA / SSO / vuln-scanning / pen-testing / training / BCP-DR / IR / RBAC / logging-audit / network-seg / hardware-tokens / SDLC / SOC2-T2 / ISO-27001 / HITRUST) with cadence + scope inference. `breach-timing.ts` matches breach↔notification in either order, normalizes hour/day windows, and preserves vague phrases ("without unreasonable delay", "promptly", "as soon as practicable") when no numeric value is present. `audit-rights.ts` extracts frequency, notice, scope, permitted methods (onsite / remote / questionnaire / SOC 2 substitution / third-party auditor), cost allocation, confidentiality, and third-party-auditor permission. `subprocessor.ts` returns the most-informative subprocessor paragraph as a single normalized record covering Art. 28(2) consent form, list location (annex / URL / on-request / absent), notice days, objection right + consequence, and Art. 28(4) flow-down. `insurance.ts` extracts per-line amounts (CGL / professional / cyber / umbrella / WC / employers / auto / EPLI / fiduciary / other) with per-occurrence vs. aggregate split, ISO endorsement form numbers (CG 20 10 / CG 20 37 / CG 20 26 etc.), AM-Best rating, and notice of cancellation. `dtsa-notice.ts` detects the 18 U.S.C. § 1833(b) notice and substantive completeness across all three pillars — § 1833(b)(1) government/attorney disclosure, § 1833(b)(2) under-seal court filing, and contractor/consultant coverage. `types.ts` declares the full `V3ExtractedData` aggregate; `index.ts` re-exports every extractor + `extractAllV3(tree, {parties?})` convenience that runs all nine in dependency order. Tests at `tests/v3/extract/v3-extractors.test.ts` (23/23 passing) cover one positive + one empty/edge case per extractor + an aggregate determinism check. **723/723 tests passing + 2 intentional skips.** The v3 rule engine continues to run pattern-based against the raw document for now — Step 31 (consistency-check engine) and Step 32 (report renderer) will thread these structured outputs through, so this step is purely additive. ACORD-25 binary spatial-layout parsing for COIs remains deferred to a follow-up that depends on v2's PDF text-with-position output, consistent with the Step 29 note.
- **Addenda ruleset + six new playbooks (spec-v3 Step 29, 20 rules):** new `src/engine/rules/v3/addenda/` ruleset implementing §34 across six playbook surfaces — vendor-security-addendum (ADDENDA-001..009), ai-addendum (ADDENDA-010..016), eula (ADDENDA-017..018), saas-tos (ADDENDA-019), privacy-policy-lint (ADDENDA-020). Coverage on the **security** surface: enumerated controls + named encryption (FIPS 140-3 / AES-256 / TLS 1.2+) + security-review cadence + right-to-audit / SOC 2 substitution + incident-response window + vulnerability-disclosure + SDLC + data-classification + pen-test cadence. **AI** surface: definitions (Generative AI / Foundation Model / Output / Training Data), prohibited training-on-customer-data without opt-in (**critical**), transparency (features + default state + hosting), IP ownership of outputs, hallucination disclaimer + human-review obligation, AI subprocessor disclosure, fine-tuning-data deletion on termination. AI citations explicitly carry the "consensus practice, not statute" framing per spec §34 — NIST AI RMF / EU AI Act / FTC enforcement actions. **EULA** surface: license grant + prohibited uses; EU Digital Content Directive 2019/770 minimums. **ToS** surface: FTC Click-to-Cancel + ROSCA alignment. **Privacy-policy-lint**: CCPA § 1798.130 + GDPR Art. 13/14 + COPPA § 312.4 disclosures. New DKB node `dkb/fixtures/v3/nodes/am-best-ratings.json` carries acceptable / marginal / unacceptable AM Best rating buckets ("AM Best public ratings as of 2026-05-13 (DKB build date)") plus 8 curated common carriers. The six playbooks (`vendor-security-addendum`, `ai-addendum`, `eula`, `saas-tos`, `privacy-policy-lint`, `coi`) upgraded from placeholder to v1.0.0 with title keywords, distinguishing phrases, expected defined terms, multi-source citations, and per-surface compliance-matrix columns. `V3_RULES` now ships 220 rules total (ADDENDA 20 + BAA 45 + DPA-GDPR 55 + DPA-US-state 25 + MSA-deep 30 + NDA-deep 25 + Transfer 20). Tests at `src/engine/rules/v3/addenda/addenda-ruleset.test.ts` (12/12 passing): registry contract, inert-when-no-playbook, surface scoping (security rules don't fire on AI playbook), compliant security + compliant AI fixtures → 0 criticals, six failure-mode tests covering each surface, determinism. ACORD-25 binary spatial-layout extractor, real privacy-policy fixture corpus, and the privacy-policy / DPA consistency check are deferred to a follow-up commit (same pattern as Steps 27 + 28).
- **MSA-deep ruleset (spec-v3 Step 28, 30 rules):** new `src/engine/rules/v3/msa-deep/` ruleset implementing the §33 MSA-deep rules (MSA-001 through MSA-030). Coverage: indemnification scope + procedure + cap-carve-out flag (001–005); aggregate cap + carve-outs + mutual consequential waiver + California Civil Code § 1668 overlay + N.Y. Gen. Oblig. Law § 5-322.1 anti-indemnity (006–010); IP allocation (background / foreground) + feedback license scope (011–012); service warranties (workmanlike + conformance + no-malicious-code + compliance + non-infringement) + UCC § 2-316 implied-warranty disclaimer overreach (013–015); SLA reference + sole-and-exclusive-remedy flag (016–017); termination for material breach / insolvency / wind-down (018–020); data return / portability (021); balanced force majeure (022); assignment change-of-control silence (023); governing-law vs venue mismatch (024); amendment + no-waiver + survival + entire-agreement boilerplate (025–026); custom **order-of-precedence consistency** rule that fires when MSA precedence places it over the SOW yet operative terms (indemnity, liability cap, IP, warranty) actually live in the subordinate document (027); AI usage clause presence (NIST AI RMF, 028); Tex. Bus. & Com. Code § 151.102 anti-indemnity overlay (029); UCC § 2-719(2) limited-remedy fail-of-essential-purpose escape (030). All rules carry `category: "msa-deep"` and `applies_to_playbooks: ["msa-vendor-deep", "msa-customer-deep"]`, leaving v2's `msa-general` / `saas-vendor` / `saas-customer` LAUNCH determinism untouched. New DKB node `dkb/fixtures/v3/nodes/state-commercial-overlays.json` carries 5 `statutory_clause_requirement` entries (Cal. Civ. Code § 1668, N.Y. Gen. Oblig. § 5-322.1, Tex. Bus. & Com. Code § 151.102, U.C.C. § 2-316, U.C.C. § 2-719). `msa-vendor-deep.json` and `msa-customer-deep.json` playbooks upgraded from placeholder to v1.0.0 with title keywords, distinguishing phrases, expected defined terms, three commercial source citations each, and 16-/17-column compliance matrices. `V3_RULES` now ships 200 rules total (BAA 45 + DPA-GDPR 55 + DPA-US-state 25 + MSA-deep 30 + NDA-deep 25 + Transfer 20). Tests at `src/engine/rules/v3/msa-deep/msa-deep-ruleset.test.ts` (10/10 passing): registry contract, inert-when-no-MSA-playbook, compliant-MSA fixture under both vendor + customer playbooks → 0 criticals, five failure-mode tests (MSA-006/009/005/017/027), determinism. Playbook v2 deprecation (`msa-general` / `saas-vendor` / `saas-customer` → `*-legacy`) and Common Paper + SEC-EDGAR-sourced real-MSA fixture corpus deferred to a follow-up commit (same pattern as Step 27).
- **NDA-deep ruleset (spec-v3 Step 27, 25 rules):** new `src/engine/rules/v3/nda-deep/` ruleset implementing the 25 NDA-deep rules of spec-v3 §32 (NDA-D-001 through NDA-D-025). Coverage: DTSA whistleblower-immunity notice presence + three-pillar completeness (18 U.S.C. § 1833(b)); confidentiality term + trade-secret perpetual carve-out; all four standard Confidential-Information exclusions (publicly available, previously known, third-party lawful, independently developed); residuals-clause flag at info severity; permitted-use scope detector + 'to evaluate the Purpose' framing; return-or-destruction with attestation; injunctive relief + irreparable harm + waiver of bond; governing-law presence and viable-jurisdiction soft warning; no-precedent / MFN, non-solicit-without-general-solicitation-carve-out, no-license, authority representation, successors-and-assigns with consent; mutual-NDA symmetry detector (scoped to `mutual-nda-deep` only); unilateral-NDA role-framing check (scoped to `unilateral-nda-deep` only). Rules are `category: "nda"` and scoped via `applies_to_playbooks: ["mutual-nda-deep", "unilateral-nda-deep"]`, leaving v2's `mutual-nda` / `unilateral-nda` LAUNCH determinism untouched. `V3_RULES` now ships 170 rules total. Tests at `src/engine/rules/v3/nda-deep/nda-deep-ruleset.test.ts` (8/8 passing) — registry contract, playbook scoping, compliant-mutual-NDA fixture → 0 criticals, determinism, four failure-mode cases. Playbook v1.0.0 metadata refresh and Common Paper / CUAD fixture corpus deferred to a follow-up commit.

### Changed

- **Browser tab title simplified to "Vaulytica":** removed the keyword-rich subtitle from `<title>` in `site/index.html`. OG / Twitter / JSON-LD titles (which carry the full SEO copy) are unchanged.
- **Research-driven fixture + rule expansion (rule count 101 → 106; fixture corpus 13 → 25):** a 3-agent parallel research swarm surfaced common real-world drafting pitfalls absent from the existing catalog (residuals clauses, AI/ML training rights over Customer Data, training-repayment / "TRAP" clauses, unilateral SaaS suspension, out-of-state choice-of-law on California workers, MFN pricing, CAM gross-up asymmetry, security-deposit overcollection, hostage-data termination, AMN-style non-solicits, DTSA whistleblower notice gaps). Twelve new bad-* fixtures were synthesized to exercise each pattern, each generated deterministically by `tests/fixtures/build-fixtures.ts`. Five high-value rules were added to catch the most common patterns:
  - **OBLI-009 — Residuals clause swallows confidentiality (warning, obligations; 102nd rule).** Detects `Residuals` / `unaided memory` / `general knowledge, skills and experience` carve-outs that effectively license trade secrets via human memory. Cites Dentons / Venable / Galkin practitioner guidance. 4 dedicated tests.
  - **CHOICE-011 — Out-of-state choice-of-law on California worker (warning, choice-and-venue; 103rd rule).** Fires when a California-resident / California-working signal is present AND the governing-law selection is non-California. Cites Cal. Lab. Code § 925 and Cal. Bus. & Prof. Code § 16600.5. 3 dedicated tests.
  - **PERS-008 — Training-repayment / stay-or-pay clause (critical, personnel; 104th rule).** Detects training-cost / signing-bonus / relocation claw-back clauses. Cites NLRB GC Memorandum 25-01 (Oct. 7, 2024) and N.Y. Trapped at Work Act (Dec. 2025). 5 dedicated tests.
  - **DARK-008 — Unilateral suspension without notice or cure (warning, dark-patterns; 105th rule).** Detects `Vendor may suspend the Service immediately / without notice / in its sole discretion` framings. Cites Morgan Lewis Sourcing@MorganLewis + ContractNerds. 3 dedicated tests.
  - **IPDATA-009 — AI / model-training rights over Customer Data (critical, ip-and-data; 106th rule).** Detects licenses to use Customer Data to train / develop / improve ML / AI models. Cites GDPR Art. 17, *Andersen v. Stability AI*, *Getty Images v. Stability AI*. 3 dedicated tests.

  Sanity-guard entries were added in `tests/integration/fixture-sanity.test.ts` for all 12 new fixtures, and the golden corpus was regenerated against the new 106-rule registry. **Fixture corpus is now 25 fixtures (target was ≥2–3 per major category); every launch playbook now has 2–3 distinct exemplars in the bad-* corpus.**

### Changed

- **Bundle splitting for initial-load performance (LAUNCH.md row l):** the full analysis pipeline (pdfjs, mammoth, docx, decimal, zod, tesseract) is split out of `src/ui/main.ts` into `src/ui/pipeline.ts` and dynamic-imported on first file drop / drag-over / `requestIdleCallback`. Initial-load JS shrinks from **560 KB → 9.51 KB** (gzipped 165 KB → 3.75 KB) — a ~45× reduction in what blocks first paint.
- **Manual chunk groups in `vite.config.ts`:** every heavy dependency is now an isolated vendor chunk (`vendor-pdfjs`, `vendor-mammoth`, `vendor-docx`, `vendor-tesseract`, `vendor-decimal`, `vendor-zod`) so a bump to one dep doesn't invalidate the cache for the others. With the year-long immutable cache on `/assets/*`, returning users only pay for the chunk that actually changed. Vaulytica's own pipeline code is its own ~115 KB (36 KB gz) chunk.
- **Parallel playbook fetch:** `ensurePlaybooks` in `src/ui/pipeline.ts` now fetches all 12 launch playbook JSONs via `Promise.all` instead of a sequential `for`-loop. Order in the result still mirrors `LAUNCH_PLAYBOOK_IDS` (Promise.all preserves index). The service worker pre-caches `/playbooks/*` so cold load gets HTTP/2 multiplexing; warm load is cache-hit-then-respond regardless.
- **FIN-001 + FIN-002 no longer skipped by NDA playbooks:** both rules have narrow pattern matchers (`<spelled-out amount> (<numeral>)` and `the <Name> of $X`) so they only fire when monetary content actually appears in the document. Skipping them on NDAs was over-cautious — when an NDA *does* carry a liquidated-damages clause, the mismatch is a real drafting error worth catching. The bad-nda fixture's intentional `fifty thousand dollars ($75,000)` mismatch now fires. **bad-nda intentional-violation detection now sits at 5/5 (was 4/5).** Other FIN-* rules (003 through 008 — fees, payment terms, late fees, etc.) remain skipped on NDA playbooks because they truly don't apply.

### Added

- **PERS-007 — IC misclassification signals (warning, personnel; 101st rule)**: when the document labels a worker as `independent contractor` AND ≥2 employee-indicator signals appear (fixed daily hours / company-supplied equipment / daily reporting / exclusivity / salary-like flat monthly retainer / required on-site presence), the rule fires. Cites IRS 20-factor test, DOL economic-realities test, California AB-5 ABC test, Massachusetts M.G.L. c.149 §148B. 6 dedicated tests including a clean IC engagement (silent), 2-signal, 3-signal, label-without-signals, signals-without-label, and salary-shaped-IC paths.
- **Lighthouse CI workflow + budgets (LAUNCH.md row l)**: new `.github/workflows/lighthouse.yml` + `lighthouserc.json` run Lighthouse against the built `dist/` on every push and PR using the mobile-4G throttled preset. CI fails if FCP > 1500 ms, LCP > 2000 ms, TTI > 2000 ms, TBT > 200 ms, CLS > 0.1, or category scores drop below performance 0.85 / accessibility 0.95 / best-practices 0.9 / SEO 0.9. 3 runs per build to dampen noise. Catches performance regressions before they reach `vaulytica.com`.
- **Playbook fixture coverage enforcement (`tests/integration/playbook-coverage.test.ts`)**: 13 assertions — for every id in `LAUNCH_PLAYBOOK_IDS`, the test runs every committed fixture and asserts that at least one fixture's matched playbook is that id, OR that the id is explicitly listed in `EXEMPT_PLAYBOOK_IDS` with a stated reason. Today's exempt list: `generic-fallback` (implicit fallback) and `saas-vendor` (overlaps saas-customer for generic SaaS docs; exercised via bad-saas-vendor.docx but matched as saas-customer). A new playbook added without a fixture now fails CI.
- **`bad-sow.docx` fixture (corpus 12 → 13)**: targets the `sow` playbook (child of `msa-general`). Matched `sow` at 0.9 confidence. Intentional violations: undefined deliverables (`as further detailed by Customer from time to time at Customer's sole discretion`), 2%/month late fee, `[TBD]` placeholder, `best efforts` undefined. Sanity guard locks in STRUCT-013, FIN-009, OBLI-008. **Playbook fixture coverage: 10 → 11 of 12 launch playbooks** — only the implicit `generic-fallback` is now uncovered, and that's by design.
- **bad-saas-vendor.docx + bad-consulting.docx fixtures (corpus 10 → 12)**: two more synthetic fixtures. `bad-saas-vendor.docx` carries aggressive vendor-side language (99.99% uptime via `best efforts`, IP indemnity, cap with indemnity carve-out) and surfaces FIN-009 + IPDATA-007 + RISK-015 + OBLI-008 + STRUCT-013. The matcher picks `saas-customer` over `saas-vendor` because the playbooks share most features for a generic SaaS doc; sanity guard is playbook-agnostic. `bad-consulting.docx` (matched `consulting-agreement` @ 0.9 confidence) exercises the new PERS-007 rule alongside PERS-005, PERS-006, OBLI-008, STRUCT-013. **Playbook fixture coverage: 8 → 10 of 12 launch playbooks** (mutual-nda, unilateral-nda, employment-at-will-us, independent-contractor, saas-customer, msa-general, lease-commercial-multitenant, lease-residential-us, consulting-agreement — plus implicit coverage of the remaining 2 via shared features).
- **Cross-OS test-matrix workflow (LAUNCH.md row c)**: new `.github/workflows/test-matrix.yml` runs the full lint + typecheck + test suite on `ubuntu-latest` + `macos-latest` + `windows-latest` against Node 20 on every push to main and every PR. Verifies the engine's cross-machine `result_hash` determinism guarantee (spec §17): the determinism-guard + golden-output suites pin the hash; the matrix verifies the same hash across three OSes. Sets `VAULYTICA_SKIP_BUILD_TESTS=1` so the heavy SRI build test runs only in the deploy workflow.
- **Static HTML validation tests (LAUNCH.md rows h + j)**: new `tests/integration/static-html.test.ts` adds 20 assertions across two surfaces. **Row j (OG / Twitter Card meta tags):** every required OG property (`og:title`, `og:description`, `og:image`, `og:url`, `og:type`, `og:site_name`) plus every Twitter Card property (`twitter:card`, `twitter:title`, `twitter:description`, `twitter:image`) is present; `og:url` matches `https://vaulytica.com`; `og:title` ≤ 70 chars; `og:description` ≤ 200 chars; `og:type` is `website`; `twitter:card` is `summary_large_image`; viewport + theme-color metas present. **Row h (static accessibility):** `<html lang>` declared, charset meta present, `<main>` / `<nav>` / `<footer>` landmarks present, `alt` on every `<img>`, `aria-label` + `tabindex="0"` on every non-native `role="button"`, no `<a href="#">` placeholder anchors, multi-nav `aria-label` discipline. Neither replaces the live axe audit / live link-preview test but both catch the static-shape regressions before they ship.
- **schema.org JSON-LD validation tests (LAUNCH.md row k)**: new `tests/integration/schema-org.test.ts` parses every `application/ld+json` block out of `site/index.html` and asserts (1) exactly 4 blocks ship (Organization + SoftwareApplication + TechArticle + FAQPage), (2) every block uses the schema.org @context, (3) each block carries its required Rich Results fields, (4) no terse FAQ answers, (5) no whitespace-padded Question names. **8 assertions; a regression in any block now fails CI before it ships.** **Site fix shipped alongside**: TechArticle was missing `author` and is now properly attributed to the Vaulytica organization — strengthens the Rich Results card on the deployed site.
- **bad-unilateral-nda.docx + bad-residential-lease.docx + bad-msa.docx fixtures (corpus 7 → 10, spec §27 row-(m) target hit)**: three more synthetic fixtures rounding out playbook coverage. `bad-unilateral-nda.docx` (unilateral-nda @ 1.0 confidence) — uncapped damages + survival-silent + placeholder. `bad-residential-lease.docx` (lease-residential-us @ 1.0 confidence) — 7-day non-renewal + 60%/year late fee + asymmetric pre-suit notice + browsewrap modification + tenant non-disparagement + placeholder. `bad-msa.docx` (msa-general @ 1.0 confidence) — MAC clause + undefined `reasonable efforts` + uncapped indemnity + bare insurance + DE-law/TX-venue mismatch + asymmetric termination + placeholder. **Sanity-guard entries added; all 16 newly-required rules fire. Spec §27 row-(m) corpus target reached: 10/10 fixtures.** Direct playbook fixture coverage now stands at 8 of 12 launch playbooks (mutual-nda, unilateral-nda, employment-at-will-us, independent-contractor, saas-customer, msa-general, lease-commercial-multitenant, lease-residential-us). The remaining 4 (saas-vendor, sow, consulting-agreement, generic-fallback) are either children of covered playbooks (sow ⊂ msa) or implicit (generic-fallback).
- **Pipeline body-text fix**: both `src/ui/pipeline.ts` and `tests/integration/_pipeline-helpers.ts` previously walked only `sections[0]` for the body text passed to `matchPlaybook`. This caused unilateral NDAs to match mutual-nda because the unilateral-specific phrasing (`the Disclosing Party`, `the Receiving Party`, `shall not disclose`) lives deeper in the document. Both helpers now recursively walk every section + child paragraph. Verified by `bad-unilateral-nda.docx` now matching `unilateral-nda` at 1.0 confidence instead of mutual-nda at 0.8.
- **FIN-009 regex broadened**: the keyword-to-rate gap can now contain a colon (`Late fee: 5% per month` previously slipped through). The `\s+` between the keyword and the rate was tightened to `[:\s]` so colon-separated formats match. Caught by the `bad-residential-lease.docx` sanity guard.
- **bad-lease.docx + bad-contractor.docx fixtures + sanity guards**: 6th and 7th synthetic fixtures. `bad-lease.docx` exercises the `lease-commercial-multitenant` playbook (matched at 0.7 confidence) with 7 intentional violations covering the unique commercial-real-estate surface (Premises placeholder, 10-day non-renewal window, 36%/year late fee, bare insurance clause, uncapped indemnification, asymmetric pre-suit notice, one-sided jury waiver) — all 7 fire. `bad-contractor.docx` exercises the `independent-contractor` playbook (matched at 0.8 confidence) with a misclassification-dark-pattern setup (fixed hours, company tools, exclusivity, non-compete in California, non-disparagement, asymmetric termination, class-action waiver) — 5 rules fire to surface the pattern. **Pushes the spec §27 row-(m) corpus from 5 → 7 fixtures (target: 10).** The 12 launch playbooks now have direct fixture coverage for 5 of 12: mutual-nda, saas-customer, employment-at-will-us, lease-commercial-multitenant, independent-contractor.
- **bad-employment.docx fixture + sanity guard**: 5th synthetic fixture covering the `employment-at-will-us` playbook (no fixture exercised this surface before). Seven intentional violations target the post-1.0 personnel + dark-pattern rules: California non-compete (PERS-005), non-disparagement without NLRA/SEC carve-outs (PERS-006), asymmetric termination-for-convenience (TERM-009), one-sided jury-trial waiver (CHOICE-010), undefined `best efforts` (OBLI-008), class-action waiver (DARK-005), survival clause silent on confidentiality + IP (TEMP-012). All 7 fire under the matched `employment-at-will-us` playbook. Sanity guard in `fixture-sanity.test.ts` locks them in. Golden generated.
- **Subresource Integrity (SRI) on the main module-script tag (threat-model hardening item):** new `subresourceIntegrity` Vite plugin runs after `deployAssets`'s `closeBundle` and rewrites every same-origin `<script src=…>` and `<link rel="modulepreload|preload|stylesheet" href=…>` in `dist/index.html` to carry an `integrity="sha384-…"` + `crossorigin="anonymous"` pair generated from the on-disk asset bytes. If a CDN cache, misconfigured edge, or supply-chain attacker swaps a JS chunk, the browser refuses to execute it — the page goes blank rather than silently running tampered code. Dynamic-import chunks load *after* the entry's SRI check passes, so this hardens the actual entrypoint. `tests/integration/sri.test.ts` runs `npm run build` and verifies the emitted hash matches `sha384(read on-disk asset)` byte-for-byte. `docs/threat-model.md` updated.
- **🎯 100-rule milestone: OBLI-008 + CHOICE-010 (99th + 100th rules):**
  - **OBLI-008 — Efforts standard undefined (info, obligations)**: surfaces `best efforts` / `commercially reasonable efforts` / `reasonable efforts` / `good faith efforts` / `diligent efforts` when no in-document `"<phrase>" means …` definition exists. Different efforts-standard phrases carry materially different obligation strengths under *Bloor v. Falstaff* (2d Cir. 1979) and its progeny. Silent when the phrase is defined. 5 dedicated tests.
  - **CHOICE-010 — Asymmetric jury-trial waiver (warning, choice-and-venue)**: fires when a jury-trial waiver binds one named party (Customer / Licensee / Recipient / Employee / Tenant / Contractor / Consumer / User / Buyer / Purchaser / Borrower) without imposing a mirror waiver on the drafter. Cites *Leasing Service Corp. v. Crane* (4th Cir. 1986) on the `knowing and voluntary` standard. Silent on bilateral `each party hereby waives` framings. 5 dedicated tests.
- **PERS-006 — Non-disparagement clause present (warning, personnel; 96th rule):** surfaces `non-disparagement`, `shall not disparage`, `will not make disparaging remarks` language for explicit review against NLRB *McLaren Macomb* (Feb 2023) and SEC Rule 21F-17 whistleblower-carve-out requirements. 4 dedicated tests.
- **DARK-007 — Browsewrap / passive-acceptance language (warning, dark-patterns; 97th rule):** detects `by using the Service you agree`, `continued use constitutes acceptance`, `you are deemed to have agreed` and similar passive-acceptance constructs that lack an affirmative consent step. Cites *Specht*, *Nguyen*, *Berkson*. 5 dedicated tests.
- **TEMP-012 — Survival clause silent on sticky obligations (warning, temporal; 98th rule):** when survival language exists AND confidentiality / IP-ownership / indemnification language exists, the rule names every sticky obligation the survival clause failed to enumerate. Silent when survival expressly names every present sticky obligation. 5 dedicated tests.
- **FIN-009 — Late fee above 18%/year (warning, financial; 93rd rule):** parses interest / late-fee / finance-charge rates and normalizes to annual (`2% per month` → 24%, `0.05% per day` → 18.25%). Fires when annualized rate > 18%. Cites N.Y. Gen. Oblig. Law § 5-501. 6 dedicated tests covering month/year/day periods, the 1.5%/month boundary, and the silent-no-rate path.
- **IPDATA-008 — Cross-border data transfer without safeguard (warning, ip-and-data; 94th rule):** fires when the contract authorizes data transfer outside the EU/EEA/UK/US/etc. but no clause references Standard Contractual Clauses, BCRs, an adequacy decision, the Data Privacy Framework, or GDPR Article 46 / Chapter V. 6 dedicated tests across each safeguard form + the no-transfer-language silent path.
- **RISK-016 — Insurance requirement without coverage minimum (warning, risk-allocation; 95th rule):** fires when the contract requires the counterparty to `maintain insurance` / `carry insurance` / `procure coverage` without specifying a per-occurrence or aggregate minimum or a `not less than $X` clause. 6 dedicated tests including `$X per occurrence`, `at least $X`, and `not less than $X` framings.
- **STRUCT-015 — Numbered section gaps (info, structural; 90th rule):** walks the section outline and reports any gap in dotted-decimal numbering (Section 1, 2, 4 → missing 3). Conservative: requires ≥3 numbered siblings before firing so unrelated stragglers don't trigger noise. 5 dedicated tests.
- **PERS-005 — Non-compete clause present (warning, personnel; 91st rule):** surfaces `non-compete`, `covenant not to compete`, `shall not directly or indirectly compete`, and similar phrasings. Cites Cal. Bus. & Prof. Code § 16600 because enforceability splits sharply by jurisdiction (California voids; Washington narrow; Texas requires § 15.50 fit; FTC 2024 nationwide ban vacated). Doesn't fire on bare non-solicitation. 4 dedicated tests.
- **TERM-009 — Asymmetric termination-for-convenience (warning, termination; 92nd rule):** fires when one party (Vendor / Provider / Company / Licensor / Employer / Landlord / Disclosing Party) can terminate at any time / in its sole discretion AND the counterparty (Customer / Licensee / Employee / Tenant / Contractor) is bound by a cure-period or material-breach gate. Skips bilateral `either party may terminate` framings. 4 dedicated tests.
- **OBLI-007 — Material Adverse Change clause present (warning, obligations; 87th rule):** surfaces `material adverse change` / `material adverse effect` / `MAC event` / `MAE clause` language for explicit review. Doesn't fire on bare `material breach`. 5 dedicated tests.
- **IPDATA-007 — Data retention period unspecified (warning, ip-and-data; 88th rule):** fires when the contract handles data (`Customer Data`, `personal data`, `PII`, `DPA`, `data processing`) but no clause specifies retention duration, deletion, return-or-destroy, or purge obligations. Aligns with GDPR Art. 5(1)(e) / CCPA retention-definition expectations. 5 dedicated tests.
- **CHOICE-009 — Governing law differs from venue jurisdiction (info, choice-and-venue; 89th rule):** surfaces contracts where the choice-of-law jurisdiction is different from the venue / forum jurisdiction (e.g., "Delaware law, California venue"). Uses the jurisdictions extractor's normalized `jurisdiction_id` when available, falls back to a text-comparison otherwise. 4 dedicated tests.
- **TEMP-011 — Auto-renewal notice window under 30 days (warning, temporal; 84th rule):** parses the number of days specified in a non-renewal notice clause and fires when it's < 30. Matches `30 days prior written notice`, `thirty (30) days`, `30-day notice`, `at least 30 days prior`. Cites the FTC Negative Option Rule (`stat-16-cfr-425`). The example rule from `docs/adding-a-rule.md` is now a real implementation. 5 dedicated tests.
- **RISK-015 — Indemnification without aggregate cap (warning, risk-allocation; 85th rule):** fires when indemnification language (`shall indemnify`, `hold harmless`, `defend and indemnify`) is present and either (a) no liability cap exists anywhere in the document, or (b) a cap exists but explicitly carves out indemnification (`limited to twelve months… except for indemnification obligations`). 5 dedicated tests covering both fail modes + the silent-on-clean-cap path.
- **DARK-006 — Asymmetric pre-suit notice / cure window (warning, dark-patterns; 86th rule):** detects clauses requiring one party (Customer / Employee / Licensee / Tenant / Contractor / Consumer / User / Buyer) to give pre-suit notice or a cure period before initiating a claim, without imposing the same gate on the drafter. Skips bilateral framings like `each party shall…`. 4 dedicated tests.
- **DARK-005 — Class-action waiver (critical, dark-patterns; 83rd rule):** detects clauses that prohibit class-action participation, force individual arbitration, or waive collective- / representative-action rights. Regex covers `waives [right to] class action`, `gives up the right to [join a] collective action`, `no class action`, `on an individual basis only`. Cites the FTC deception statement; relevant in consumer- and employee-facing contracts since AT&T Mobility v. Concepcion (2011) and Epic Systems v. Lewis (2018). 6 dedicated tests.
- **STRUCT-014 — Inconsistent defined-term casing (info, structural; 82nd rule):** when a multi-word Title-Case term is defined (`"Confidential Information" means …`) but referenced in lowercase elsewhere (`recipient may not share confidential information`), the lowercase form is flagged. Skips single-word defined terms (too noisy) and sentence-start lowercase (often unavoidable). 5 dedicated tests.
- **STRUCT-013 — Unfilled template placeholders (critical, structural; 81st rule):** catches `[insert …]`, `[Title-Case Name]`, `[TBD]` / `[REDACTED]` / `[PLACEHOLDER]` / `[PENDING]`, `{{mustache}}`, `<<angle>>`, `XXX`-runs of 3+ uppercase Xs, and underscore-line placeholders of 10+ chars. Doesn't fire on bracketed footnotes like `[1]` or `[a]`. Runs in every playbook (no override). Combined with the FIN-001 skip-lift below, `bad-nda.docx` now catches **5/5** intentional violations (was 2/5 at v1.0.0).
- **Per-fixture sanity guards (`tests/integration/fixture-sanity.test.ts`):** pin down the rule IDs that **must** fire for each bad-* fixture so a rule regression that silently drops a finding is caught even when the `result_hash` legitimately drifts. Today's lockdown: `bad-nda.docx` → TEMP-001 + STRUCT-007 + STRUCT-013 + FIN-001 + RISK-009 (5/5 intentional violations); `bad-saas.docx` → TEMP-004 + OBLI-002 + RISK-011. Clean fixtures are intentional `it.skip` placeholders.
- **End-to-end report-builder test (`tests/integration/end-to-end-report.test.ts`):** for every committed fixture, runs the live engine, hands the `EngineRun` to `buildDocxReport` + `buildJsonReport`, and asserts the DOCX is a valid OOXML zip + the JSON re-serializes with the same `result_hash`. Catches regressions where the report builder chokes on real engine output (the existing unit tests use mocked runs).
- **Cross-run determinism guard (`tests/integration/determinism-guard.test.ts`):** every fixture runs 5 times in the same process; asserts one unique `result_hash` per fixture. Pins down determinism alongside the existing all-rules + golden-output suites; the cross-machine half lands once the launch CI matrix fans out across ubuntu/macos/windows.

### Fixed

- **RISK-009 ("Uncapped liability") regex broadened** to match the canonical `(liable|responsible) for all damages…without limitation` phrasing alongside the original `unlimited liability` / `no cap on liability` / `without (any) cap/limitation on (its) liability` forms. The bad-nda fixture's intentional violation now fires.
- **Extractor + rule precision (v1.1 backlog from LAUNCH.md):** eight detection gaps closed and the corresponding tests re-enabled (no more `it.skip` + `// TODO(v1.1)` markers): `extractDates` named-anchor detection ("the Effective Date") now case-insensitive with titlecase normalization; `extractDates` ISO branch emits `iso: undefined` for calendar-impossible dates instead of skipping them, so TEMP-001 ("Impossible date") fires; `extractJurisdictions` governing-law regex case-insensitive; `extractObligations` `TRIGGER_RE` accepts word-number durations like `within thirty (30) days`; `extractParties` `PARTY_DECL` regex dropped the `/i` flag that was slurping lowercase connectives (`is`/`made`/`between`/`and`) into the captured name and dropping `jurisdiction_of_formation`; TEMP-004 auto-renewal regex matches `renews automatically` / `auto-renew` / `shall renew automatically`; RISK-007 consequential-damages-waiver regex matches the canonical `Neither party shall be liable for consequential, special, incidental, or punitive damages` phrasing. Golden outputs regenerated.
- Test suite: **453/453 passing + 2 deliberately skipped** (the 2 clean fixtures in `fixture-sanity.test.ts` are intentional placeholders; the previous skip-count of 7 from v1.0.0 was real regressions).

## [1.0.0] — 2026-05-12

Initial public release. Vaulytica is now feature-complete for the seventeen-step build plan in [`spec.md`](docs/spec.md) §26.

### Added

- **Repo scaffolding (Step 0):** TypeScript + Vite + Vitest, ESLint, Prettier, EditorConfig, .nvmrc pinned to Node 20. Directory structure per spec §6.
- **Marketing site (Step 1):** Single-file `site/index.html` — nav, hero, drop zone, "what I check" grid, inline SVG architecture diagram, "what I do not do," "why no AI," "your privacy," 12-card source grid, 10-question FAQ, footer. Four schema.org JSON-LD blocks (Organization, SoftwareApplication, TechArticle, FAQPage). OG + Twitter meta. Theme toggle. FAQ accordions.
- **Ingest layer (Step 2):** `pdfjs-dist`-backed PDF ingest with heading-from-font-size heuristics; `mammoth`-backed DOCX ingest with `parseDocxHtml` exposed for tests; paste ingest with ATX + Setext heading detection; `normalize.ts` for stable IDs + contiguous offsets; SHA-256 hashing.
- **OCR fallback (Step 3):** `tesseract.js`-backed OCR triggered only when the PDF text layer is empty and the caller opts in. OffscreenCanvas + per-call worker lifecycle.
- **Extractors (Step 4):** Nine pure extractors — `parties`, `dates`, `amounts` (decimal.js-backed normalizer), `definitions`, `sections`, `crossrefs`, `obligations` (LEXDEMOD-style), `jurisdictions`, `classifier`. `extractAll` composes them in dependency order.
- **DKB scaffolding (Step 5):** Typed shapes + Zod schemas + version helpers + `loadDkb` with IndexedDB cache and offline fallback. Hand-authored starter DKB at `dkb/dist/v0.0.1-starter/` (30 clauses, 12 jurisdictions, 10 definition templates, 8 dark patterns, 30 statutory citations, 14 classifier patterns).
- **Rule engine + 12 launch rules (Step 6):** Engine core (`finding.ts`, `ordering.ts`, `runner.ts`) with SHA-256 `result_hash` over canonicalized run. STRUCT-001..008, FIN-001, FIN-002, TEMP-001, RISK-009.
- **Remaining 68 rules (Step 7):** Full 80-rule catalog per spec §18 across structural / financial / temporal / obligations / risk-allocation / choice-and-venue / termination / IP-and-data / personnel / dark-patterns categories. Shared `rules/_helpers.ts`.
- **Playbook system + 12 playbooks (Step 8):** Zod-validated `Playbook` type, deterministic `matchPlaybook` (additive per-match scoring: +0.3 title / +0.4 required-clause / +0.2 distinguishing / −0.1 negative; threshold 0.5; lexicographic tiebreak), `parsePlaybook` + `fetchPlaybooks` loaders, 12 JSON playbooks under `playbooks/` (mutual-nda, unilateral-nda, employment-at-will-us, independent-contractor, saas-customer, saas-vendor, msa-general, sow, lease-commercial-multitenant, lease-residential-us, consulting-agreement, generic-fallback).
- **DOCX + JSON report builder (Step 9):** `docx@^9.6`-backed `buildDocxReport(run, ingest, dkb, playbook)` producing the cover / executive summary / findings / obligations / extracted appendix / audit trail / verbatim disclaimer per spec §22; US Letter, Arial 11pt, mint accent. `buildJsonReport`, `formatCitation` (Bluebook flavor for U.S.C. / C.F.R. / public-law / state-code citations), `buildBibliography` with document-order numbering.
- **DKB build pipeline part 1 (Step 10):** `dkb/build/sources.yaml` with all 8 sources from §12, `RateLimitedHttp` client with per-source RPS + UA + retry, `FilesystemCache` + `MemoryCache`, 8 fetchers (edgar, uscode, ecfr, govinfo, commonpaper, cuad, ledgar, ulc) each splitting a pure `parse*` function from the network orchestrator. CLI: `npm run dkb:fetch -- <id>`.
- **DKB build pipeline part 2 (Step 11):** `stopwords.txt`, `classifier_taxonomy.json` (55+ canonical clauses reconciling CUAD + LEDGAR), deterministic TF-IDF trainer with byte-stable JSON output, 27 hand-authored regex pattern overlays, `build.ts` orchestrator, `regression.ts` golden-output harness, `.github/workflows/dkb-rebuild.yml` weekly cron with PR-on-diff.
- **UI hookup (Step 12):** `src/ui/` modules (`theme.ts`, `dropzone.ts`, `progress.ts`, `ticker.ts`, `states.ts`, `main.ts`). Drop zone transforms in place through empty → analyzing → complete states. Full pipeline: file → ingest → extract → loadDkb (cached) → matchPlaybook → runEngine with live `onRule` progress → buildDocxReport → Blob URL download.
- **PWA + offline (Step 13):** Service worker with per-concern caches (`-html`, `-assets`, `-dkb`, `-playbooks`), network-first / cache-first-revalidate / stale-while-revalidate strategies. Manifest with full icon set (PNG 192/512 + maskable-512 generated from `favicon.svg` via `sharp`). `npm run icons` regenerates. "Works offline" footer badge once the SW is in control.
- **Cloudflare Pages deployment (Step 14):** Vite plugin emits `dist/_headers` (strict CSP with `connect-src 'self'`, Permissions-Policy denying hardware APIs, HSTS, COOP/CORP, per-route cache rules) + `dist/_redirects`. Build hook copies `playbooks/`, latest `dkb/dist/<v>/`, icons, manifest, and `sw.js` into `dist/`. Playwright smoke test asserts ZIP magic bytes + zero cross-origin requests during analysis. Deploy workflow at `.github/workflows/deploy.yml`.
- **Documentation (Step 15):** `docs/architecture.md`, `docs/adding-a-rule.md`, `docs/adding-a-playbook.md`, `docs/data-sources.md`, `docs/threat-model.md`, `docs/determinism.md`. CONTRIBUTING rewritten with full PR flow, accept/reject rules, and verification gate. README docs section.
- **Test corpus + golden outputs (Step 16):** `tests/fixtures/build-fixtures.ts` deterministically generates `mutual-nda.docx` (clean baseline), `bad-nda.docx` (5 intentional violations), `bad-saas.docx` (auto-renewal-buried + unilateral mod right + asymmetric indemnity), `pasted-mutual-nda.txt`. `tests/integration/golden-output.test.ts` asserts `result_hash` + canonical-JSON equality against committed goldens; `npm run fixtures:regen-golden` updates the baseline on deliberate rule changes.
- **Launch checklist (Step 17):** [`LAUNCH.md`](LAUNCH.md) tracks every spec §27 item with status / date / verifier. Cross-machine determinism row is the load-bearing claim; mechanical items pass, deployment-bound items remain ⏳ pending until the v1.0.0 deploy.

### Changed

- **Engine runner determinism fix:** `computeResultHash` now blanks `execution_log[*].elapsed_ms` along with `result_hash` and `executed_at`. Pre-existing bug where repeated runs produced different hashes is fixed. The determinism contract (spec §17) is now genuinely cross-machine, not just same-machine-fast-enough.
- **Runner API:** Optional `onRule({ rule, index, total, fired })` progress callback on `runEngine` — used by the UI ticker, optional for tests, deterministic-safe.

### Production dependencies

`decimal.js`, `docx`, `mammoth`, `pdfjs-dist`, `tesseract.js`, `zod`.

### Dev dependencies

`@playwright/test`, `@types/js-yaml`, `@types/node`, `@typescript-eslint/eslint-plugin`, `@typescript-eslint/parser`, `@xmldom/xmldom`, `eslint`, `eslint-config-prettier`, `happy-dom`, `js-yaml`, `prettier`, `sharp`, `tsx`, `typescript`, `vite`, `vitest`.

[1.0.0]: https://github.com/claygood/vaulytica/releases/tag/v1.0.0
