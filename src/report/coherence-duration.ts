/**
 * Cross-document negotiation-posture **exposure duration** — per front, the *mean*
 * number of rounds its binding floor sat *below* the acceptable floor across its
 * recovered exposures: the central-tendency *magnitude* of the same fall-to-recovery
 * episodes v28 pairs, where v28 reads only the *extreme* (spec-v40).
 *
 * v28 ({@link computeCoherenceLatency}) pairs each *fall* crossing with the *recovery*
 * crossing that closes it and reads two reductions: the deal's **slowest** single
 * recovery (`max_latency`, an extreme) and whether any fall went **unrecovered**
 * (`open_count`, the gate). Both throw away the one read a deal lead asks reviewing a
 * close: not the single worst episode, but the **typical** one — *when this front
 * falls below the floor, how many rounds does it usually take to come back?* A count
 * (v24), an index (v26/v27), a rate (v39), or an extreme (v28's `max_latency`) all
 * collapse the episode *durations* to a single number that the typical episode does
 * not see:
 *
 * - The **one bad round.** Cap recovers in 1 round, 1 round, 1 round, then once takes
 *   5 — `max_latency` 5 (the deal's slowest), but a **mean** of 2 rounds. One episode
 *   dragged; the front usually recovers fast.
 * - The **chronic lingerer.** Term recovers in 4 rounds, 4 rounds, 4 rounds — the same
 *   `max_latency`-class extreme would call Cap worse (5 > 4), yet Term's **mean** is 4:
 *   every exposure drags. It is the front that *typically* stays exposed longest, which
 *   the single worst episode structurally cannot name.
 *
 * That is a missing **axis**: the *duration-magnitude* dimension of the same fall-to-
 * recovery episodes. Where v28 reads the single longest closed episode, v40 reads the
 * **mean** closed episode per front — the central tendency, not the extreme — and gates
 * on a front whose *typical* recovered exposure spans **at least two rounds**
 * (`total_rounds ≥ 2 × closed_episodes`, an integer-exact bar): the front that, on
 * average, does *not* recover the very next round.
 *
 * It is a reduction of the **same** episodes v28 pairs — `computeCoherenceLatency` is
 * imported and reused unchanged (the join pattern v38 used for v36+v37), so
 * `total_closed_episodes` equals v28's `recovered_count` and `total_open_episodes` its
 * `open_count` by construction. It adds **no** posture math beyond averaging the closed
 * episode lengths v28 already computes over the `below-acceptable` rung v10 defines. The
 * posture filter (spec-v10 §3), restated:
 *  - **Deterministic** — same N coherences in the same order → identical `duration_hash`,
 *    on any machine. Fronts are pinned by `localeCompare(_, "en")` (the order v28 already
 *    pins); the round order is the caller's. The longest-mean pick is decided by *integer
 *    cross-multiplication* (`total_rounds × closed_episodes` of the two fronts), never a
 *    float comparison, so the ranking is exact and platform-independent.
 *  - **Honest about unstated data** — a front no document states does not fall or recover
 *    (the §3 contract v28 already enforces): silence contributes no episode, so a front
 *    that never fell in-sequence carries no mean (`steady`), and an unstated front carries
 *    none (`unstated`). An *open* episode (a fall that never recovered) is an *unbounded*
 *    duration with no finite length to average, so it is counted (`open_episodes`) but
 *    excluded from the mean — v28's gate owns the unrecovered fall; v40 reads the
 *    *recovered* exposures' typical length.
 *  - **Advisory** — the report names how long the team's own floor *typically* stays
 *    crossed between a fall and its recovery. It asserts no legal conclusion.
 *  - **Additive** — the duration carries its own `duration_hash`, namespaced apart from
 *    every `coherence_hash`, `movement_hash`, `trajectory_hash`, `shift_trajectory_hash`,
 *    `arc_hash`, `exposure_hash`, `persistence_hash`, `breadth_hash`, `recurrence_hash`,
 *    `volatility_hash`, `synchrony_hash`, `settling_hash`, `onset_hash`, `latency_hash`,
 *    `concurrency_hash`, `relapse_hash`, `tenure_hash`, `affinity_hash`,
 *    `recovery_affinity_hash`, `opposition_hash`, `precedence_hash`, `concession_hash`,
 *    `recovery_order_hash`, `weak_front_hash`, and `cadence_hash`, so computing it moves
 *    no golden.
 */

import { sha256Hex } from "../ingest/hash.js";
import { stableStringify } from "../engine/runner.js";
import type { NegotiationTier } from "../playbooks/custom-interpreter.js";
import type { PostureCoherence } from "./posture-coherence.js";
import { computeCoherenceLatency } from "./coherence-latency.js";

/**
 * A front's recovered-exposure duration class:
 *  - `lingering` — it has ≥ 1 *recovered* episode and its **mean** closed duration is at
 *    least two rounds (`total_rounds ≥ 2 × closed_episodes`): when it falls, it *typically*
 *    does not recover the very next round — the gate-worthy class;
 *  - `brief` — it has ≥ 1 recovered episode but its mean closed duration is *below* two
 *    rounds (`total_rounds < 2 × closed_episodes`, including a mean of exactly one — every
 *    exposure recovered the next round): its exposures are typically short;
 *  - `open` — it fell below floor in-sequence but **no** episode recovered (only an
 *    unrecovered fall, an unbounded duration with no finite length to average — v28's
 *    `--fail-on-unrecovered-exposure` owns this front);
 *  - `steady` — stated, but never *fell* below floor in-sequence (no episode to measure,
 *    including a front that recovered from a *pre-archive* exposure);
 *  - `unstated` — no document ever stated the front (§3: silence is not exposure).
 */
export type DurationClass = "lingering" | "brief" | "open" | "steady" | "unstated";

/** One negotiation front's whole-sequence recovered-exposure duration. */
export type CoherenceDurationFront = {
  dimension: string;
  /** The binding floor at each round, in sequence order (`null` = unstated that round). */
  floors: (NegotiationTier | null)[];
  /** The lengths (in rounds below floor) of every *recovered* episode, sorted ascending. */
  latencies: number[];
  /** How many episodes recovered with a finite duration (= the length of {@link latencies}). */
  closed_episodes: number;
  /** How many episodes were left open (a fall that never recovered — excluded from the mean). */
  open_episodes: number;
  /** The sum of {@link latencies} — the total recovered rounds below floor (an integer). */
  total_rounds: number;
  /** The mean closed duration `total_rounds / closed_episodes` (`null` when no episode recovered). */
  mean_duration: number | null;
  /** The longest single recovered episode (`null` when none recovered) — v28's per-front extreme, carried for contrast. */
  max_latency: number | null;
  /** The duration class. */
  class: DurationClass;
};

export type CoherenceDuration = {
  /** How many rounds (coherences) the duration spans. */
  rounds: number;
  fronts: CoherenceDurationFront[];
  /** Per-front tally by duration class. */
  class_counts: Record<DurationClass, number>;
  /** How many fall-to-recovery episodes closed with a recovery — equals v28's `recovered_count`. */
  total_closed_episodes: number;
  /** How many episodes were left open — equals v28's `open_count`. */
  total_open_episodes: number;
  /** The sum of every recovered episode's length across all fronts (the grand numerator). */
  total_rounds: number;
  /** The highest *mean* recovered duration across the deal (`null` when no front recovered). */
  max_mean: number | null;
  /** The front owning {@link max_mean} (earliest on a tie; `null` when none recovered). */
  longest_mean_dimension: string | null;
  /** Did any front's recovered exposures average at least two rounds? The gate-worthy verdict. */
  lingering: boolean;
  /** SHA-256 over the canonical per-front duration set — additive, apart from every other hash. */
  duration_hash: string;
};

function emptyClassCounts(): Record<DurationClass, number> {
  return { lingering: 0, brief: 0, open: 0, steady: 0, unstated: 0 };
}

/**
 * Walk N cross-document posture coherences — the same bundle at round 1, round 2, …,
 * round N — and report, per negotiation front, the **mean** number of rounds its binding
 * floor sat below the acceptable floor across its *recovered* exposures (`mean_duration`),
 * the deal's chronic lingerer (`longest_mean_dimension`), and whether any front's
 * recovered exposures *typically* span at least two rounds (`lingering`) — the central
 * tendency of the same fall-to-recovery episodes v28 pairs, not the single worst one
 * (v28's `max_latency`) nor the unrecovered gate (v28's `open_count`).
 *
 * Pure and deterministic: it delegates the episode pairing to
 * {@link computeCoherenceLatency} (reused unchanged — the join pattern v38 used for
 * v36+v37), so fronts are matched by dimension and pinned by `localeCompare`, the round
 * order is the caller's, the longest-mean pick uses integer cross-multiplication (never a
 * float comparison), and `duration_hash` is over the canonical per-front duration set, so
 * the same N coherences in the same order always yield identical bytes.
 *
 * Requires at least two rounds — a recovery duration is a *between-round* span; a single
 * round has no transition to pair a fall and a recovery over (v28 enforces this).
 */
export async function computeCoherenceDuration(
  rounds: readonly PostureCoherence[],
): Promise<CoherenceDuration> {
  const latency = await computeCoherenceLatency(rounds);

  const class_counts = emptyClassCounts();
  let total_closed_episodes = 0;
  let total_open_episodes = 0;
  let total_rounds = 0;
  // The longest mean, tracked as an exact integer ratio (total_rounds / closed_episodes)
  // to avoid any float comparison: the running best is `(bestTotal, bestCount)`.
  let bestTotal = 0;
  let bestCount = 0;
  let longest_mean_dimension: string | null = null;
  let lingering = false;

  const fronts: CoherenceDurationFront[] = latency.fronts.map((f) => {
    // Split v28's episodes into the recovered (a finite length to average) and the open
    // (an unbounded duration excluded from the mean — v28's gate owns it, §3).
    const latencies = f.episodes
      .filter((e) => e.latency !== null)
      .map((e) => e.latency as number)
      .sort((a, b) => a - b);
    const closed_episodes = latencies.length;
    const open_episodes = f.episodes.length - closed_episodes;
    const frontTotal = latencies.reduce((s, l) => s + l, 0);

    total_closed_episodes += closed_episodes;
    total_open_episodes += open_episodes;
    total_rounds += frontTotal;

    const mean_duration = closed_episodes === 0 ? null : frontTotal / closed_episodes;

    // The mean spans at least two rounds — `mean ≥ 2` ⟺ `total ≥ 2 × count`, integer-exact:
    // when this front falls, its recovered exposures typically outlast a single round.
    const isLingering = closed_episodes > 0 && frontTotal >= 2 * closed_episodes;

    const klass: DurationClass =
      f.latency === "unstated"
        ? "unstated"
        : closed_episodes === 0
          ? f.latency === "open"
            ? "open"
            : "steady"
          : isLingering
            ? "lingering"
            : "brief";
    if (klass === "lingering") lingering = true;
    class_counts[klass] += 1;

    // The longest mean across the deal: the first front (in localeCompare order) whose mean
    // strictly exceeds the running best wins. `total/count > bestTotal/bestCount` ⟺
    // `total × bestCount > bestTotal × count` (all non-negative integers), so the ranking is
    // exact — no float comparison, no platform drift.
    if (
      closed_episodes > 0 &&
      (longest_mean_dimension === null || frontTotal * bestCount > bestTotal * closed_episodes)
    ) {
      bestTotal = frontTotal;
      bestCount = closed_episodes;
      longest_mean_dimension = f.dimension;
    }

    return {
      dimension: f.dimension,
      floors: f.floors,
      latencies,
      closed_episodes,
      open_episodes,
      total_rounds: frontTotal,
      mean_duration,
      max_latency: f.max_latency,
      class: klass,
    };
  });

  const max_mean = longest_mean_dimension === null ? null : bestTotal / bestCount;

  const duration_hash = await sha256Hex(
    stableStringify({
      rounds: latency.rounds,
      fronts: fronts.map((f) => ({
        dimension: f.dimension,
        floors: f.floors,
        latencies: f.latencies,
        open_episodes: f.open_episodes,
        class: f.class,
      })),
    }),
  );

  return {
    rounds: latency.rounds,
    fronts,
    class_counts,
    total_closed_episodes,
    total_open_episodes,
    total_rounds,
    max_mean,
    longest_mean_dimension,
    lingering,
    duration_hash,
  };
}

/**
 * Did any front's *recovered* exposures average at least two rounds below the acceptable
 * floor — a front that, when it falls, *typically* does not recover the very next round?
 * The CI gate predicate — the *duration-magnitude* counterpart to v28's unrecovered gate
 * and v39's churn-rate gate. It needs no tuning: the bar is `mean ≥ 2 rounds`, the first
 * integer above the metric's structural minimum of one round (a fall and the immediately
 * following recovery), so it separates the front that *typically* lingers from the one
 * that *typically* recovers at once. **Distinct from v28's `exposureUnrecovered`**: a
 * front that always recovers but slowly (mean 3, no open episode) trips this gate and
 * clears v28's; a front that recovers promptly twice (mean 1) then falls and never returns
 * trips v28's gate and clears this one. **Distinct from a `max_latency` extreme**: a front
 * with episodes `[1, 1, 1, 5]` has the deal's slowest single recovery (5) yet a mean of 2,
 * while a front with `[1, 1, 1, 1, 5]` has the same slowest recovery yet a mean of 1.8 —
 * the extreme cannot tell the chronic lingerer from the front with one bad round.
 */
export function exposureLingers(duration: CoherenceDuration): boolean {
  return duration.lingering;
}

/**
 * Serialize a {@link CoherenceDuration} to a stable, pretty-printed JSON string. The key
 * order is fixed and the front order is already pinned by {@link computeCoherenceDuration},
 * so the same duration always yields identical bytes — the `duration_hash` it carries is
 * the canonical fingerprint, reproducible from `fronts` (over the integer episode lengths,
 * the derived `mean_duration` aside).
 */
export function buildCoherenceDurationJson(duration: CoherenceDuration): string {
  return JSON.stringify(
    {
      schema: "vaulytica.posture-duration.v1",
      duration_hash: duration.duration_hash,
      rounds: duration.rounds,
      class_counts: duration.class_counts,
      total_closed_episodes: duration.total_closed_episodes,
      total_open_episodes: duration.total_open_episodes,
      total_rounds: duration.total_rounds,
      max_mean: duration.max_mean,
      longest_mean_dimension: duration.longest_mean_dimension,
      lingering: duration.lingering,
      fronts: duration.fronts.map((f) => ({
        dimension: f.dimension,
        floors: f.floors,
        latencies: f.latencies,
        closed_episodes: f.closed_episodes,
        open_episodes: f.open_episodes,
        total_rounds: f.total_rounds,
        mean_duration: f.mean_duration,
        max_latency: f.max_latency,
        class: f.class,
      })),
    },
    null,
    2,
  );
}

/** Render a mean round count as a one-decimal string, e.g. `2` → `"2"`, `2.5` → `"2.5"`. */
function meanStr(mean: number): string {
  return Number.isInteger(mean) ? String(mean) : mean.toFixed(1);
}

/**
 * Render a {@link CoherenceDuration} as human-readable terminal lines: the chronic
 * lingerer (the front and its mean rounds below floor, or none when nothing recovered),
 * the class tally, then one line per front that recovered any episode (its class, its mean
 * and longest durations, and its floor path), `lingering` fronts first. A `steady`, `open`,
 * or `unstated` front is counted but never listed (§3 honesty — an open front carries no
 * finite duration). Lives beside its JSON sibling so the CLI renders the duration from one
 * definition.
 */
export function renderCoherenceDurationSummary(duration: CoherenceDuration): string {
  const cc = duration.class_counts;
  const n = duration.rounds;
  const lines = [
    `\nCoherence exposure duration across ${n} rounds (mean rounds below floor per recovered episode):`,
    duration.max_mean === null
      ? `  chronic lingerer: none — no front fell below the floor and recovered in-sequence.`
      : `  chronic lingerer: ${duration.longest_mean_dimension} — recovered exposures averaged ${meanStr(duration.max_mean)} round${duration.max_mean === 1 ? "" : "s"} below floor.`,
    `  fronts: ${cc.lingering} lingering (typically ≥ 2 rounds), ${cc.brief} brief; ${cc.open} open (never recovered), ${cc.steady} steady, ${cc.unstated} never stated.`,
  ];
  const recovered = duration.fronts.filter((f) => f.closed_episodes > 0);
  // Lingering fronts first (the heavier exposure), then any brief front; each group keeps
  // the localeCompare order the fronts already carry.
  for (const f of [
    ...recovered.filter((f) => f.class === "lingering"),
    ...recovered.filter((f) => f.class === "brief"),
  ]) {
    const path = f.floors.map((t) => t ?? "—").join(" → ");
    const mark = f.class === "lingering" ? "⚠" : "·";
    const openNote = f.open_episodes > 0 ? `, ${f.open_episodes} still open` : "";
    lines.push(
      `  ${mark} ${f.dimension}: ${f.class} — mean ${meanStr(f.mean_duration!)} of ${f.closed_episodes} recovered episode${f.closed_episodes === 1 ? "" : "s"} (longest ${f.max_latency})${openNote} (${path}).`,
    );
  }
  lines.push(`  duration_hash: ${duration.duration_hash}`);
  return lines.join("\n") + "\n";
}
