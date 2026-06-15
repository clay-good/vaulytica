/**
 * Cross-document negotiation-posture **exposure recurrence** — the per-front count
 * of *separate* below-floor episodes across the whole deal (spec-v23).
 *
 * v21 ({@link computeCoherencePersistence}) reads the posture archive on the
 * **duration** axis: per front, how many rounds it sat below the acceptable floor
 * (`rounds_below`) and whether its latest stated floor is still below (its current
 * standing). But `rounds_below` is a **sum** — it adds every below-floor round and
 * forgets their *shape*. A front whose binding floor reads `below → below → below`
 * (one steady descent) and a front that reads `below → acceptable → below` (it
 * fell, **recovered**, and fell **again**) both report `rounds_below = 2` and
 * `persistence = open`: the same duration, the same standing, the same gate. Yet
 * the second is a concession the team won back and then lost — churn the first does
 * not have. v21 cannot see it, because it sums the floor path into one number; v17
 * cannot (its net first-vs-last is `unchanged`); v20 cannot (its worst point is the
 * same); v22 cannot (its per-round count is blind to *which* front recurred).
 *
 * This module is the orthogonal **episode-count** axis the duration sum throws away:
 *
 *  - v17 answers *which way did the floor move* — up, down, or whipsaw.
 *  - v20 answers *how low did the floor ever get* — the worst rung reached.
 *  - v21 answers *how long was it below floor, and is it still below floor now* —
 *    the total count of below-floor rounds and the current standing.
 *  - v23 (here) answers *how many separate times did it fall below floor* — the
 *    count of maximal contiguous below-floor **episodes** (`below_runs`): one
 *    descent is one episode; a recover-then-relapse is two; an oscillating front is
 *    three or more. A front that recovered and relapsed is `recurring` (gate trips);
 *    a front that fell once is `single` (gate clears).
 *
 * It adds **no** posture math beyond a run-length scan for the `below-acceptable`
 * rung v10 defines, over the binding floors v12 derived and v21 already reads. The
 * posture filter (spec-v10 §3), restated:
 *  - **Deterministic** — same N coherences in the same order → identical
 *    `recurrence_hash`, on any machine. Fronts are pinned by `localeCompare(_,
 *    "en")` (the same order the trajectory/exposure/persistence functions use); the
 *    round order is the caller's.
 *  - **Honest about unstated data** — a front no document states in *any* round is
 *    `unstated`, never `recurring`/`single`/`none`. Within a front's path, an
 *    unstated round does **not** end a below-floor episode: silence is not a
 *    recovery (the §3 contract that keeps `unstated` never-flagged in v20 and
 *    current standing reading the latest *stated* round in v21). Only a *stated*
 *    at-or-above-floor round splits an episode.
 *  - **Advisory** — the report names how many separate times each front sat below
 *    the team's own floor. It asserts no legal conclusion.
 *  - **Additive** — the recurrence carries its own `recurrence_hash`, namespaced
 *    apart from every `coherence_hash`, `movement_hash`, `trajectory_hash`,
 *    `shift_trajectory_hash`, `arc_hash`, `exposure_hash`, `persistence_hash`, and
 *    `breadth_hash`, so computing it moves no golden.
 */

import type { NegotiationTier } from "../playbooks/custom-interpreter.js";
import { sha256Hex } from "../ingest/hash.js";
import { stableStringify } from "../engine/runner.js";
import type { PostureCoherence } from "./posture-coherence.js";

/** The team's acceptable floor — the one rung whose name means "below what we will accept." */
const BELOW_FLOOR: NegotiationTier = "below-acceptable";

/**
 * A front's below-floor episode class:
 *  - `recurring` — it fell below floor in **two or more** separate episodes (it
 *    recovered and relapsed at least once);
 *  - `single` — it fell below floor in exactly one episode;
 *  - `none` — stated, but never below floor;
 *  - `unstated` — no document ever stated the front (§3: silence is not exposure).
 */
export type RecurrenceClass = "recurring" | "single" | "none" | "unstated";

/** A single below-floor episode: a maximal contiguous below-floor stretch's round range. */
export type RecurrenceEpisode = {
  /** The 1-based round the episode began (the first below-floor round of the run). */
  first_round: number;
  /** The 1-based round the episode ended (the last below-floor round before a stated recovery / the sequence end). */
  last_round: number;
};

/** One negotiation front's whole-sequence below-floor episode structure. */
export type CoherenceRecurrenceFront = {
  dimension: string;
  /** The binding floor at each round, in sequence order (`null` = unstated that round). */
  floors: (NegotiationTier | null)[];
  /** How many rounds stated a `below-acceptable` binding floor (the v21 sum, for context). */
  rounds_below: number;
  /** How many separate below-floor episodes the front had (the verdict). */
  below_runs: number;
  /** Each episode's 1-based round range, in order. */
  episodes: RecurrenceEpisode[];
  /** The below-floor episode class. */
  recurrence: RecurrenceClass;
};

export type CoherenceRecurrence = {
  /** How many rounds (coherences) the recurrence spans. */
  rounds: number;
  fronts: CoherenceRecurrenceFront[];
  /** Per-front tally by recurrence class. */
  class_counts: Record<RecurrenceClass, number>;
  /** How many fronts fell below floor in two or more separate episodes (the gate-worthy count). */
  recurring_count: number;
  /** The front with the most below-floor episodes (earliest on a tie; `null` when none ever was). */
  most_recurrent_dimension: string | null;
  /** The episode count at {@link most_recurrent_dimension} (0 when no front was ever below floor). */
  max_runs: number;
  /** SHA-256 over the canonical recurrence set — additive, apart from every other hash. */
  recurrence_hash: string;
};

function emptyClassCounts(): Record<RecurrenceClass, number> {
  return { recurring: 0, single: 0, none: 0, unstated: 0 };
}

/**
 * Scan one front's binding-floor path for its maximal contiguous below-floor
 * episodes. A *stated* at-or-above-floor round (a real recovery) ends an episode;
 * an unstated round (`null`) does **not** end it — silence after an exposure keeps
 * the last known standing (§3), so `below → null → below` is one episode and only
 * `below → acceptable → below` is two. Returns the episodes (each a 1-based round
 * range) and whether any round was ever stated.
 */
function scanEpisodes(floors: (NegotiationTier | null)[]): {
  episodes: RecurrenceEpisode[];
  stated: boolean;
} {
  const episodes: RecurrenceEpisode[] = [];
  let stated = false;
  let start: number | null = null; // 1-based start of the open episode, if any
  let last = 0; // 1-based last below-floor round of the open episode

  floors.forEach((t, i) => {
    if (t === null) return; // silence: neither extends nor ends an episode (§3)
    stated = true;
    if (t === BELOW_FLOOR) {
      if (start === null) start = i + 1;
      last = i + 1;
    } else if (start !== null) {
      // a stated recovery closes the open episode
      episodes.push({ first_round: start, last_round: last });
      start = null;
    }
  });
  if (start !== null) episodes.push({ first_round: start, last_round: last });

  return { episodes, stated };
}

/**
 * Walk N cross-document posture coherences — the same bundle at round 1, round
 * 2, …, round N — and report, per negotiation front, how many *separate* times it
 * fell below the acceptable floor (its episode count), not merely how many rounds
 * it was down in total (v21's sum).
 *
 * Pure and deterministic: fronts are matched by dimension and pinned by
 * `localeCompare`, the round order is the caller's, and `recurrence_hash` is over
 * the canonical per-front set, so the same N coherences in the same order always
 * yield identical bytes.
 *
 * Every coherence must have been computed against the **same** team positions (the
 * caller applies one active playbook to every document in every round); comparing
 * floors across different ladders is nonsense, the same way v13/v16 refuse a
 * cross-ladder diff. The CLI core ({@link computeCoherenceRecurrenceArtifacts})
 * enforces this via the v15/v16 ladder guard before calling this.
 *
 * Requires at least two rounds — recurrence is the *whole-deal* episode structure;
 * a single round's floor is exactly what `analyze --posture` already reports.
 */
export async function computeCoherenceRecurrence(
  rounds: readonly PostureCoherence[],
): Promise<CoherenceRecurrence> {
  if (rounds.length < 2) {
    throw new Error(`a recurrence needs at least two rounds (got ${rounds.length})`);
  }

  const byDim = rounds.map((c) => new Map(c.dimensions.map((d) => [d.dimension, d])));
  const labels = Array.from(
    new Set(rounds.flatMap((c) => c.dimensions.map((d) => d.dimension))),
  ).sort((a, b) => a.localeCompare(b, "en"));

  const class_counts = emptyClassCounts();
  let recurring_count = 0;
  let most_recurrent_dimension: string | null = null;
  let max_runs = 0;

  const fronts: CoherenceRecurrenceFront[] = labels.map((dimension) => {
    const floors = byDim.map((m) => m.get(dimension)?.weakest_tier ?? null);
    const { episodes, stated } = scanEpisodes(floors);
    const below_runs = episodes.length;
    const rounds_below = floors.filter((t) => t === BELOW_FLOOR).length;

    const recurrence: RecurrenceClass = !stated
      ? "unstated"
      : below_runs >= 2
        ? "recurring"
        : below_runs === 1
          ? "single"
          : "none";

    if (recurrence === "recurring") recurring_count += 1;
    class_counts[recurrence] += 1;
    // The most recurrent front is the one with the most episodes; the first such
    // front wins a tie (labels are already localeCompare-sorted, so > keeps the earliest).
    if (below_runs > max_runs) {
      max_runs = below_runs;
      most_recurrent_dimension = dimension;
    }

    return { dimension, floors, rounds_below, below_runs, episodes, recurrence };
  });

  const recurrence_hash = await sha256Hex(
    stableStringify({
      rounds: rounds.length,
      fronts: fronts.map((f) => ({
        dimension: f.dimension,
        floors: f.floors,
        rounds_below: f.rounds_below,
        below_runs: f.below_runs,
        episodes: f.episodes,
        recurrence: f.recurrence,
      })),
    }),
  );

  return {
    rounds: rounds.length,
    fronts,
    class_counts,
    recurring_count,
    most_recurrent_dimension,
    max_runs,
    recurrence_hash,
  };
}

/**
 * Did any front fall below the team's acceptable floor in *two or more* separate
 * episodes — did it recover and relapse? The CI gate predicate — the *churn*
 * counterpart to v21's current-standing gate and v20's ever gate. Unlike
 * `exposureBreached` (any front ever below floor) and `exposureOpen` (any front
 * still below floor now), this fires on a front that went below floor, recovered,
 * and went below floor *again*, even if its latest stated floor has since recovered.
 * It needs no tuning — two episodes is the threshold that *means* recurrence. A
 * consumer wanting a higher episode count reads `max_runs` instead.
 */
export function exposureRecurred(recurrence: CoherenceRecurrence): boolean {
  return recurrence.recurring_count > 0;
}

/**
 * Serialize a {@link CoherenceRecurrence} to a stable, pretty-printed JSON string.
 * The key order is fixed and the front order is already pinned by
 * {@link computeCoherenceRecurrence}, so the same recurrence always yields
 * identical bytes — the `recurrence_hash` it carries is the canonical fingerprint,
 * reproducible from `fronts`.
 */
export function buildCoherenceRecurrenceJson(recurrence: CoherenceRecurrence): string {
  return JSON.stringify(
    {
      schema: "vaulytica.posture-recurrence.v1",
      recurrence_hash: recurrence.recurrence_hash,
      rounds: recurrence.rounds,
      class_counts: recurrence.class_counts,
      recurring_count: recurrence.recurring_count,
      most_recurrent_dimension: recurrence.most_recurrent_dimension,
      max_runs: recurrence.max_runs,
      fronts: recurrence.fronts.map((f) => ({
        dimension: f.dimension,
        floors: f.floors,
        rounds_below: f.rounds_below,
        below_runs: f.below_runs,
        episodes: f.episodes,
        recurrence: f.recurrence,
      })),
    },
    null,
    2,
  );
}

/** Format a front's episode round ranges as a human-readable list (e.g. "round 1, rounds 3–4"). */
function renderEpisodes(episodes: RecurrenceEpisode[]): string {
  return episodes
    .map((e) =>
      e.first_round === e.last_round
        ? `round ${e.first_round}`
        : `rounds ${e.first_round}–${e.last_round}`,
    )
    .join(", ");
}

/**
 * Render a {@link CoherenceRecurrence} as human-readable terminal lines: the class
 * tally and the recurring-front count, then one line per **recurring** front
 * (showing its episode count, the episode round ranges, and the floor path), then
 * one line per **single** front (one episode — below floor, but no relapse). A
 * `none` or `unstated` front is counted but never listed (§3 honesty). Lives beside
 * its JSON sibling so the CLI renders the recurrence from one definition.
 */
export function renderCoherenceRecurrenceSummary(recurrence: CoherenceRecurrence): string {
  const cc = recurrence.class_counts;
  const n = recurrence.rounds;
  const lines = [
    `\nCoherence exposure recurrence across ${n} rounds (separate below-floor episodes per front):`,
    `  ${cc.recurring} recurring (recovered & relapsed), ${cc.single} single episode, ${cc.none} never below floor, ${cc.unstated} never stated.`,
    `  recurring fronts (fell below floor in ≥2 separate episodes): ${recurrence.recurring_count}.`,
  ];
  for (const f of recurrence.fronts) {
    if (f.recurrence !== "recurring") continue;
    const path = f.floors.map((t) => t ?? "—").join(" → ");
    lines.push(
      `  ⚠ ${f.dimension}: recurring — below floor in ${f.below_runs} separate episodes (${renderEpisodes(f.episodes)}), over ${f.rounds_below} of ${n} rounds (${path}).`,
    );
  }
  for (const f of recurrence.fronts) {
    if (f.recurrence !== "single") continue;
    const path = f.floors.map((t) => t ?? "—").join(" → ");
    lines.push(
      `  · ${f.dimension}: single episode — below floor ${renderEpisodes(f.episodes)} (${path}).`,
    );
  }
  lines.push(`  recurrence_hash: ${recurrence.recurrence_hash}`);
  return lines.join("\n") + "\n";
}
