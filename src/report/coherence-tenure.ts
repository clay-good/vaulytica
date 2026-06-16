/**
 * Cross-document negotiation-posture **exposure tenure** — per front, the *fraction*
 * of the rounds that *stated* it in which its binding floor sat below the acceptable
 * floor (`share`), the deal's heaviest-occupancy front (`max_share`), and whether any
 * front was below floor for a strict **majority** of its stated rounds (spec-v31).
 *
 * v21 ({@link computeCoherencePersistence}) reads the posture archive on the **current
 * standing** axis: per front, how many rounds it sat below floor (`rounds_below`, a raw
 * count against the *total* round span) and whether its *latest stated* floor is still
 * below acceptable (`open`/`resolved`). Its gate fires on the **endpoint** — a front
 * below floor *now*. But the endpoint throws away the one axis a deal lead asks
 * auditing the whole package: **across the rounds that actually put a front on the
 * table, how much of that span was it an unaccepted position — was it below floor more
 * often than not?** Two fronts v21 reports identically (both `resolved` — recovered, gate
 * clears) can be opposites on this axis:
 *
 * - The **brief dip.** Cap is stated in 5 rounds, below floor in round 2 only, then
 *   recovers and holds — below floor 1 of 5 stated rounds (a 20% tenure). `resolved`.
 * - The **chronic burden.** Cap is stated in 5 rounds, below floor in rounds 1–4, and
 *   recovers only at round 5 — below floor 4 of 5 stated rounds (an 80% tenure). Also
 *   `resolved` to v21 (it recovered by the close), yet it was an unacceptable position
 *   for the *majority* of the deal.
 *
 * That is a missing **axis**: the *occupancy* dimension of the same below-floor data —
 * not the per-episode count (v23), the per-episode below-duration (v28), nor the
 * endpoint standing (v21), but the **aggregate share** of a front's stated span spent
 * below floor. Where v21 divides `rounds_below` by the *total* round count and headlines
 * the endpoint, v31 divides by the front's **stated** rounds (the §3-honest denominator —
 * silence neither exposes a front nor dilutes its share) and headlines the **burden**.
 *
 * It adds **no** posture math beyond a per-front occupancy count over the
 * `below-acceptable` rung v10 defines, taken over the binding floors v12 derived and
 * v20/v21 already read. `total_below_rounds` equals v21's `rounds_below` summed across
 * fronts by construction. The posture filter (spec-v10 §3), restated:
 *  - **Deterministic** — same N coherences in the same order → identical `tenure_hash`,
 *    on any machine. Fronts are pinned by `localeCompare(_, "en")` (the same order the
 *    trajectory/exposure/persistence/latency functions use); the round order is the
 *    caller's. The heaviest-share pick is decided by *integer cross-multiplication*
 *    (`below × stated` of the two fronts), never a float comparison, so the ranking is
 *    exact and platform-independent.
 *  - **Honest about unstated data** — a front no document states in a round does not
 *    count toward its denominator *or* its numerator: silence is neither exposure nor a
 *    clean round (the §3 contract that keeps an unstated front `unstated`, never ranked,
 *    in v20/v21). The share is over the rounds that *stated* the front, so a front on
 *    the table twice and below floor both times reads 100% — it was an unaccepted
 *    position every time it was discussed — not 40% diluted by three rounds of silence.
 *  - **Advisory** — the report names what share of each front's stated span sat below the
 *    team's own floor. It asserts no legal conclusion.
 *  - **Additive** — the tenure carries its own `tenure_hash`, namespaced apart from
 *    every `coherence_hash`, `movement_hash`, `trajectory_hash`, `shift_trajectory_hash`,
 *    `arc_hash`, `exposure_hash`, `persistence_hash`, `breadth_hash`, `recurrence_hash`,
 *    `volatility_hash`, `synchrony_hash`, `settling_hash`, `onset_hash`, `latency_hash`,
 *    `concurrency_hash`, and `relapse_hash`, so computing it moves no golden.
 */

import type { NegotiationTier } from "../playbooks/custom-interpreter.js";
import { sha256Hex } from "../ingest/hash.js";
import { stableStringify } from "../engine/runner.js";
import type { PostureCoherence } from "./posture-coherence.js";

/** The team's acceptable floor — the one rung whose name means "below what we will accept." */
const BELOW_FLOOR: NegotiationTier = "below-acceptable";

/**
 * A front's below-floor occupancy class:
 *  - `majority` — below floor for a *strict majority* of its stated rounds
 *    (`below_rounds × 2 > stated_rounds`) — it was, on balance, an unaccepted position
 *    more often than not across the rounds that put it on the table;
 *  - `minority` — stated and below floor in ≥ 1 round, but not a strict majority
 *    (including an exact split, e.g. below 2 of 4);
 *  - `none` — stated, but never below floor;
 *  - `unstated` — no document ever stated the front (§3: silence is not exposure).
 */
export type TenureClass = "majority" | "minority" | "none" | "unstated";

/** One negotiation front's whole-sequence below-floor occupancy. */
export type CoherenceTenureFront = {
  dimension: string;
  /** The binding floor at each round, in sequence order (`null` = unstated that round). */
  floors: (NegotiationTier | null)[];
  /** How many rounds *stated* the front (the §3-honest denominator). */
  stated_rounds: number;
  /** How many of those stated rounds had a `below-acceptable` binding floor (the numerator). */
  below_rounds: number;
  /** The occupancy share `below_rounds / stated_rounds` (`null` when unstated). */
  share: number | null;
  /** The below-floor occupancy class. */
  tenure: TenureClass;
};

export type CoherenceTenure = {
  /** How many rounds (coherences) the tenure spans. */
  rounds: number;
  fronts: CoherenceTenureFront[];
  /** Per-front tally by occupancy class. */
  class_counts: Record<TenureClass, number>;
  /** Every front's below-floor rounds, summed — equals v21's `rounds_below` summed across fronts. */
  total_below_rounds: number;
  /** Every front's stated rounds, summed — the grand denominator. */
  total_stated_rounds: number;
  /** The heaviest occupancy across the deal — the largest `share` (`null` when no front was ever below floor). */
  max_share: number | null;
  /** The front owning {@link max_share} (earliest on a tie; `null` when none below floor). */
  heaviest_dimension: string | null;
  /** Was any front below floor for a strict majority of its stated rounds? The gate-worthy verdict. */
  majority: boolean;
  /** SHA-256 over the canonical per-front occupancy set — additive, apart from every other hash. */
  tenure_hash: string;
};

function emptyClassCounts(): Record<TenureClass, number> {
  return { majority: 0, minority: 0, none: 0, unstated: 0 };
}

/**
 * Walk N cross-document posture coherences — the same bundle at round 1, round 2, …,
 * round N — and report, per negotiation front, what *share* of the rounds that stated
 * it sat below the acceptable floor (`share`), the deal's heaviest such share
 * (`max_share`), and whether any front was below floor for a strict majority of its
 * stated rounds (`majority`), not merely whether it is below floor *now* (v21's endpoint)
 * or how many times it crossed (v24's count).
 *
 * Pure and deterministic: fronts are matched by dimension and pinned by `localeCompare`,
 * the round order is the caller's, the heaviest-share pick uses integer
 * cross-multiplication (never a float comparison), and `tenure_hash` is over the
 * canonical per-front occupancy set, so the same N coherences in the same order always
 * yield identical bytes.
 *
 * Every coherence must have been computed against the **same** team positions (the
 * caller applies one active playbook to every document in every round); comparing
 * floors across different ladders is nonsense, the same way v13/v16 refuse a
 * cross-ladder diff. The CLI core ({@link computeCoherenceTenureArtifacts}) enforces this
 * via the v15/v16 ladder guard before calling this.
 *
 * Requires at least two rounds — a tenure is a *whole-deal* occupancy; a single round's
 * floors are exactly what `analyze --posture` already reports.
 */
export async function computeCoherenceTenure(
  rounds: readonly PostureCoherence[],
): Promise<CoherenceTenure> {
  if (rounds.length < 2) {
    throw new Error(`a tenure needs at least two rounds (got ${rounds.length})`);
  }

  const byDim = rounds.map((c) => new Map(c.dimensions.map((d) => [d.dimension, d])));
  const labels = Array.from(
    new Set(rounds.flatMap((c) => c.dimensions.map((d) => d.dimension))),
  ).sort((a, b) => a.localeCompare(b, "en"));

  const class_counts = emptyClassCounts();
  let total_below_rounds = 0;
  let total_stated_rounds = 0;
  // The heaviest share, tracked as an exact integer ratio (below/stated) to avoid any
  // float comparison: the running best is `(bestBelow, bestStated)`.
  let bestBelow = 0;
  let bestStated = 0;
  let heaviest_dimension: string | null = null;
  let majority = false;

  const fronts: CoherenceTenureFront[] = labels.map((dimension) => {
    const floors = byDim.map((m) => m.get(dimension)?.weakest_tier ?? null);

    let stated_rounds = 0;
    let below_rounds = 0;
    for (const t of floors) {
      if (t === null) continue; // silence: neither denominator nor numerator (§3)
      stated_rounds += 1;
      if (t === BELOW_FLOOR) below_rounds += 1;
    }
    total_below_rounds += below_rounds;
    total_stated_rounds += stated_rounds;

    const share = stated_rounds === 0 ? null : below_rounds / stated_rounds;

    // Strict majority over the *stated* span (cross-multiplied to stay integer-exact).
    const isMajority = below_rounds * 2 > stated_rounds;

    const tenure: TenureClass =
      stated_rounds === 0
        ? "unstated"
        : below_rounds === 0
          ? "none"
          : isMajority
            ? "majority"
            : "minority";
    if (tenure === "majority") majority = true;
    class_counts[tenure] += 1;

    // The heaviest share across the deal: the first front (in localeCompare order) whose
    // share strictly exceeds the running best wins. `below/stated > bestBelow/bestStated`
    // ⟺ `below × bestStated > bestBelow × stated` (all non-negative integers), so the
    // ranking is exact — no float comparison, no platform drift.
    if (
      below_rounds > 0 &&
      (heaviest_dimension === null || below_rounds * bestStated > bestBelow * stated_rounds)
    ) {
      bestBelow = below_rounds;
      bestStated = stated_rounds;
      heaviest_dimension = dimension;
    }

    return { dimension, floors, stated_rounds, below_rounds, share, tenure };
  });

  const max_share = heaviest_dimension === null ? null : bestBelow / bestStated;

  const tenure_hash = await sha256Hex(
    stableStringify({
      rounds: rounds.length,
      fronts: fronts.map((f) => ({
        dimension: f.dimension,
        floors: f.floors,
        stated_rounds: f.stated_rounds,
        below_rounds: f.below_rounds,
        tenure: f.tenure,
      })),
    }),
  );

  return {
    rounds: rounds.length,
    fronts,
    class_counts,
    total_below_rounds,
    total_stated_rounds,
    max_share,
    heaviest_dimension,
    majority,
    tenure_hash,
  };
}

/**
 * Was any front below the team's acceptable floor for a strict **majority** of its
 * stated rounds — an unaccepted position more often than not across the rounds that put
 * it on the table? The CI gate predicate — the *occupancy* counterpart to v21's
 * *current-standing* gate. Unlike `exposureOpen` (a front below floor at its *latest*
 * stated round — including a fresh, late dip in 1 of many rounds), this fires on the
 * *aggregate burden*: a front below floor for more than half the span it was discussed,
 * **even if it recovered by the close**. It needs no tuning — a strict majority is the
 * one occupancy boundary whose meaning ("below floor more often than not") needs no
 * threshold knob. A front below floor for exactly half its stated rounds (or fewer)
 * clears it; a consumer wanting a different bar reads `share` and `max_share` from the
 * JSON. **Distinct from v21's `exposureOpen`**: a front below floor in only its final
 * round is `open` to v21 (gate trips) but a minority to v31 (gate clears); a front below
 * floor for rounds 1–4 of 5 that recovers at round 5 is `resolved` to v21 (gate clears)
 * but a majority to v31 (gate trips).
 */
export function exposureMajorityBelow(tenure: CoherenceTenure): boolean {
  return tenure.majority;
}

/**
 * Serialize a {@link CoherenceTenure} to a stable, pretty-printed JSON string. The key
 * order is fixed and the front order is already pinned by {@link computeCoherenceTenure},
 * so the same tenure always yields identical bytes — the `tenure_hash` it carries is the
 * canonical fingerprint, reproducible from `fronts` (over the integer occupancy, the
 * derived `share` aside).
 */
export function buildCoherenceTenureJson(tenure: CoherenceTenure): string {
  return JSON.stringify(
    {
      schema: "vaulytica.posture-tenure.v1",
      tenure_hash: tenure.tenure_hash,
      rounds: tenure.rounds,
      class_counts: tenure.class_counts,
      total_below_rounds: tenure.total_below_rounds,
      total_stated_rounds: tenure.total_stated_rounds,
      max_share: tenure.max_share,
      heaviest_dimension: tenure.heaviest_dimension,
      majority: tenure.majority,
      fronts: tenure.fronts.map((f) => ({
        dimension: f.dimension,
        floors: f.floors,
        stated_rounds: f.stated_rounds,
        below_rounds: f.below_rounds,
        share: f.share,
        tenure: f.tenure,
      })),
    },
    null,
    2,
  );
}

/** Render an occupancy share (0–1) as a whole-percent string, e.g. `0.8` → `"80%"`. */
function pct(share: number): string {
  return `${Math.round(share * 100)}%`;
}

/**
 * Render a {@link CoherenceTenure} as human-readable terminal lines: the heaviest
 * occupancy (the front and the share of its stated span below floor, or none-below when
 * no front was ever below floor), the class tally, then one line per front that was below
 * floor in any round (its class, its share, and its floor path), `majority` fronts first.
 * A `none` or `unstated` front is counted but never listed (§3 honesty). Lives beside its
 * JSON sibling so the CLI renders the tenure from one definition.
 */
export function renderCoherenceTenureSummary(tenure: CoherenceTenure): string {
  const cc = tenure.class_counts;
  const n = tenure.rounds;
  const lines = [
    `\nCoherence exposure tenure across ${n} rounds (share of each front's stated span below floor):`,
    tenure.max_share === null
      ? `  heaviest occupancy: none — no front was ever below the floor in-sequence.`
      : `  heaviest occupancy: ${tenure.heaviest_dimension} — below floor ${pct(tenure.max_share)} of its stated rounds.`,
    `  fronts: ${cc.majority} majority (below floor most of their stated span), ${cc.minority} minority; ${cc.none} never below floor, ${cc.unstated} never stated.`,
  ];
  const exposed = tenure.fronts.filter((f) => f.tenure === "majority" || f.tenure === "minority");
  // Majority fronts first (the heavier burden), then minority; each group keeps the
  // localeCompare order the fronts already carry.
  for (const f of [
    ...exposed.filter((f) => f.tenure === "majority"),
    ...exposed.filter((f) => f.tenure === "minority"),
  ]) {
    const path = f.floors.map((t) => t ?? "—").join(" → ");
    const mark = f.tenure === "majority" ? "⚠" : "·";
    lines.push(
      `  ${mark} ${f.dimension}: ${f.tenure} — below floor ${f.below_rounds} of ${f.stated_rounds} stated round${f.stated_rounds === 1 ? "" : "s"} (${pct(f.share!)}) (${path}).`,
    );
  }
  lines.push(`  tenure_hash: ${tenure.tenure_hash}`);
  return lines.join("\n") + "\n";
}
