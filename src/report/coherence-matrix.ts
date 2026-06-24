/**
 * Cross-document negotiation-posture **exposure matrix** — the raw, un-reduced
 * *per-front × per-round* floor-state grid every other posture axis collapses
 * (spec-v44).
 *
 * Every `coherence-*` reading from v16 to v43 takes the same N-round archive and
 * *reduces* it to a scalar (or a small vector): v22 collapses each round (column)
 * to a below-floor **count**; v24 collapses each front (row) to a crossing
 * **count**; v28/v40 to a **latency** or a **mean**; v35/v42 to an **edge set** and
 * its transitive closure. Each is a lens — and each throws the rest of the grid
 * away. None of them emits the grid *itself*: the full two-dimensional object whose
 * cell `(front, round)` is that front's binding-floor standing in that round —
 * below the acceptable floor, at-or-above it, or unstated. A dashboard that wants to
 * render a posture **heatmap**, a spreadsheet that wants to pivot the deal's
 * exposure, an auditor who wants the substrate behind every scalar — all of them
 * want the grid, and no command produces it. That is a missing **shape**, not a
 * missing reduction: every prior axis is O(fronts) or O(rounds) scalars; the matrix
 * is the O(fronts × rounds) object they are all functions of.
 *
 * This module is that grid:
 *
 *  - v22 answers *for each round, how many fronts were below floor* — a per-round
 *    reduction (a column collapsed to a count).
 *  - v24 answers *for each front, how many times it crossed the floor* — a per-front
 *    reduction (a row collapsed to a count).
 *  - v44 (here) answers *what was every front's standing in every round* — the grid
 *    neither axis collapses, plus the one whole-grid verdict the shape makes
 *    natural: a **blackout** round, a column in which *every* stated front sits below
 *    the floor at once (the deal's worst possible cross-section — the moment no front
 *    held the line). It carries the per-front rows (the heatmap), the per-round
 *    column summaries (which round, if any, blacked out), and the whole-grid cell
 *    tally.
 *
 * It adds **no** posture math beyond reading the `below-acceptable` rung v10 defines
 * off the binding floors v12 derived — the same `weakest_tier` v22/v24 already read,
 * laid out as a grid rather than summed. The posture filter (spec-v10 §3), restated:
 *  - **Deterministic** — same N coherences in the same order → identical
 *    `matrix_hash`, on any machine. Rows (fronts) are pinned by `localeCompare(_,
 *    "en")` (the order every sibling pins fronts); columns keep the caller's round
 *    order; each cell is one of three string symbols. No float, no count, enters the
 *    fingerprint — the cells alone determine every derived summary.
 *  - **Honest about unstated data** — a front no document states in a round is
 *    `unstated` that round (not `below`): "not stated" is not a point on the
 *    ideal→floor axis, so silence is never a false exposure (the §3 contract that
 *    keeps `unstated` never-flagged in v20/v22). A round in which *no* front is even
 *    stated is never a blackout (a blackout needs at least one stated front, all of
 *    them below).
 *  - **Advisory** — the grid names where each front stood across the team's own
 *    floor in each round. It asserts no legal conclusion.
 *  - **Additive** — the matrix carries its own `matrix_hash`, namespaced apart from
 *    every `coherence_hash`, `movement_hash`, `trajectory_hash`,
 *    `shift_trajectory_hash`, `arc_hash`, `exposure_hash`, `persistence_hash`,
 *    `breadth_hash`, `recurrence_hash`, `volatility_hash`, `synchrony_hash`,
 *    `settling_hash`, `onset_hash`, `latency_hash`, `concurrency_hash`,
 *    `relapse_hash`, `tenure_hash`, `affinity_hash`, `recovery_affinity_hash`,
 *    `opposition_hash`, `precedence_hash`, `concession_hash`, `recovery_order_hash`,
 *    `weak_front_hash`, `cadence_hash`, `duration_hash`, `durability_hash`,
 *    `chain_hash`, and `recovery_chain_hash`, so computing it moves no golden.
 */

import type { NegotiationTier } from "../playbooks/custom-interpreter.js";
import { sha256Hex } from "../ingest/hash.js";
import { stableStringify } from "../engine/runner.js";
import type { PostureCoherence } from "./posture-coherence.js";

/** The team's acceptable floor — the one rung whose name means "below what we will accept." */
const BELOW_FLOOR: NegotiationTier = "below-acceptable";

/**
 * One front's binding-floor standing in one round — the value of a single grid cell:
 *  - `below`    — the binding floor was `below-acceptable` that round (the exposure);
 *  - `above`    — a front was stated and sat at-or-above the floor (`ideal` or
 *                 `acceptable` — the floor is binary, so the two clear rungs are one
 *                 cell, matching the family's binary-floor design);
 *  - `unstated` — no document stated the front that round (`unevaluable`, unranked —
 *                 §3: silence is never exposure).
 */
export type MatrixCell = "below" | "above" | "unstated";

/** One negotiation front's whole-sequence floor-state row — the heatmap row. */
export type CoherenceMatrixFront = {
  dimension: string;
  /** The front's standing at each round, in sequence order — the raw grid row. */
  cells: MatrixCell[];
  /** How many rounds this front sat below floor (a derived row tally, for context). */
  below_rounds: number;
  /** How many rounds this front was stated at all (`below` + `above`; the rest unstated). */
  stated_rounds: number;
};

/** One round's column summary — the deal-wide standing that round. */
export type CoherenceMatrixRound = {
  /** The 1-based round index, in sequence order. */
  round: number;
  /** How many fronts sat below floor this round. */
  below_fronts: number;
  /** How many fronts were stated this round (the denominator; the rest are unstated). */
  stated_fronts: number;
  /**
   * Is this a **blackout** round — at least one front stated and *every* stated front
   * below the floor at once? The whole-grid alarm: the deal's worst cross-section.
   */
  blackout: boolean;
};

export type CoherenceMatrix = {
  /** How many rounds (coherences) the grid spans — its column count. */
  rounds: number;
  /** Every front, pinned by `dimension` (`localeCompare`) — the grid's rows. */
  fronts: CoherenceMatrixFront[];
  /** The per-round column summaries, in sequence order. */
  per_round: CoherenceMatrixRound[];
  /** The whole-grid cell tally by state. */
  cell_counts: Record<MatrixCell, number>;
  /** The 1-based rounds that blacked out (every stated front below floor), in order. */
  blackout_rounds: number[];
  /** Did any round black out? The gate-worthy verdict. */
  has_blackout: boolean;
  /** SHA-256 over the canonical grid (per-front cells) — additive, apart from every other hash. */
  matrix_hash: string;
};

function emptyCellCounts(): Record<MatrixCell, number> {
  return { below: 0, above: 0, unstated: 0 };
}

/** Map a binding floor (`null` = unstated) to its grid cell — the only floor read this module does. */
function cellOf(tier: NegotiationTier | null): MatrixCell {
  if (tier === null) return "unstated";
  return tier === BELOW_FLOOR ? "below" : "above";
}

/**
 * Walk N cross-document posture coherences — the same bundle at round 1, round 2, …,
 * round N — and lay out the **full per-front × per-round floor-state grid**: each
 * cell is a front's binding-floor standing that round (`below` / `above` /
 * `unstated`). Unlike every other `coherence-*` reading, it does *not* reduce the
 * grid to a scalar — it emits the grid itself, plus the per-round column summaries
 * (which round, if any, blacked out — every stated front below floor at once) and
 * the whole-grid cell tally.
 *
 * Pure and deterministic: rows (fronts) are matched by dimension and pinned by
 * `localeCompare`, columns keep the caller's round order, every cell is one of three
 * fixed string symbols, and `matrix_hash` is over the canonical per-front cell rows,
 * so the same N coherences in the same order always yield identical bytes. The
 * per-round summaries, the cell tally, and the blackout list are all functions of the
 * cells, so they are derived (and omitted from the hash), never imported.
 *
 * Every coherence must have been computed against the **same** team positions (the
 * caller applies one active playbook to every document in every round); comparing
 * floors across different ladders is nonsense, the same way v13/v16 refuse a
 * cross-ladder diff. The CLI core ({@link computeCoherenceMatrixArtifacts}) enforces
 * this via the v15/v16 ladder guard before calling this.
 *
 * Requires at least two rounds — the matrix is the *whole-deal* grid; a single
 * round's floors are exactly what `analyze --posture` already reports as one column.
 */
export async function computeCoherenceMatrix(
  rounds: readonly PostureCoherence[],
): Promise<CoherenceMatrix> {
  if (rounds.length < 2) {
    throw new Error(`a matrix needs at least two rounds (got ${rounds.length})`);
  }

  const byDim = rounds.map((c) => new Map(c.dimensions.map((d) => [d.dimension, d])));
  const labels = Array.from(
    new Set(rounds.flatMap((c) => c.dimensions.map((d) => d.dimension))),
  ).sort((a, b) => a.localeCompare(b, "en"));

  const cell_counts = emptyCellCounts();

  const fronts: CoherenceMatrixFront[] = labels.map((dimension) => {
    const cells = byDim.map((m) => cellOf(m.get(dimension)?.weakest_tier ?? null));
    let below_rounds = 0;
    let stated_rounds = 0;
    for (const c of cells) {
      cell_counts[c] += 1;
      if (c === "below") below_rounds += 1;
      if (c !== "unstated") stated_rounds += 1;
    }
    return { dimension, cells, below_rounds, stated_rounds };
  });

  // Per-round column summaries. A blackout is a column with at least one stated front
  // and *every* stated front below floor — the deal's worst cross-section. A round in
  // which no front is even stated is never a blackout (§3: silence is not exposure).
  const per_round: CoherenceMatrixRound[] = rounds.map((_, i) => {
    let below_fronts = 0;
    let stated_fronts = 0;
    for (const f of fronts) {
      const c = f.cells[i]!;
      if (c === "below") below_fronts += 1;
      if (c !== "unstated") stated_fronts += 1;
    }
    return {
      round: i + 1,
      below_fronts,
      stated_fronts,
      blackout: stated_fronts >= 1 && below_fronts === stated_fronts,
    };
  });

  const blackout_rounds = per_round.filter((r) => r.blackout).map((r) => r.round);

  const matrix_hash = await sha256Hex(
    stableStringify({
      rounds: rounds.length,
      fronts: fronts.map((f) => ({ dimension: f.dimension, cells: f.cells })),
    }),
  );

  return {
    rounds: rounds.length,
    fronts,
    per_round,
    cell_counts,
    blackout_rounds,
    has_blackout: blackout_rounds.length > 0,
    matrix_hash,
  };
}

/**
 * Did any round **black out** — was there a round in which *every* stated front sat
 * below the acceptable floor at once? The CI gate predicate — the whole-grid verdict
 * the matrix shape makes natural, and the one no per-front or per-round *reduction*
 * poses. Unlike `exposureWidened` (v22: did the latest round have strictly more
 * fronts below floor than the first — a *trend* between two endpoint counts), this
 * fires on a single column reaching *full* width: the deal momentarily had no front
 * holding the line. The two are independent — a deal can black out in round 1 and
 * recover (not widened, but blacked out), and a deal can widen from one to three of
 * five fronts (widened, but never a full column). It needs no tuning — "every stated
 * front" is a structural all-quantifier, not a threshold knob. A consumer wanting the
 * per-round counts, or the worst partial column, reads `per_round` from the JSON.
 */
export function exposureBlackout(matrix: CoherenceMatrix): boolean {
  return matrix.has_blackout;
}

/**
 * Serialize a {@link CoherenceMatrix} to a stable, pretty-printed JSON string. The
 * key order is fixed and the row order is already pinned by
 * {@link computeCoherenceMatrix} (columns in the caller's round order), so the same
 * matrix always yields identical bytes — the `matrix_hash` it carries is the
 * canonical fingerprint, reproducible from `fronts` (the per-round summaries, cell
 * tally, and blackout list are fully determined by the cells, so they ride along for
 * a consumer's convenience but the hash covers the grid alone).
 */
export function buildCoherenceMatrixJson(matrix: CoherenceMatrix): string {
  return JSON.stringify(
    {
      schema: "vaulytica.posture-matrix.v1",
      matrix_hash: matrix.matrix_hash,
      rounds: matrix.rounds,
      cell_counts: matrix.cell_counts,
      blackout_rounds: matrix.blackout_rounds,
      has_blackout: matrix.has_blackout,
      per_round: matrix.per_round.map((r) => ({
        round: r.round,
        below_fronts: r.below_fronts,
        stated_fronts: r.stated_fronts,
        blackout: r.blackout,
      })),
      fronts: matrix.fronts.map((f) => ({
        dimension: f.dimension,
        cells: f.cells,
        below_rounds: f.below_rounds,
        stated_rounds: f.stated_rounds,
      })),
    },
    null,
    2,
  );
}

/** The heatmap glyph for a cell — `▓` below floor, `░` at-or-above, `·` unstated. */
const GLYPH: Record<MatrixCell, string> = { below: "▓", above: "░", unstated: "·" };

/**
 * Render a {@link CoherenceMatrix} as a human-readable terminal **heatmap**: a legend,
 * the blackout verdict (which rounds, if any, had every stated front below floor), a
 * grid with one row per front (the dimension label, padded, then one glyph per round)
 * and a header marking each round (`*` under a blackout column), and the whole-grid
 * cell tally. Lives beside its JSON sibling so the CLI renders the matrix from one
 * definition.
 */
export function renderCoherenceMatrixSummary(matrix: CoherenceMatrix): string {
  const n = matrix.rounds;
  const cc = matrix.cell_counts;
  const total = cc.below + cc.above + cc.unstated;
  const lines = [
    `\nCoherence exposure matrix across ${n} rounds × ${matrix.fronts.length} fronts (per-front × per-round floor state):`,
    `  legend: ${GLYPH.below} below floor   ${GLYPH.above} at-or-above floor   ${GLYPH.unstated} unstated`,
    matrix.has_blackout
      ? `  blackout (every stated front below floor): round${matrix.blackout_rounds.length === 1 ? "" : "s"} ${matrix.blackout_rounds.join(", ")}.`
      : `  blackout: none — no round had every stated front below floor at once.`,
  ];

  // The grid. Pad the dimension label column to the widest label, and each round
  // column to its header width so the glyphs line up under their round numbers.
  const labelWidth = Math.max(9, ...matrix.fronts.map((f) => f.dimension.length));
  const headers = matrix.per_round.map((r) => `r${r.round}`);
  const colWidth = headers.map((h) => h.length);
  const pad = (s: string, w: number) => s + " ".repeat(Math.max(0, w - s.length));

  lines.push(`  ${pad("", labelWidth)}  ${headers.map((h, i) => pad(h, colWidth[i]!)).join(" ")}`);
  // A marker row flagging blackout columns with `*` (a quiet space otherwise).
  lines.push(
    `  ${pad("", labelWidth)}  ${matrix.per_round.map((r, i) => pad(r.blackout ? "*" : "", colWidth[i]!)).join(" ")}`,
  );
  for (const f of matrix.fronts) {
    const row = f.cells.map((c, i) => pad(GLYPH[c], colWidth[i]!)).join(" ");
    lines.push(`  ${pad(f.dimension, labelWidth)}  ${row}`);
  }

  lines.push(
    `  cells: ${cc.below} below, ${cc.above} above, ${cc.unstated} unstated (of ${total}).`,
  );
  lines.push(`  matrix_hash: ${matrix.matrix_hash}`);
  return lines.join("\n") + "\n";
}
