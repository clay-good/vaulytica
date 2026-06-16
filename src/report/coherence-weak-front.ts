/**
 * Cross-document negotiation-posture **persistent weak front** — the per-front *join* of v36's
 * concession order and v37's recovery order. v36 ({@link computeCoherenceConcession}) names, per
 * unordered pair, the front that *concedes* (falls below the acceptable floor) **first**; v37
 * ({@link computeCoherenceRecoveryOrder}) names the front that *recovers* (climbs back at-or-above the
 * floor) **last** — the laggard left exposed longest. Each is a directional half-truth, and each spec
 * named the same prize the other half could not name alone: a front that **concedes first _and_
 * recovers last** is the deal's **persistent weak point** — exposed coming and going — while a front
 * that concedes first but recovers *first* is merely *volatile*. v38 is the per-front reduction that
 * names it (spec-v38).
 *
 * This is the family's **first per-front synthesis**. Every axis v32–v37 is *pairwise* (an unordered
 * pair is its primary object); v38's primary object is a **front**. It introduces no new fall, recovery,
 * crossing, or ordering — it reads only the `leading` edges v36/v37 already classify, and asks, per
 * front: is it the weak side (the `first_conceder`) of a `leading` concession pair **and** the weak side
 * (the `last_recoverer`) of a `leading` recovery-order pair?
 *
 * - The **persistent weak front.** Term concedes the floor before Cap (v36 names the `(Cap, Term)` pair
 *   `leading` with `first_conceder` = Term) _and_ Term recovers above the floor after Mmm (v37 names the
 *   `(Mmm, Term)` pair `leading` with `last_recoverer` = Term). Term is exposed on **both** directional
 *   axes — given ground early, restored late. Only the join calls it persistently weak.
 * - The **volatile front (cleared).** Fee concedes first against Cap (v36) but recovers *first* against
 *   everyone (v37) — it gives ground early but is restored early. It is volatile, not weak; the join
 *   clears it (`recovers_last_against` is empty), where reading v36 alone would flag it.
 *
 * The posture filter (spec-v10 §3), restated:
 *  - **Deterministic** — same N coherences in the same order → identical `weak_front_hash`, on any
 *    machine. The reduction reads v36/v37's `leading` pairs (themselves `localeCompare`-pinned and
 *    integer-decided), accumulates per-front partner lists sorted by `localeCompare(_, "en")`, and picks
 *    the most-exposed front by *integer* leading-edge count (earliest label on a tie), never a float
 *    compare. No float threshold enters the verdict.
 *  - **Honest about unstated data** — the join inherits v36/v37's §3 contract exactly: silence is
 *    neither a fall nor a recovery. A front weak on *neither* axis (no `leading` edge against it in
 *    either half) carries no signal and is omitted from `fronts[]`; a front weak on only one axis is
 *    reported (`conceding` or `lagging`) but never gated.
 *  - **Advisory** — the report names which front the counterparty both gives ground on first and
 *    restores last across the team's own floor. It asserts no legal conclusion.
 *  - **Additive** — the report carries its own `weak_front_hash`, namespaced apart from every
 *    `coherence_hash`, `movement_hash`, `trajectory_hash`, `shift_trajectory_hash`, `arc_hash`,
 *    `exposure_hash`, `persistence_hash`, `breadth_hash`, `recurrence_hash`, `volatility_hash`,
 *    `synchrony_hash`, `settling_hash`, `onset_hash`, `latency_hash`, `concurrency_hash`,
 *    `relapse_hash`, `tenure_hash`, `affinity_hash`, `recovery_affinity_hash`, `opposition_hash`,
 *    `precedence_hash`, `concession_hash`, and `recovery_order_hash`, so computing it moves no golden.
 */

import { sha256Hex } from "../ingest/hash.js";
import { stableStringify } from "../engine/runner.js";
import type { PostureCoherence } from "./posture-coherence.js";
import { computeCoherenceConcession } from "./coherence-concession.js";
import { computeCoherenceRecoveryOrder } from "./coherence-recovery-order.js";

/**
 * One front's exposure class across the deal:
 *  - `persistent-weak` — a strict-majority **first-conceder** against ≥ 1 partner (v36 `leading`) _and_
 *    a strict-majority **last-recoverer** against ≥ 1 partner (v37 `leading`): exposed on both
 *    directional axes — gives ground early, is restored late — the gate-worthy class;
 *  - `conceding` — concedes first against ≥ 1 partner but is never a consistent last-recoverer: gives
 *    ground early but is restored on time (a *volatile* front, a directional half-signal);
 *  - `lagging` — recovers last against ≥ 1 partner but never concedes first: restored late but does not
 *    give ground early.
 *
 * A front that is the weak side of *neither* ordering carries no signal and is omitted from the report.
 */
export type WeakFrontClass = "persistent-weak" | "conceding" | "lagging";

/** One front's whole-sequence exposure relation, joining v36's concession order and v37's recovery order. */
export type CoherenceWeakFrontEntry = {
  /** The front. */
  dimension: string;
  /** The partners this front is the v36 `first_conceder` against (it concedes the floor first), sorted. */
  concedes_first_against: string[];
  /** The partners this front is the v37 `last_recoverer` against (it is restored last), sorted. */
  recovers_last_against: string[];
  /** The partners where it both concedes first *and* recovers last — the sharpest same-partner evidence, sorted. */
  confirmed_against: string[];
  /** The exposure class. */
  class: WeakFrontClass;
};

export type CoherenceWeakFront = {
  /** How many rounds (coherences) the report spans. */
  rounds: number;
  /** The fronts with a weak signal on either axis, pinned by `dimension` (`localeCompare`). */
  fronts: CoherenceWeakFrontEntry[];
  /** Per-front tally by exposure class. */
  class_counts: Record<WeakFrontClass, number>;
  /** Every `persistent-weak` front's dimension, pinned — the headline. */
  weak_fronts: string[];
  /** The persistent-weak front with the most total leading edges against it (earliest label on a tie; `null` when none). */
  most_exposed_front: string | null;
  /** Was any front both a strict-majority first-conceder and a strict-majority last-recoverer? The gate-worthy verdict. */
  has_persistent_weak_front: boolean;
  /** SHA-256 over the canonical per-front set — additive, apart from every other hash. */
  weak_front_hash: string;
};

function emptyClassCounts(): Record<WeakFrontClass, number> {
  return { "persistent-weak": 0, conceding: 0, lagging: 0 };
}

/**
 * Walk N cross-document posture coherences — the same bundle at round 1, …, round N — and report, *per
 * front*, whether it is the deal's **persistent weak point**: a front the counterparty both gives ground
 * on **first** (a v36 `first_conceder`) and restores **last** (a v37 `last_recoverer`). For each front
 * with a weak signal on either axis: the partners it `concedes_first_against`, the partners it
 * `recovers_last_against`, the `confirmed_against` (the same-partner intersection), and its `class`
 * (`persistent-weak` / `conceding` / `lagging`); plus the deal's `most_exposed_front`, the `weak_fronts`
 * list, and `has_persistent_weak_front` (the gate).
 *
 * Pure and deterministic: it computes v36's concession and v37's recovery order over the same rounds
 * (both pure, both `localeCompare`-pinned, both decided by integer cross-multiplication), reads only
 * their `leading` pairs, accumulates per-front partner lists, enumerates fronts in pinned order, and
 * picks the most-exposed front by integer leading-edge count (never a float comparison). The
 * `weak_front_hash` is over the canonical per-front set, so the same N coherences in the same order
 * always yield identical bytes.
 *
 * Requires at least two rounds — delegated to v36/v37, which both require it (a fall/recovery is a
 * between-round event).
 */
export async function computeCoherenceWeakFront(
  rounds: readonly PostureCoherence[],
): Promise<CoherenceWeakFront> {
  // v36 and v37 both require ≥ 2 rounds and enforce it; calling them first surfaces the same error.
  const [concession, recoveryOrder] = await Promise.all([
    computeCoherenceConcession(rounds),
    computeCoherenceRecoveryOrder(rounds),
  ]);

  // Per front, the partners it gives ground on first (v36 `leading` pairs where it is the
  // `first_conceder`) and the partners it is restored last against (v37 `leading` pairs where it is the
  // `last_recoverer`). A `leading` pair always has a non-null leader/laggard.
  const concedesFirstAgainst = new Map<string, Set<string>>();
  for (const p of concession.pairs) {
    if (p.class !== "leading" || p.first_conceder === null) continue;
    const front = p.first_conceder;
    const partner = front === p.dimension_a ? p.dimension_b : p.dimension_a;
    (concedesFirstAgainst.get(front) ?? setInto(concedesFirstAgainst, front)).add(partner);
  }

  const recoversLastAgainst = new Map<string, Set<string>>();
  for (const p of recoveryOrder.pairs) {
    if (p.class !== "leading" || p.last_recoverer === null) continue;
    const front = p.last_recoverer;
    const partner = front === p.dimension_a ? p.dimension_b : p.dimension_a;
    (recoversLastAgainst.get(front) ?? setInto(recoversLastAgainst, front)).add(partner);
  }

  const labels = Array.from(
    new Set([...concedesFirstAgainst.keys(), ...recoversLastAgainst.keys()]),
  ).sort((a, b) => a.localeCompare(b, "en"));

  const class_counts = emptyClassCounts();
  const weak_fronts: string[] = [];
  let most_exposed_front: string | null = null;
  let bestEdges = 0;

  const fronts: CoherenceWeakFrontEntry[] = [];
  for (const dimension of labels) {
    const concedes = sortedLabels(concedesFirstAgainst.get(dimension));
    const recovers = sortedLabels(recoversLastAgainst.get(dimension));
    const concedesSet = new Set(concedes);
    const confirmed = recovers.filter((p) => concedesSet.has(p)); // already sorted (recovers is)

    const klass: WeakFrontClass =
      concedes.length > 0 && recovers.length > 0
        ? "persistent-weak"
        : concedes.length > 0
          ? "conceding"
          : "lagging";
    class_counts[klass] += 1;

    if (klass === "persistent-weak") {
      weak_fronts.push(dimension);
      // The most-exposed front: the persistent-weak front with the most total leading edges against it.
      // Integer comparison only; the first front (in label order) with strictly more edges wins, so the
      // tie-break is the earliest label.
      const edges = concedes.length + recovers.length;
      if (most_exposed_front === null || edges > bestEdges) {
        bestEdges = edges;
        most_exposed_front = dimension;
      }
    }

    fronts.push({
      dimension,
      concedes_first_against: concedes,
      recovers_last_against: recovers,
      confirmed_against: confirmed,
      class: klass,
    });
  }

  const has_persistent_weak_front = weak_fronts.length > 0;

  const weak_front_hash = await sha256Hex(
    stableStringify({
      rounds: rounds.length,
      fronts: fronts.map((f) => ({
        dimension: f.dimension,
        concedes_first_against: f.concedes_first_against,
        recovers_last_against: f.recovers_last_against,
        class: f.class,
      })),
    }),
  );

  return {
    rounds: rounds.length,
    fronts,
    class_counts,
    weak_fronts,
    most_exposed_front,
    has_persistent_weak_front,
    weak_front_hash,
  };
}

/** Create-and-return an empty `Set` registered under `key` in `m` (so the inline `?? …` reads cleanly). */
function setInto(m: Map<string, Set<string>>, key: string): Set<string> {
  const s = new Set<string>();
  m.set(key, s);
  return s;
}

/** The members of a (possibly absent) set, sorted by `localeCompare(_, "en")` — the family's pin order. */
function sortedLabels(s: Set<string> | undefined): string[] {
  return s ? Array.from(s).sort((a, b) => a.localeCompare(b, "en")) : [];
}

/**
 * Is any front the deal's persistent weak point — both a strict-majority **first-conceder** (v36) against
 * some partner *and* a strict-majority **last-recoverer** (v37) against some partner: a front the
 * counterparty both gives ground on first and restores last, exposed coming and going? The CI gate
 * predicate — the family's first *per-front* conjunction. **Strictly stronger** than v36's `concedes` or
 * v37's `lags`, which each fire on a directional ordering *existing at all*; this requires a single front
 * to be the weak side of **both**. A deal can trip v36 and v37 (different fronts lead each) yet clear
 * this (no one front is weak on both). It needs no tuning — it is the conjunction of two already
 * tuning-free strict-majority verdicts.
 */
export function exposurePersistentlyWeak(weakFront: CoherenceWeakFront): boolean {
  return weakFront.has_persistent_weak_front;
}

/**
 * Serialize a {@link CoherenceWeakFront} to a stable, pretty-printed JSON string. The key order is fixed
 * and the front order is already pinned by {@link computeCoherenceWeakFront}, so the same report always
 * yields identical bytes — the `weak_front_hash` it carries is the canonical fingerprint, reproducible
 * from `fronts` (over the per-front partner lists and class; the derived `confirmed_against`, the
 * `most_exposed_front`, and `has_persistent_weak_front` aside).
 */
export function buildCoherenceWeakFrontJson(weakFront: CoherenceWeakFront): string {
  return JSON.stringify(
    {
      schema: "vaulytica.posture-weak-front.v1",
      weak_front_hash: weakFront.weak_front_hash,
      rounds: weakFront.rounds,
      class_counts: weakFront.class_counts,
      weak_fronts: weakFront.weak_fronts,
      most_exposed_front: weakFront.most_exposed_front,
      has_persistent_weak_front: weakFront.has_persistent_weak_front,
      fronts: weakFront.fronts.map((f) => ({
        dimension: f.dimension,
        concedes_first_against: f.concedes_first_against,
        recovers_last_against: f.recovers_last_against,
        confirmed_against: f.confirmed_against,
        class: f.class,
      })),
    },
    null,
    2,
  );
}

/** Render a partner list compactly: `[Cap, Term]` → `"Cap, Term"`, empty → `"—"`. */
function partners(list: string[]): string {
  return list.length === 0 ? "—" : list.join(", ");
}

/**
 * Render a {@link CoherenceWeakFront} as human-readable terminal lines: the most-exposed persistent weak
 * front (its concession partners, its recovery partners, and its confirmed same-partner counterparts, or
 * none-weak when no front is persistently weak), the class tally, then one line per front
 * (`persistent-weak` first), then the hash. A front weak on neither axis is never listed (§3 honesty).
 * Lives beside its JSON sibling so the CLI renders the report from one definition.
 */
export function renderCoherenceWeakFrontSummary(weakFront: CoherenceWeakFront): string {
  const cc = weakFront.class_counts;
  const n = weakFront.rounds;
  const lines = [
    `\nCoherence persistent weak front across ${n} rounds (which front the counterparty concedes first AND recovers last):`,
  ];
  if (weakFront.most_exposed_front === null) {
    lines.push(
      `  persistent weak front: none — no front both concedes the floor first and recovers last for a strict majority of the comparisons.`,
    );
  } else {
    const f = weakFront.fronts.find((e) => e.dimension === weakFront.most_exposed_front)!;
    lines.push(
      `  most-exposed front: ${f.dimension} — concedes first vs ${partners(f.concedes_first_against)}; recovers last vs ${partners(f.recovers_last_against)}${
        f.confirmed_against.length > 0 ? `; both vs ${partners(f.confirmed_against)}` : ""
      }.`,
    );
  }
  lines.push(
    `  fronts: ${cc["persistent-weak"]} persistent-weak (concedes first AND recovers last), ${cc.conceding} conceding-only, ${cc.lagging} lagging-only.`,
  );
  // Persistent-weak fronts first (the gate-worthy class), then conceding-only, then lagging-only; each
  // group keeps the pinned `dimension` order the entries already carry.
  for (const f of [
    ...weakFront.fronts.filter((e) => e.class === "persistent-weak"),
    ...weakFront.fronts.filter((e) => e.class === "conceding"),
    ...weakFront.fronts.filter((e) => e.class === "lagging"),
  ]) {
    const mark = f.class === "persistent-weak" ? "⚠" : "·";
    lines.push(
      `  ${mark} ${f.dimension}: ${f.class} — concedes first vs ${partners(f.concedes_first_against)}; recovers last vs ${partners(f.recovers_last_against)}.`,
    );
  }
  lines.push(`  weak_front_hash: ${weakFront.weak_front_hash}`);
  return lines.join("\n") + "\n";
}
