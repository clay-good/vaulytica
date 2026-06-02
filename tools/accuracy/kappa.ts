/**
 * Cohen's κ — inter-annotator agreement (spec-v5 §5, Step 69).
 *
 * "If the humans cannot agree on whether a clause is defective, the engine
 * cannot be graded against a coin flip." κ corrects raw agreement for the
 * agreement expected by chance, so a rule graded only on documents the
 * annotators disagreed about is flagged `low_confidence` (spec-v5 §8) rather
 * than given a false-precise precision/recall number.
 *
 * Pure and deterministic: same paired verdicts → same κ. No floating-point
 * nondeterminism beyond IEEE-754, which is bit-stable across machines.
 */

import type { Verdict } from "./schema.js";

export type VerdictPair = { a: Verdict; b: Verdict };

export type KappaResult = {
  /** Cohen's κ in [-1, 1]; 1 = perfect, 0 = chance-level, <0 = worse than chance. */
  kappa: number;
  /** Raw proportion of items both annotators labeled the same. */
  observed_agreement: number;
  /** Agreement expected by chance given each annotator's marginal rates. */
  expected_agreement: number;
  /** Number of doubly-annotated items the κ was computed over. */
  n: number;
  /** Standard interpretive band (Landis & Koch), for the scoreboard. */
  interpretation: KappaBand;
};

export type KappaBand =
  | "none" // n === 0 — undefined, treated as no agreement signal
  | "poor" // < 0.0
  | "slight" // 0.00–0.20
  | "fair" // 0.21–0.40
  | "moderate" // 0.41–0.60
  | "substantial" // 0.61–0.80
  | "almost-perfect"; // 0.81–1.00

/**
 * Compute Cohen's κ over a set of binary (should_fire / should_not_fire)
 * verdict pairs.
 *
 * Edge case: when both annotators always chose the same single label (no
 * variance — e.g. every item is `should_not_fire`), expected agreement is 1,
 * so κ is mathematically 0/0. We return κ = 1 with `interpretation` still
 * derived from the value, because perfect agreement on a degenerate label
 * distribution is genuinely perfect agreement — but the caller should weight
 * it by `n`, which is why `n` is always returned.
 */
export function cohensKappa(pairs: ReadonlyArray<VerdictPair>): KappaResult {
  const n = pairs.length;
  if (n === 0) {
    return {
      kappa: 0,
      observed_agreement: 0,
      expected_agreement: 0,
      n: 0,
      interpretation: "none",
    };
  }

  let agree = 0;
  // Marginal counts for each annotator over the two labels.
  let aFire = 0;
  let bFire = 0;
  for (const { a, b } of pairs) {
    if (a === b) agree++;
    if (a === "should_fire") aFire++;
    if (b === "should_fire") bFire++;
  }

  const po = agree / n;
  const aFireRate = aFire / n;
  const bFireRate = bFire / n;
  // pe = P(both pick fire) + P(both pick not-fire) under independence.
  const pe = aFireRate * bFireRate + (1 - aFireRate) * (1 - bFireRate);

  let kappa: number;
  if (pe >= 1) {
    // Degenerate marginals (no variance). Perfect observed agreement → κ=1;
    // any disagreement is impossible here, so po===1.
    kappa = po >= 1 ? 1 : 0;
  } else {
    kappa = (po - pe) / (1 - pe);
  }

  return {
    kappa,
    observed_agreement: po,
    expected_agreement: pe,
    n,
    interpretation: bandFor(kappa),
  };
}

export function bandFor(kappa: number): KappaBand {
  if (kappa < 0) return "poor";
  if (kappa <= 0.2) return "slight";
  if (kappa <= 0.4) return "fair";
  if (kappa <= 0.6) return "moderate";
  if (kappa <= 0.8) return "substantial";
  return "almost-perfect";
}

/**
 * The κ below which a rule's metric is flagged `low_confidence` (spec-v5
 * Open-Q #7). 0.6 is the Landis & Koch "moderate/substantial" boundary — a
 * conservative default to be re-decided against the first measured κ once a
 * real annotated corpus exists (Step 70, human-gated).
 */
export const LOW_CONFIDENCE_KAPPA_THRESHOLD = 0.6;

export function isLowConfidence(k: KappaResult): boolean {
  return k.n === 0 || k.kappa < LOW_CONFIDENCE_KAPPA_THRESHOLD;
}
