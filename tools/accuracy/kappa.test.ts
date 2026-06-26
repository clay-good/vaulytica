import { describe, expect, it } from "vitest";
import { cohensKappa, bandFor, isLowConfidence, type VerdictPair } from "./kappa.js";

const F = "should_fire" as const;
const N = "should_not_fire" as const;
const pair = (a: typeof F | typeof N, b: typeof F | typeof N): VerdictPair => ({ a, b });

describe("Cohen's κ (spec-v5 §5)", () => {
  it("returns the 'none' band for an empty set", () => {
    const k = cohensKappa([]);
    expect(k.n).toBe(0);
    expect(k.interpretation).toBe("none");
    expect(isLowConfidence(k)).toBe(true);
  });

  it("κ = 1 for perfect agreement with label variance", () => {
    const k = cohensKappa([pair(F, F), pair(N, N), pair(F, F), pair(N, N)]);
    expect(k.kappa).toBeCloseTo(1, 10);
    expect(k.interpretation).toBe("almost-perfect");
  });

  it("κ ≈ 0 for chance-level agreement", () => {
    // A always fires; B fires half the time, independently → po = pe.
    const k = cohensKappa([pair(F, F), pair(F, N), pair(F, F), pair(F, N)]);
    expect(k.kappa).toBeCloseTo(0, 10);
  });

  it("handles the textbook 2x2 example", () => {
    // 20 fire/fire, 5 fire/not, 10 not/fire, 15 not/not (n=50).
    const pairs: VerdictPair[] = [
      ...Array(20).fill(pair(F, F)),
      ...Array(5).fill(pair(F, N)),
      ...Array(10).fill(pair(N, F)),
      ...Array(15).fill(pair(N, N)),
    ];
    const k = cohensKappa(pairs);
    // po = (20+15)/50 = 0.70
    expect(k.observed_agreement).toBeCloseTo(0.7, 10);
    // aFire=25/50=0.5, bFire=30/50=0.6 → pe = .5*.6 + .5*.4 = 0.5
    expect(k.expected_agreement).toBeCloseTo(0.5, 10);
    // κ = (0.7-0.5)/(1-0.5) = 0.4
    expect(k.kappa).toBeCloseTo(0.4, 10);
    expect(k.interpretation).toBe("fair");
  });

  it("κ = 1 on a degenerate single-label distribution (no variance)", () => {
    const k = cohensKappa([pair(N, N), pair(N, N), pair(N, N)]);
    expect(k.kappa).toBe(1);
  });

  it("negative κ for systematic disagreement", () => {
    const k = cohensKappa([pair(F, N), pair(N, F), pair(F, N), pair(N, F)]);
    expect(k.kappa).toBeLessThan(0);
    expect(k.interpretation).toBe("poor");
  });

  it("bandFor matches Landis & Koch cutoffs", () => {
    expect(bandFor(-0.1)).toBe("poor");
    expect(bandFor(0.1)).toBe("slight");
    expect(bandFor(0.3)).toBe("fair");
    expect(bandFor(0.5)).toBe("moderate");
    expect(bandFor(0.7)).toBe("substantial");
    expect(bandFor(0.9)).toBe("almost-perfect");
  });

  it("flags low confidence below the 0.6 threshold", () => {
    expect(isLowConfidence(cohensKappa([pair(F, F), pair(F, N), pair(F, F), pair(F, N)]))).toBe(
      true,
    );
    expect(isLowConfidence(cohensKappa([pair(F, F), pair(N, N)]))).toBe(false);
  });
});
