import { describe, expect, it } from "vitest";
import type { CoherenceInput } from "../../src/report/posture-coherence.js";
import {
  bundlePostureCoherence,
  buildPostureCoherenceJson,
} from "../../src/report/posture-coherence.js";
import type { NegotiationPosture, NegotiationTier } from "../../src/playbooks/custom-interpreter.js";
import { buildPostureReview } from "./posture-review.js";
// The individual commands, to prove the composition does not drift from them.
import { compareCoherenceTrendArtifacts } from "./coherence-trend.js";

function posture(map: Record<string, NegotiationTier>): NegotiationPosture {
  return {
    positions: Object.entries(map).map(([dimension, tier]) => ({ dimension, tier })),
    counts: { ideal: 0, acceptable: 0, below_acceptable: 0, unevaluable: 0 },
    posture_hash: "test",
  };
}
const bundle = (...docs: Array<[string, Record<string, NegotiationTier>]>): CoherenceInput[] =>
  docs.map(([document, map]) => ({ document, posture: posture(map) }));

async function artifacts(): Promise<string[]> {
  const rounds: NegotiationTier[][] = [
    ["acceptable", "acceptable"],
    ["below-acceptable", "acceptable"],
    ["acceptable", "below-acceptable"],
  ];
  const out: string[] = [];
  for (const [cap, term] of rounds) {
    const c = await bundlePostureCoherence(
      bundle(["msa.docx", { Cap: cap!, Term: term! }], ["order.docx", { Cap: "ideal", Term: "ideal" }]),
    );
    out.push(buildPostureCoherenceJson(c, null));
  }
  return out;
}

describe("buildPostureReview", () => {
  it("renders the three attorney sections in deal language", async () => {
    const out = await buildPostureReview(await artifacts(), "markdown");
    expect(out.ok).toBe(true);
    if (out.ok) {
      expect(out.output).toContain("Position drift");
      expect(out.output).toContain("Exposure map");
      expect(out.output).toContain("Weakest front");
      // Each section names a drill-down command.
      expect(out.output).toContain("coherence-trend");
      expect(out.output).toContain("coherence-matrix");
      expect(out.output).toContain("coherence-weak-front");
    }
  });

  it("nests the three sibling reports under posture_review with a hash (JSON)", async () => {
    const out = await buildPostureReview(await artifacts(), "json");
    expect(out.ok).toBe(true);
    if (out.ok) {
      const doc = JSON.parse(out.output);
      expect(doc.posture_review).toBeDefined();
      expect(doc.posture_review.position_drift).toBeDefined();
      expect(doc.posture_review.exposure_map).toBeDefined();
      expect(doc.posture_review.weakest_front).toBeDefined();
      expect(doc.posture_review_hash).toMatch(/^[0-9a-f]{64}$/);
    }
  });

  it("the nested position_drift equals the standalone coherence-trend output (no recomputation drift)", async () => {
    const texts = await artifacts();
    const review = await buildPostureReview(texts, "json");
    const trend = await compareCoherenceTrendArtifacts(texts, "json");
    expect(review.ok && trend.ok).toBe(true);
    if (review.ok && trend.ok) {
      const nested = JSON.parse(review.output).posture_review.position_drift;
      expect(nested).toEqual(JSON.parse(trend.output));
    }
  });

  it("is deterministic", async () => {
    const texts = await artifacts();
    const a = await buildPostureReview(texts, "json");
    const b = await buildPostureReview(texts, "json");
    expect(a.ok && b.ok && a.output === b.output).toBe(true);
  });

  it("refuses fewer than two rounds", async () => {
    const [one] = await artifacts();
    const out = await buildPostureReview([one!], "markdown");
    expect(out.ok).toBe(false);
  });

  it("reports a tampered artifact as a hard error, not a crash", async () => {
    const texts = await artifacts();
    const tampered = texts[1]!.replace(/"coherence_hash":\s*"[0-9a-f]+"/, '"coherence_hash":"deadbeef"');
    const out = await buildPostureReview([texts[0]!, tampered], "markdown");
    expect(out.ok).toBe(false);
    if (!out.ok) expect(out.errors.join(" ")).toMatch(/round 2|hash|tamper/i);
  });
});
