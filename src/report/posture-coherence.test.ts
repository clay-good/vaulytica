import { describe, it, expect } from "vitest";
import {
  bundlePostureCoherence,
  hasDivergence,
  type CoherenceInput,
  type PostureCoherenceKind,
} from "./posture-coherence.js";
import type {
  NegotiationPosture,
  NegotiationTier,
} from "../playbooks/custom-interpreter.js";

/** Build a minimal posture from a `{ dimension: tier }` map (only the fields the engine reads). */
function posture(map: Record<string, NegotiationTier>): NegotiationPosture {
  const positions = Object.entries(map).map(([dimension, tier]) => ({ dimension, tier }));
  return {
    positions,
    counts: { ideal: 0, acceptable: 0, below_acceptable: 0, unevaluable: 0 },
    posture_hash: "test",
  };
}

/** A bundle from a list of `[label, { dimension: tier }]` documents. */
function bundle(...docs: Array<[string, Record<string, NegotiationTier>]>): CoherenceInput[] {
  return docs.map(([document, map]) => ({ document, posture: posture(map) }));
}

/** The coherence kind for the single dimension `Cap` across the given per-doc tiers. */
async function coherenceOf(...tiers: NegotiationTier[]): Promise<PostureCoherenceKind> {
  const docs = bundle(...tiers.map((t, i): [string, Record<string, NegotiationTier>] => [`doc${i}`, { Cap: t }]));
  const c = await bundlePostureCoherence(docs);
  return c.dimensions[0]!.coherence;
}

describe("bundlePostureCoherence — coherence classification", () => {
  it("labels a front every stating document agrees on as aligned", async () => {
    expect(await coherenceOf("ideal", "ideal")).toBe("aligned");
    expect(await coherenceOf("acceptable", "acceptable", "acceptable")).toBe("aligned");
    // an unstated document does not break alignment among the stated ones.
    expect(await coherenceOf("ideal", "ideal", "unevaluable")).toBe("aligned");
  });

  it("labels a front documents disagree on as divergent", async () => {
    expect(await coherenceOf("ideal", "below-acceptable")).toBe("divergent");
    expect(await coherenceOf("ideal", "acceptable", "below-acceptable")).toBe("divergent");
    // one stated outlier among agreeing documents still diverges.
    expect(await coherenceOf("acceptable", "acceptable", "below-acceptable")).toBe("divergent");
  });

  it("labels a front only one document states as single (nothing to compare)", async () => {
    expect(await coherenceOf("ideal", "unevaluable")).toBe("single");
    expect(await coherenceOf("unevaluable", "below-acceptable", "unevaluable")).toBe("single");
  });

  it("labels a front no document states as unstated — silence is never a divergence", async () => {
    expect(await coherenceOf("unevaluable", "unevaluable")).toBe("unstated");
    expect(await coherenceOf("unevaluable", "unevaluable", "unevaluable")).toBe("unstated");
  });

  it("never ranks unstated as the binding floor (the §3 honesty contract)", async () => {
    // An unstated document is unranked; the floor is the weakest *stated* rung.
    const c = await bundlePostureCoherence(
      bundle(["MSA", { Cap: "ideal" }], ["Order", { Cap: "acceptable" }], ["DPA", { Cap: "unevaluable" }]),
    );
    const cap = c.dimensions[0]!;
    expect(cap.coherence).toBe("divergent");
    expect(cap.weakest_tier).toBe("acceptable"); // NOT unevaluable
    expect(cap.weakest_documents).toEqual(["Order"]);
  });
});

describe("bundlePostureCoherence — binding floor", () => {
  it("reports the weakest stated rung and every document carrying it, in input order", async () => {
    const c = await bundlePostureCoherence(
      bundle(
        ["MSA", { Cap: "ideal" }],
        ["SOW", { Cap: "below-acceptable" }],
        ["Order", { Cap: "below-acceptable" }],
      ),
    );
    const cap = c.dimensions[0]!;
    expect(cap.weakest_tier).toBe("below-acceptable");
    expect(cap.weakest_documents).toEqual(["SOW", "Order"]);
  });

  it("has no floor when no document states the front", async () => {
    const c = await bundlePostureCoherence(bundle(["A", { Cap: "unevaluable" }], ["B", { Cap: "unevaluable" }]));
    expect(c.dimensions[0]!.weakest_tier).toBeNull();
    expect(c.dimensions[0]!.weakest_documents).toEqual([]);
  });
});

describe("bundlePostureCoherence — structure & determinism", () => {
  it("sorts dimensions by label, keeps documents in input order, and tallies counts", async () => {
    const c = await bundlePostureCoherence(
      bundle(
        ["MSA", { Liability: "ideal", Governing: "ideal", Indemnity: "unevaluable" }],
        ["SOW", { Liability: "below-acceptable", Governing: "ideal", Indemnity: "unevaluable" }],
      ),
    );
    expect(c.dimensions.map((d) => d.dimension)).toEqual(["Governing", "Indemnity", "Liability"]);
    // documents preserved in caller order within each dimension.
    expect(c.dimensions[0]!.tiers.map((t) => t.document)).toEqual(["MSA", "SOW"]);
    expect(c.counts).toEqual({ aligned: 1, divergent: 1, single: 0, unstated: 1 });
  });

  it("is deterministic — same bundle, same input order → identical coherence_hash", async () => {
    const docs = bundle(["MSA", { Cap: "ideal" }], ["SOW", { Cap: "acceptable" }]);
    const a = await bundlePostureCoherence(docs);
    const b = await bundlePostureCoherence(docs);
    expect(a.coherence_hash).toBe(b.coherence_hash);
    expect(a.coherence_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("a re-ordered bundle is a different artifact (document order is meaningful)", async () => {
    const ab = await bundlePostureCoherence(bundle(["A", { Cap: "ideal" }], ["B", { Cap: "acceptable" }]));
    const ba = await bundlePostureCoherence(bundle(["B", { Cap: "acceptable" }], ["A", { Cap: "ideal" }]));
    expect(ab.coherence_hash).not.toBe(ba.coherence_hash);
  });

  it("handles a single-document bundle (every stated front is `single`)", async () => {
    const c = await bundlePostureCoherence(bundle(["only", { Cap: "ideal", Law: "unevaluable" }]));
    expect(c.dimensions.find((d) => d.dimension === "Cap")!.coherence).toBe("single");
    expect(c.dimensions.find((d) => d.dimension === "Law")!.coherence).toBe("unstated");
  });
});

describe("hasDivergence — the CI gate predicate", () => {
  it("trips when any front is divergent", async () => {
    const c = await bundlePostureCoherence(bundle(["A", { Cap: "ideal" }], ["B", { Cap: "below-acceptable" }]));
    expect(hasDivergence(c)).toBe(true);
  });

  it("does not trip on aligned, single, or unstated fronts only", async () => {
    const c = await bundlePostureCoherence(
      bundle(
        ["A", { Cap: "ideal", Law: "ideal", Indemnity: "unevaluable" }],
        ["B", { Cap: "ideal", Law: "unevaluable", Indemnity: "unevaluable" }],
      ),
    );
    // Cap aligned, Law single, Indemnity unstated — no divergence.
    expect(hasDivergence(c)).toBe(false);
  });
});
