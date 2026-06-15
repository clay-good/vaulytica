import { describe, expect, it } from "vitest";
import {
  computeCoherencePersistence,
  exposureOpen,
  buildCoherencePersistenceJson,
  renderCoherencePersistenceSummary,
} from "./coherence-persistence.js";
import { compareCoherenceExposure, exposureBreached } from "./coherence-exposure.js";
import { bundlePostureCoherence, type CoherenceInput } from "./posture-coherence.js";
import type { NegotiationPosture, NegotiationTier } from "../playbooks/custom-interpreter.js";

function posture(map: Record<string, NegotiationTier>): NegotiationPosture {
  return {
    positions: Object.entries(map).map(([dimension, tier]) => ({ dimension, tier })),
    counts: { ideal: 0, acceptable: 0, below_acceptable: 0, unevaluable: 0 },
    posture_hash: "test",
  };
}

const bundle = (...docs: Array<[string, Record<string, NegotiationTier>]>): CoherenceInput[] =>
  docs.map(([document, map]) => ({ document, posture: posture(map) }));

/** A round whose `Cap` floor is the weaker of the two docs' tiers; `Law` held ideal throughout. */
const round = (capA: NegotiationTier, capB: NegotiationTier) =>
  bundlePostureCoherence(
    bundle(["msa.docx", { Cap: capA, Law: "ideal" }], ["order.docx", { Cap: capB, Law: "ideal" }]),
  );

describe("computeCoherencePersistence (spec-v21 — below-floor duration & current standing)", () => {
  it("reports rounds-below, the span, and the current standing of an open front", async () => {
    // Cap floors: below → below → below. Down all three rounds, still down now.
    const rounds = await Promise.all([
      round("below-acceptable", "below-acceptable"),
      round("below-acceptable", "below-acceptable"),
      round("below-acceptable", "below-acceptable"),
    ]);
    const p = await computeCoherencePersistence(rounds);
    expect(p.rounds).toBe(3);
    const cap = p.fronts.find((f) => f.dimension === "Cap")!;
    expect(cap.rounds_below).toBe(3);
    expect(cap.first_below_round).toBe(1);
    expect(cap.last_below_round).toBe(3);
    expect(cap.last_stated_round).toBe(3);
    expect(cap.currently_below).toBe(true);
    expect(cap.persistence).toBe("open");
    expect(exposureOpen(p)).toBe(true);
  });

  it("classifies a resolved dip as `resolved`, clearing the gate v20 keeps red forever", async () => {
    // Cap dips to below floor in round 2 then recovers to acceptable and holds.
    // v20: worst_floor = below-acceptable, exposed = true (stays red after the fix).
    // v21: latest stated floor is acceptable → resolved, gate clears.
    const rounds = await Promise.all([
      round("ideal", "ideal"),
      round("ideal", "below-acceptable"),
      round("acceptable", "acceptable"),
    ]);
    const p = await computeCoherencePersistence(rounds);
    const cap = p.fronts.find((f) => f.dimension === "Cap")!;
    expect(cap.rounds_below).toBe(1);
    expect(cap.first_below_round).toBe(2);
    expect(cap.last_below_round).toBe(2);
    expect(cap.currently_below).toBe(false);
    expect(cap.persistence).toBe("resolved");
    expect(exposureOpen(p)).toBe(false); // v21 gate clears — the dip is closed

    // The level axis cannot see the recovery: v20 stays exposed/red.
    const exposure = await compareCoherenceExposure(rounds);
    expect(exposure.fronts.find((f) => f.dimension === "Cap")!.exposed).toBe(true);
    expect(exposureBreached(exposure)).toBe(true);
  });

  it("classifies a front still below floor at the latest round as `open` (the gate trips)", async () => {
    // Cap was ideal, slipped to below floor in round 2, still below in round 3.
    const rounds = await Promise.all([
      round("ideal", "ideal"),
      round("ideal", "below-acceptable"),
      round("ideal", "below-acceptable"),
    ]);
    const p = await computeCoherencePersistence(rounds);
    const cap = p.fronts.find((f) => f.dimension === "Cap")!;
    expect(cap.rounds_below).toBe(2);
    expect(cap.first_below_round).toBe(2);
    expect(cap.last_below_round).toBe(3);
    expect(cap.currently_below).toBe(true);
    expect(cap.persistence).toBe("open");
    expect(exposureOpen(p)).toBe(true);
  });

  it("classifies a front that never fell below floor as `none`", async () => {
    const rounds = await Promise.all([round("ideal", "acceptable"), round("acceptable", "ideal")]);
    const cap = (await computeCoherencePersistence(rounds)).fronts.find(
      (f) => f.dimension === "Cap",
    )!;
    expect(cap.rounds_below).toBe(0);
    expect(cap.first_below_round).toBeNull();
    expect(cap.currently_below).toBe(false);
    expect(cap.persistence).toBe("none");
  });

  it("classifies a front no document ever states as `unstated`, never open/resolved (silence is not exposure, §3)", async () => {
    // `Gap` is `unevaluable` in every document in every round → no binding floor
    // is ever stated → unstated, never open or resolved.
    const gapRound = () =>
      bundlePostureCoherence(
        bundle(
          ["msa.docx", { Cap: "below-acceptable", Gap: "unevaluable" }],
          ["order.docx", { Cap: "below-acceptable", Gap: "unevaluable" }],
        ),
      );
    const p = await computeCoherencePersistence([await gapRound(), await gapRound()]);
    const gap = p.fronts.find((f) => f.dimension === "Gap")!;
    expect(gap.floors).toEqual([null, null]);
    expect(gap.rounds_below).toBe(0);
    expect(gap.last_stated_round).toBeNull();
    expect(gap.currently_below).toBe(false);
    expect(gap.persistence).toBe("unstated");
    expect(p.class_counts.unstated).toBe(1);
    // Cap is genuinely below floor → open; the unstated Gap does not count.
    expect(p.open_count).toBe(1);
  });

  it("keeps the last KNOWN standing when a front goes unstated after an exposure (§3)", async () => {
    // Cap is below floor in round 2, then no document states it in round 3.
    // Current standing reads the latest *stated* round (2) → still open; silence
    // after an exposure is neither an invented recovery nor a fresh exposure.
    const r1 = await round("ideal", "ideal");
    const r2 = await round("below-acceptable", "below-acceptable");
    const r3 = await bundlePostureCoherence(
      bundle(["msa.docx", { Law: "ideal" }], ["order.docx", { Law: "ideal" }]),
    );
    const cap = (await computeCoherencePersistence([r1, r2, r3])).fronts.find(
      (f) => f.dimension === "Cap",
    )!;
    expect(cap.floors).toEqual(["ideal", "below-acceptable", null]);
    expect(cap.last_stated_round).toBe(2);
    expect(cap.currently_below).toBe(true);
    expect(cap.persistence).toBe("open");
  });

  it("counts a front stated in only some rounds, ignoring the unstated rounds", async () => {
    // Round 1 has no Cap; rounds 2-3 do, recovering by round 3.
    const r1 = await bundlePostureCoherence(
      bundle(["msa.docx", { Law: "ideal" }], ["order.docx", { Law: "ideal" }]),
    );
    const r2 = await round("acceptable", "below-acceptable");
    const r3 = await round("acceptable", "acceptable");
    const cap = (await computeCoherencePersistence([r1, r2, r3])).fronts.find(
      (f) => f.dimension === "Cap",
    )!;
    expect(cap.floors).toEqual([null, "below-acceptable", "acceptable"]);
    expect(cap.rounds_below).toBe(1);
    expect(cap.first_below_round).toBe(2);
    expect(cap.last_stated_round).toBe(3);
    expect(cap.persistence).toBe("resolved");
  });

  it("tallies persistence classes and the open count across fronts", async () => {
    // Cap: open (below now); Law: none (ideal throughout); Risk: resolved (dipped, recovered).
    const rounds = await Promise.all([
      bundlePostureCoherence(
        bundle(
          ["a.docx", { Cap: "below-acceptable", Law: "ideal", Risk: "below-acceptable" }],
          ["b.docx", { Cap: "ideal", Law: "ideal", Risk: "ideal" }],
        ),
      ),
      bundlePostureCoherence(
        bundle(
          ["a.docx", { Cap: "below-acceptable", Law: "ideal", Risk: "acceptable" }],
          ["b.docx", { Cap: "ideal", Law: "ideal", Risk: "ideal" }],
        ),
      ),
    ]);
    const p = await computeCoherencePersistence(rounds);
    expect(p.class_counts).toEqual({ open: 1, resolved: 1, none: 1, unstated: 0 });
    expect(p.open_count).toBe(1);
  });

  it("is deterministic: identical rounds in identical order → identical persistence_hash", async () => {
    const mk = () =>
      Promise.all([round("ideal", "below-acceptable"), round("acceptable", "acceptable")]);
    const a = await computeCoherencePersistence(await mk());
    const b = await computeCoherencePersistence(await mk());
    expect(a.persistence_hash).toBe(b.persistence_hash);
    expect(a.persistence_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("throws on fewer than two rounds", async () => {
    const rounds = [await round("ideal", "ideal")];
    await expect(computeCoherencePersistence(rounds)).rejects.toThrow(/at least two rounds/);
  });

  it("renders open and resolved fronts and stable JSON", async () => {
    // Cap open (still below); Risk resolved (recovered); Law none (omitted).
    const rounds = await Promise.all([
      bundlePostureCoherence(
        bundle(
          ["a.docx", { Cap: "ideal", Law: "ideal", Risk: "below-acceptable" }],
          ["b.docx", { Cap: "ideal", Law: "ideal", Risk: "ideal" }],
        ),
      ),
      bundlePostureCoherence(
        bundle(
          ["a.docx", { Cap: "below-acceptable", Law: "ideal", Risk: "acceptable" }],
          ["b.docx", { Cap: "ideal", Law: "ideal", Risk: "ideal" }],
        ),
      ),
    ]);
    const p = await computeCoherencePersistence(rounds);
    const summary = renderCoherencePersistenceSummary(p);
    expect(summary).toContain("Coherence exposure persistence across 2 rounds");
    expect(summary).toMatch(/⚠ Cap: open — below floor 1 of 2 rounds/);
    expect(summary).toMatch(/✓ Risk: resolved — was below floor round 1/);
    expect(summary).not.toMatch(/Law:/); // never below floor → omitted
    expect(summary).toMatch(/persistence_hash: [0-9a-f]{64}/);

    const json = JSON.parse(buildCoherencePersistenceJson(p));
    expect(json.schema).toBe("vaulytica.posture-persistence.v1");
    expect(json.persistence_hash).toBe(p.persistence_hash);
    expect(json.rounds).toBe(2);
    expect(json.open_count).toBe(1);
    const capJson = json.fronts.find((f: { dimension: string }) => f.dimension === "Cap");
    expect(capJson.persistence).toBe("open");
    expect(capJson.currently_below).toBe(true);
  });
});
