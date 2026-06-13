import { describe, expect, it } from "vitest";
import { evaluateNegotiationPosture } from "./custom-interpreter.js";
import type { NegotiationPosition } from "./custom-playbook.js";
import { buildTree } from "../extract/_fixtures.js";
import { extractAll } from "../extract/index.js";

function posture(doc: string[], positions: NegotiationPosition[]) {
  const tree = buildTree(["Agreement", ...doc]);
  const extracted = extractAll(tree);
  return evaluateNegotiationPosture(positions, { tree, extracted });
}

const liabilityLadder: NegotiationPosition = {
  dimension: "Liability cap",
  ideal: { kind: "numeric_threshold", metric: "liability_cap_multiple", comparator: "gte", value: 12 },
  acceptable: { kind: "numeric_threshold", metric: "liability_cap_multiple", comparator: "gte", value: 6 },
  guidance: { ideal: "12 months fees", acceptable: "6 months fees", walk_away: "Escalate — below our floor." },
};

describe("evaluateNegotiationPosture — tier classification (spec-v10 Thrust A)", () => {
  it("reports IDEAL when the draft meets the strict tier", async () => {
    const p = await posture(
      ["The liability cap is 15x the total fees paid under this Agreement."],
      [liabilityLadder],
    );
    const row = p.positions[0]!;
    expect(row.tier).toBe("ideal");
    expect(row.guidance).toBe("12 months fees");
    expect(p.counts.ideal).toBe(1);
  });

  it("reports ACCEPTABLE when between the floor and the ideal", async () => {
    const p = await posture(
      ["The liability cap is 8x the total fees paid under this Agreement."],
      [liabilityLadder],
    );
    const row = p.positions[0]!;
    expect(row.tier).toBe("acceptable");
    expect(row.guidance).toBe("6 months fees");
    // The detail explains why it's not ideal.
    expect(row.detail).toMatch(/8/);
  });

  it("reports BELOW-ACCEPTABLE when both tiers fail", async () => {
    const p = await posture(
      ["The liability cap is 3x the total fees paid under this Agreement."],
      [liabilityLadder],
    );
    const row = p.positions[0]!;
    expect(row.tier).toBe("below-acceptable");
    expect(row.guidance).toBe("Escalate — below our floor.");
    expect(p.counts.below_acceptable).toBe(1);
  });

  it("reports UNEVALUABLE (never a false walk-away) when the metric is absent", async () => {
    const p = await posture(
      ["The parties agree to the terms set forth herein. No cap is stated."],
      [liabilityLadder],
    );
    const row = p.positions[0]!;
    expect(row.tier).toBe("unevaluable");
    expect(row.reason).toBeTruthy();
    expect(p.counts.unevaluable).toBe(1);
  });

  it("classifies a governing-law ladder by set membership", async () => {
    const lawLadder: NegotiationPosition = {
      dimension: "Governing law",
      ideal: { kind: "governing_law_in", allowed: ["Delaware"] },
      acceptable: { kind: "governing_law_in", allowed: ["Delaware", "New York"] },
    };
    const ny = await posture(
      ["This Agreement is governed by the laws of the State of New York."],
      [lawLadder],
    );
    expect(ny.positions[0]!.tier).toBe("acceptable");
    const tx = await posture(
      ["This Agreement is governed by the laws of the State of Texas."],
      [lawLadder],
    );
    expect(tx.positions[0]!.tier).toBe("below-acceptable");
  });

  it("classifies a clause-presence ladder (ideal = mutual, acceptable = any)", async () => {
    const indemnity: NegotiationPosition = {
      dimension: "Indemnification",
      ideal: { kind: "clause_present", pattern: "mutual indemnification" },
      acceptable: { kind: "clause_present", pattern: "indemnif" },
    };
    const oneWay = await posture(
      ["Provider shall indemnify Customer against all claims (indemnification)."],
      [indemnity],
    );
    expect(oneWay.positions[0]!.tier).toBe("acceptable");
  });

  it("is deterministic, sorted by dimension, with a stable posture_hash", async () => {
    const positions: NegotiationPosition[] = [
      { dimension: "Zeta", ideal: { kind: "clause_present", pattern: "zzz" }, acceptable: { kind: "clause_present", pattern: "yyy" } },
      liabilityLadder,
    ];
    const a = await posture(["The liability cap is 8x the total fees paid."], positions);
    const b = await posture(["The liability cap is 8x the total fees paid."], positions);
    expect(a.positions.map((r) => r.dimension)).toEqual(["Liability cap", "Zeta"]);
    expect(a.posture_hash).toBe(b.posture_hash);
  });

  it("is empty and stable for no positions", async () => {
    const p = await posture(["Body."], []);
    expect(p.positions).toEqual([]);
    expect(p.counts).toEqual({ ideal: 0, acceptable: 0, below_acceptable: 0, unevaluable: 0 });
  });
});
