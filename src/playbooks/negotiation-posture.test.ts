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
  ideal: {
    kind: "numeric_threshold",
    metric: "liability_cap_multiple",
    comparator: "gte",
    value: 12,
  },
  acceptable: {
    kind: "numeric_threshold",
    metric: "liability_cap_multiple",
    comparator: "gte",
    value: 6,
  },
  guidance: {
    ideal: "12 months fees",
    acceptable: "6 months fees",
    walk_away: "Escalate — below our floor.",
  },
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

  it("classifies a Thrust C mutuality ladder (ideal = mutual, acceptable = present)", async () => {
    const indemnity: NegotiationPosition = {
      dimension: "Indemnification mutuality",
      ideal: { kind: "clause_mutual", clause: "indemnification" },
      acceptable: { kind: "clause_present", pattern: "indemnif" },
      guidance: {
        ideal: "Mutual indemnity — hold.",
        acceptable: "One-way indemnity present — push for mutual.",
        walk_away: "No indemnity at all — escalate.",
      },
    };
    const mutual = await posture(
      ["Each party shall indemnify and hold the other party harmless from third-party claims."],
      [indemnity],
    );
    expect(mutual.positions[0]!.tier).toBe("ideal");
    const oneWay = await posture(
      ["Customer shall indemnify Provider against all claims arising from Customer's use."],
      [indemnity],
    );
    expect(oneWay.positions[0]!.tier).toBe("acceptable");
    expect(oneWay.positions[0]!.guidance).toBe("One-way indemnity present — push for mutual.");
  });

  it("classifies a Thrust C temporal ladder (cure period in days)", async () => {
    const cure: NegotiationPosition = {
      dimension: "Cure period",
      ideal: {
        kind: "numeric_threshold",
        metric: "cure_period_days",
        comparator: "gte",
        value: 30,
      },
      acceptable: {
        kind: "numeric_threshold",
        metric: "cure_period_days",
        comparator: "gte",
        value: 15,
      },
    };
    const acceptable = await posture(
      ["The breaching party shall have a cure period of 20 days to remedy the default."],
      [cure],
    );
    expect(acceptable.positions[0]!.tier).toBe("acceptable");
  });

  it("is deterministic, sorted by dimension, with a stable posture_hash", async () => {
    const positions: NegotiationPosition[] = [
      {
        dimension: "Zeta",
        ideal: { kind: "clause_present", pattern: "zzz" },
        acceptable: { kind: "clause_present", pattern: "yyy" },
      },
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

describe("approved_language (add-negotiation-ladder-playbooks)", () => {
  const ladderWithFallback: NegotiationPosition = {
    ...liabilityLadder,
    approved_language: "Notwithstanding the foregoing, liability shall be capped at 6x fees.",
  };

  it("carries the team's approved language onto a below-floor row only", async () => {
    const below = await posture(
      ["The liability cap is 3x the total fees paid."],
      [ladderWithFallback],
    );
    expect(below.positions[0]!.tier).toBe("below-acceptable");
    expect(below.positions[0]!.approved_language).toMatch(/capped at 6x fees/);

    // Not carried when at or above the floor (only actionable below).
    const ok = await posture(
      ["The liability cap is 8x the total fees paid."],
      [ladderWithFallback],
    );
    expect(ok.positions[0]!.tier).toBe("acceptable");
    expect(ok.positions[0]!.approved_language).toBeUndefined();
  });

  it("does not affect posture_hash (hash covers dimension + tier only)", async () => {
    const withLang = await posture(
      ["The liability cap is 3x the total fees paid."],
      [ladderWithFallback],
    );
    const without = await posture(
      ["The liability cap is 3x the total fees paid."],
      [liabilityLadder],
    );
    expect(withLang.posture_hash).toBe(without.posture_hash);
  });

  it("the negotiation sheet quotes it, attributed to the playbook", async () => {
    const { buildNegotiationSheet } = await import("../report/negotiation-sheet.js");
    const p = await posture(["The liability cap is 3x the total fees paid."], [ladderWithFallback]);
    const html = buildNegotiationSheet(p, "Test");
    expect(html).toContain("approved fallback language");
    expect(html).toContain("capped at 6x fees");
  });
});

describe("intermediate rungs (add-negotiation-ladder-playbooks)", () => {
  const num = (value: number) =>
    ({
      kind: "numeric_threshold",
      metric: "liability_cap_multiple",
      comparator: "gte",
      value,
    }) as const;
  // Ladder: ideal 12x, floor 6x, with two intermediate rungs 9x and 7x
  // (best-first). Same ideal/acceptable as `liabilityLadder`.
  const ladderWithRungs: NegotiationPosition = {
    ...liabilityLadder,
    rungs: [
      { label: "9x cap", predicate: num(9) },
      { label: "7x cap", predicate: num(7) },
    ],
  };

  it("reports the HIGHEST met rung above the floor as detail only", async () => {
    const ten = await posture(["The liability cap is 10x the total fees paid."], [ladderWithRungs]);
    expect(ten.positions[0]!.tier).toBe("acceptable");
    expect(ten.positions[0]!.met_rung).toBe("9x cap");

    const eight = await posture(
      ["The liability cap is 8x the total fees paid."],
      [ladderWithRungs],
    );
    expect(eight.positions[0]!.tier).toBe("acceptable");
    expect(eight.positions[0]!.met_rung).toBe("7x cap");
  });

  it("omits met_rung when only the floor is met (no rung reached)", async () => {
    const p = await posture(["The liability cap is 6x the total fees paid."], [ladderWithRungs]);
    expect(p.positions[0]!.tier).toBe("acceptable");
    expect(p.positions[0]!.met_rung).toBeUndefined();
  });

  it("never carries a met_rung below the floor or at ideal", async () => {
    const below = await posture(
      ["The liability cap is 3x the total fees paid."],
      [ladderWithRungs],
    );
    expect(below.positions[0]!.tier).toBe("below-acceptable");
    expect(below.positions[0]!.met_rung).toBeUndefined();

    const ideal = await posture(
      ["The liability cap is 15x the total fees paid."],
      [ladderWithRungs],
    );
    expect(ideal.positions[0]!.tier).toBe("ideal");
    expect(ideal.positions[0]!.met_rung).toBeUndefined();
  });

  // THE BINARY-FLOOR INVARIANT: rungs are detail only. For every draft, the
  // reported tier stays in the v2 value set, and the posture_hash is identical
  // to the same ladder WITHOUT rungs — so the coherence subsystem and its 29
  // commands/goldens are provably unaffected.
  it("keeps tier in the v2 value set and posture_hash byte-identical to a no-rungs ladder", async () => {
    const V2_TIERS = new Set(["ideal", "acceptable", "below-acceptable", "unevaluable"]);
    for (const cap of ["15x", "10x", "8x", "6x", "3x", "unstated"]) {
      const doc =
        cap === "unstated"
          ? ["No cap is stated."]
          : [`The liability cap is ${cap} the total fees paid.`];
      const withRungs = await posture(doc, [ladderWithRungs]);
      const without = await posture(doc, [liabilityLadder]);
      expect(V2_TIERS.has(withRungs.positions[0]!.tier)).toBe(true);
      expect(withRungs.positions[0]!.tier).toBe(without.positions[0]!.tier);
      expect(withRungs.posture_hash).toBe(without.posture_hash);
    }
  });

  it("the negotiation sheet shows the met rung above the floor", async () => {
    const { buildNegotiationSheet } = await import("../report/negotiation-sheet.js");
    const p = await posture(["The liability cap is 8x the total fees paid."], [ladderWithRungs]);
    const html = buildNegotiationSheet(p, "Test");
    expect(html).toContain("met rung: 7x cap");
  });
});
