import { describe, expect, it } from "vitest";
import { evaluateNegotiationPosture, resolvePositionsForDealValue } from "./custom-interpreter.js";
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

describe("deal-size bands end-to-end (add-negotiation-ladder-playbooks)", () => {
  const num = (value: number) =>
    ({
      kind: "numeric_threshold",
      metric: "liability_cap_multiple",
      comparator: "gte",
      value,
    }) as const;
  const banded: NegotiationPosition = {
    dimension: "Liability cap",
    ideal: num(3),
    acceptable: num(2),
    size_bands: [{ min_value: 1_000_000, label: "≥ $1M", ideal: num(12), acceptable: num(6) }],
  };

  it("evaluates against the resolved band and reports which band, tier stays in the v2 set", async () => {
    const V2 = new Set(["ideal", "acceptable", "below-acceptable", "unevaluable"]);
    // 8x cap: under the big-deal band (floor 6) it is acceptable; under the
    // small default (floor 2) it is ideal. The band changes the outcome.
    const big = await posture(
      ["The liability cap is 8x the total fees paid."],
      resolvePositionsForDealValue([banded], 5_000_000),
    );
    expect(big.positions[0]!.tier).toBe("acceptable");
    expect(big.positions[0]!.size_band).toBe("≥ $1M");
    expect(V2.has(big.positions[0]!.tier)).toBe(true);

    const small = await posture(
      ["The liability cap is 8x the total fees paid."],
      resolvePositionsForDealValue([banded], undefined),
    );
    expect(small.positions[0]!.tier).toBe("ideal");
    expect(small.positions[0]!.size_band).toBe("default (no --deal-value)");
  });

  it("does not put size_band in posture_hash (detail only)", async () => {
    const withBand = await posture(
      ["The liability cap is 8x the total fees paid."],
      resolvePositionsForDealValue([banded], 5_000_000),
    );
    // The same resolved ladder authored directly, with no size_bands/_resolved_band.
    const plain = await posture(
      ["The liability cap is 8x the total fees paid."],
      [{ dimension: "Liability cap", ideal: num(12), acceptable: num(6) }],
    );
    expect(withBand.posture_hash).toBe(plain.posture_hash);
  });
});

/**
 * A metric that counts must read all three spellings of its number.
 *
 * Every count-valued metric was written `(\d+)` — digits only. The static
 * sweeps that fixed exactly this blindness across 65 rule recognizers
 * (`parenthetical-numeral.test.ts`) and 68 more for the words-only form
 * (`spelled-period.test.ts`) walked `src/engine/rules`, `src/extract` and
 * `src/engine/consistency` — never `src/playbooks`, so the interpreter that
 * reads documents for the negotiation ladder kept the blindness both sweeps
 * existed to end. All four sweeps now walk `src/playbooks` too.
 *
 * The dominant missing form was not the exotic one. "thirty (30) days" is how
 * a lawyer writes "30 days", and `(\d+)\s+days` cannot match it: after the
 * digits comes ")", not a space. Across the corpus that is 69 spans the
 * interpreter could not see.
 *
 * And an unread number is not a missing number here — it is an **unevaluable**
 * dimension, which drops off the ladder silently. Measured: 45 specimens gain
 * a cure-period verdict, 13 a termination-notice verdict, and rewriting the
 * corpus into words no longer turns an `ideal` and three `below-acceptable`
 * verdicts into `unevaluable`.
 */
describe("a counted metric reads all three spellings", () => {
  const cureLadder: NegotiationPosition = {
    dimension: "Cure period",
    ideal: { kind: "numeric_threshold", metric: "cure_period_days", comparator: "gte", value: 30 },
    acceptable: {
      kind: "numeric_threshold",
      metric: "cure_period_days",
      comparator: "gte",
      value: 15,
    },
  };

  const SPELLINGS: Array<[label: string, clause: string, tier: string]> = [
    ["bare numeral", "The breach must be cured within 30 days of notice.", "ideal"],
    // The dominant form in a drafted instrument, and the one `(\d+)\s+days`
    // could never match.
    ["parenthetical", "The breach must be cured within thirty (30) days of notice.", "ideal"],
    // The plain-language form, with no numeral to fall back on.
    ["words only", "The breach must be cured within thirty days of notice.", "ideal"],
    [
      "words below the floor",
      "The breach must be cured within ten days of notice.",
      "below-acceptable",
    ],
  ];

  for (const [label, clause, tier] of SPELLINGS) {
    it(`reads the ${label} spelling`, async () => {
      const p = await posture([clause], [cureLadder]);
      expect(p.positions[0]!.tier).toBe(tier);
    });
  }

  it("does not misread a long numeral as its first three digits", async () => {
    // `PERIOD_COUNT`'s numeral branch is `\d{1,3}` and `countValue` reads a
    // span's first three digits, so routing every match through it would turn
    // a 1095-day term into 109. The digits-first alternation is what prevents
    // that, and this is the case that proves it.
    const termLadder: NegotiationPosition = {
      dimension: "Term",
      ideal: {
        kind: "numeric_threshold",
        metric: "term_length_days",
        comparator: "gte",
        value: 1000,
      },
      acceptable: {
        kind: "numeric_threshold",
        metric: "term_length_days",
        comparator: "gte",
        value: 500,
      },
    };
    const p = await posture(["This Agreement has a term of 1095 days."], [termLadder]);
    expect(p.positions[0]!.tier).toBe("ideal");
  });

  it("reads a liability cap stated as a multiple in words", async () => {
    const p = await posture(
      ["The liability cap is fifteen times the total fees paid under this Agreement."],
      [liabilityLadder],
    );
    expect(p.positions[0]!.tier).toBe("ideal");
  });
});

/**
 * A cap stated as a sum in words, and the looseness it must not inherit.
 *
 * The digit patterns for `liability_cap_amount` take any `$` within 120
 * characters of "liab" — loose enough that "limited liability company … in
 * consideration of Four Hundred Eighty Thousand Dollars" reports a purchase
 * price as a liability cap. That is pre-existing and left alone. The word-form
 * pattern is new, so it requires real cap language instead of inheriting the
 * weakness; over the corpus that keeps all seven genuine word-sum caps and
 * drops the one match that is not a cap.
 */
describe("a liability cap written as a sum in words", () => {
  const capLadder: NegotiationPosition = {
    dimension: "Liability cap amount",
    ideal: {
      kind: "numeric_threshold",
      metric: "liability_cap_amount",
      comparator: "gte",
      value: 1_000_000,
    },
    acceptable: {
      kind: "numeric_threshold",
      metric: "liability_cap_amount",
      comparator: "gte",
      value: 100_000,
    },
  };

  it("reads a cap introduced by cap language", async () => {
    const p = await posture(
      ["Liability under this Guaranty is limited to Three Million Dollars."],
      [capLadder],
    );
    expect(p.positions[0]!.tier).toBe("ideal");
  });

  it("reads 'shall not exceed' too", async () => {
    const p = await posture(
      ["Each party's liability for breach shall not exceed Five Hundred Thousand Dollars."],
      [capLadder],
    );
    expect(p.positions[0]!.tier).toBe("acceptable");
  });

  it("does not read a purchase price beside the word 'liability' as a cap", async () => {
    const p = await posture(
      [
        "Ridgeline Holdings, a limited liability company, for and in consideration of Four Hundred Eighty Thousand Dollars, hereby sells the Equipment.",
      ],
      [capLadder],
    );
    expect(p.positions[0]!.tier).toBe("unevaluable");
  });
});

/**
 * "must not exceed" is the third spelling of "shall not exceed".
 *
 * `capInWords` shipped reading `shall` and `will` and not `must` — the same
 * blindness the `shall-will` sweep exists to catch, in code written in the
 * same change that widened that sweep to `src/playbooks`. It caught it
 * immediately, which is the argument for the widening.
 */
describe("the cap-language gate reads all three modals", () => {
  const capLadder: NegotiationPosition = {
    dimension: "Liability cap amount",
    ideal: {
      kind: "numeric_threshold",
      metric: "liability_cap_amount",
      comparator: "gte",
      value: 100_000,
    },
    acceptable: {
      kind: "numeric_threshold",
      metric: "liability_cap_amount",
      comparator: "gte",
      value: 10_000,
    },
  };

  for (const modal of ["shall", "will", "must"]) {
    it(`reads "${modal} not exceed"`, async () => {
      const p = await posture(
        [`Each party's liability for breach ${modal} not exceed Five Hundred Thousand Dollars.`],
        [capLadder],
      );
      expect(p.positions[0]!.tier).toBe("ideal");
    });
  }

  it("reads a bare 'not to exceed' with no modal at all", async () => {
    const p = await posture(
      ["Liability is capped at an amount not exceeding Five Hundred Thousand Dollars."],
      [capLadder],
    );
    expect(p.positions[0]!.tier).toBe("ideal");
  });
});

/**
 * A cap denominated in something other than dollars.
 *
 * The cap-amount patterns read a digit CLASS, so by the rule
 * `currency-glyph.test.ts` states they must admit every glyph — the literal-US-
 * statutory-threshold exemption does not apply to a figure the document
 * chooses. Reading only `$` did not produce a wrong number for a €500,000 cap,
 * it produced NO number: unevaluable, and the dimension gone from the ladder.
 */
describe("a liability cap in another currency", () => {
  const capLadder: NegotiationPosition = {
    dimension: "Liability cap amount",
    ideal: {
      kind: "numeric_threshold",
      metric: "liability_cap_amount",
      comparator: "gte",
      value: 100_000,
    },
    acceptable: {
      kind: "numeric_threshold",
      metric: "liability_cap_amount",
      comparator: "gte",
      value: 10_000,
    },
  };

  for (const [glyph, label] of [
    ["$", "dollar"],
    ["€", "euro"],
    ["£", "pound"],
    ["¥", "yen"],
  ]) {
    it(`reads a cap stated in ${label}s`, async () => {
      const p = await posture(
        [`Each party's total liability under this Agreement is limited to ${glyph}500,000.`],
        [capLadder],
      );
      expect(p.positions[0]!.tier).toBe("ideal");
    });
  }

  it("still reads the figure stated before the subject", async () => {
    const p = await posture(
      ["The parties agree to €500,000 as the aggregate limit of liability hereunder."],
      [capLadder],
    );
    expect(p.positions[0]!.tier).toBe("ideal");
  });
});
