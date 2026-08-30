import { describe, expect, it } from "vitest";
import { rule as RISK_002 } from "./RISK-002.js";
import { buildContext } from "../../_test-fixtures.js";
import type { RuleContext } from "../../finding.js";
import type { Party } from "../../../extract/types.js";

describe("RISK-002 — a parent instrument named with more than one word", () => {
  // An indemnity "under the Purchase Agreement" describes a PARENT deal's
  // allocation, not an indemnity of this document, and the guard that says so
  // read only a ONE-word title: "under the Stock Purchase Agreement" fell
  // straight through, so an escrow securing the seller's obligations under it
  // was scored as seller-heavy asymmetry. The rule lowercases its sentence
  // before testing, so the word count — not capitalization — is what bounds
  // the title here.
  const GUARD = /indemnif[^.]{0,60}\bunder\s+the\s+(?:[a-z]+\s+){1,4}agreement\b/;

  it("recognizes a one-, two-, and four-word parent title", () => {
    for (const s of [
      "seller's indemnification obligations under the purchase agreement",
      "seller's indemnification obligations under the stock purchase agreement",
      "seller's indemnification obligations under the asset purchase and contribution agreement",
    ]) {
      expect(GUARD.test(s), s).toBe(true);
    }
  });

  it("does not treat 'under this Agreement' as a parent", () => {
    expect(GUARD.test("each party shall indemnify the other under this agreement")).toBe(false);
  });
});

/**
 * The tally seeded itself from EVERY extracted party, including the natural
 * persons who sign. Two signature lines at zero drag `min` to 0, so an
 * ordinary two-versus-one indemnity clears the `max - min >= 2` threshold and
 * a master purchase agreement where each side indemnifies the other was
 * reported as one-sided.
 */
describe("RISK-002 v1.3.0 — a signatory is not a party bearing indemnity", () => {
  const party = (name: string, extra: Record<string, string> = {}) =>
    ({ id: name, name, positions: [], ...extra }) as unknown as Party;

  const ctxWith = (parties: Party[], ...paras: string[]): RuleContext => {
    const base = buildContext(["Indemnification", ...paras]);
    return { ...base, extracted: { ...base.extracted, parties } };
  };

  const BUYER_ONCE = "Buyer shall indemnify Seller against any claim for personal injury.";
  const SELLER_TWICE = [
    "Seller shall indemnify Buyer against any claim that the Goods infringe a patent.",
    "Seller shall indemnify Buyer against any claim for damage to tangible property.",
  ];

  it("does not report a two-versus-one indemnity as asymmetric", () => {
    expect(
      RISK_002.check(
        ctxWith(
          [
            party("Ardmore Instrument Works, Inc", { role: "Buyer", entity_type: "corporation" }),
            party("Yerbury Precision Components LLC", { role: "Seller", entity_type: "LLC" }),
            party("Rosalind Achterberg"),
            party("Emeka Villanueva"),
          ],
          BUYER_ONCE,
          ...SELLER_TWICE,
        ),
      ),
    ).toBeNull();
  });

  it("still reports a genuinely one-sided indemnity", () => {
    expect(
      RISK_002.check(
        ctxWith(
          [
            party("Ardmore Instrument Works, Inc", { role: "Buyer", entity_type: "corporation" }),
            party("Yerbury Precision Components LLC", { role: "Seller", entity_type: "LLC" }),
            party("Rosalind Achterberg"),
          ],
          ...SELLER_TWICE,
        ),
      ),
    ).not.toBeNull();
  });

  /** An individual who IS a party is introduced with a role, and is kept. */
  it("keeps an individual party that carries a role", () => {
    expect(
      RISK_002.check(
        ctxWith(
          [
            party("Halcyon Robotics, Inc", { role: "Company", entity_type: "corporation" }),
            party("Priya Raghunathan", { role: "Executive" }),
          ],
          "The Company shall indemnify Executive against any claim arising from her service.",
          "The Company shall indemnify Executive for expenses advanced under this Section.",
        ),
      ),
    ).not.toBeNull();
  });
});
