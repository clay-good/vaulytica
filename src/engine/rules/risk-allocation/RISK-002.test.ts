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

/**
 * The split defend/indemnify form — how most technology contracts write a
 * mutual indemnity, and the shape this rule read BACKWARDS.
 *
 *   "Provider shall defend Customer against any claim …,
 *    and shall indemnify Customer for damages finally awarded."
 *
 * The indemnitor was taken as the party surface CLOSEST to the verb, and in
 * that sentence the closest surface is CUSTOMER — the party being protected.
 * When both sides are drafted that way (§9.1 Provider→Customer, §9.2
 * Customer→Provider) both sentences land on the same party and a symmetric
 * indemnity is reported as one-sided: measured on a complete SaaS agreement,
 * the counts came out 0 and 2.
 *
 * The subject is what stands before the MODAL, so that is what the rule reads
 * now. Found by the clean-document method — a professionally complete contract
 * where every finding is a candidate bug — not by the corpus, which does not
 * move at all on this fix (11 findings before, 11 after).
 */
describe("RISK-002 — the indemnitor is the subject, not the nearest name", () => {
  const PREAMBLE =
    'This Agreement is between Corvent Systems, Inc., a Delaware corporation ("Provider"), and Ridgeline Manufacturing LLC, a Michigan limited liability company ("Customer").';
  const check = (...lines: string[]) =>
    RISK_002.check(buildContext(["Services Agreement", PREAMBLE, ...lines]));

  it("reads a mutual indemnity written as defend-then-indemnify as mutual", () => {
    expect(
      check(
        "Provider shall defend Customer against any third-party claim alleging that the Service infringes a patent, and shall indemnify Customer for damages finally awarded.",
        "Customer shall defend Provider against any third-party claim alleging that Customer Data infringes the rights of a third party, and shall indemnify Provider for damages finally awarded.",
      ),
      "a mutual indemnity was reported as asymmetric",
    ).toBeNull();
  });

  it("still reads the compact form as mutual", () => {
    expect(
      check(
        "Provider shall defend, indemnify, and hold harmless Customer from any third-party claim.",
        "Customer shall defend, indemnify, and hold harmless Provider from any third-party claim.",
      ),
    ).toBeNull();
  });

  it("still reports a genuinely one-sided indemnity, and names the right side", () => {
    const finding = check(
      "Customer shall indemnify Provider from any claim.",
      "Customer shall indemnify Provider from any other claim.",
      "Customer shall indemnify Provider from a third claim.",
    );
    expect(finding, "a three-to-nothing indemnity went unreported").not.toBeNull();
    // The indemnitor carries the count, and it is the CUSTOMER here.
    expect(finding!.description).toContain("ridgeline manufacturing llc=3");
    expect(finding!.description).toContain("corvent systems, inc=0");
  });

  it("is not fooled by a fronted phrase naming the other party first", () => {
    // "Under its agreement with Provider, Customer shall indemnify …" — the
    // first surface in the sentence is the wrong one, which is why the rule
    // takes the LAST subject-plus-modal rather than the first surface.
    const finding = check(
      "Under its agreement with Provider, Customer shall indemnify Provider from any claim.",
      "Under its agreement with Provider, Customer shall indemnify Provider from another claim.",
      "Under its agreement with Provider, Customer shall indemnify Provider from a third claim.",
    );
    expect(finding).not.toBeNull();
    expect(finding!.description).toContain("ridgeline manufacturing llc=3");
  });
});
