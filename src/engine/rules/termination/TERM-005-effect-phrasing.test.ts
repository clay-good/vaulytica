import { describe, expect, it } from "vitest";
import { rule as TERM_005 } from "./TERM-005.js";
import { buildContext } from "../../_test-fixtures.js";

// Guard: an effect-of-termination clause must be recognized however phrased, so
// TERM-005 does not warn "no effect-of-termination clause" on a doc that has one.
describe("TERM-005 effect-of-termination phrasing", () => {
  for (const clause of [
    "Upon termination, Customer's access to the Service will be disabled.",
    "Following termination, the parties shall have no further obligations.",
    "Upon termination, any prepaid fees shall be forfeited.",
    "Upon termination, outstanding amounts become immediately due and payable.",
    "Upon expiration or termination, Tenant shall surrender the Premises.",
  ]) {
    it(`recognizes: ${clause.slice(0, 46)}`, () => {
      expect(TERM_005.check(buildContext(["Termination", clause]))).toBeNull();
    });
  }

  it("recognizes an entity dissolution wind-down clause", () => {
    expect(
      TERM_005.check(
        buildContext([
          "Dissolution",
          "Upon dissolution, the Partnership's assets shall be applied first to creditors, then to the Partners in accordance with their capital accounts.",
        ]),
      ),
    ).toBeNull();
  });

  it("still warns on a bare dissolution trigger with no wind-down", () => {
    expect(
      TERM_005.check(
        buildContext([
          "Dissolution",
          "The Company shall dissolve upon the written consent of the Members.",
        ]),
      ),
    ).not.toBeNull();
  });

  it("recognizes a construction terminate-for-default remedy", () => {
    expect(
      TERM_005.check(
        buildContext([
          "Default",
          "If the Contractor fails to cure, the Owner may terminate this Agreement for default and complete the Work by other means, and the Contractor shall be liable for the resulting costs.",
        ]),
      ),
    ).toBeNull();
  });

  it("does not read a firing-for-cause clause as a termination effect", () => {
    expect(
      TERM_005.check(
        buildContext([
          "HR",
          "The Company may terminate any employee for cause who fails to complete required training.",
        ]),
      ),
    ).not.toBeNull();
  });

  it("still warns when the contract states no termination effect", () => {
    expect(
      TERM_005.check(
        buildContext([
          "Term",
          "Either party may terminate this Agreement for convenience on 30 days notice.",
        ]),
      ),
    ).not.toBeNull();
  });

  it("a plain payment term does not read as a termination effect", () => {
    expect(
      TERM_005.check(buildContext(["Fees", "Invoices are due and payable Net 30."])),
    ).not.toBeNull();
  });
});

describe("TERM-005 — the consequence stated with 'in which case' (v1.10.0)", () => {
  it("reads a purchase order's termination-for-convenience effect", () => {
    // Buyer-side PO terms state the effect in the same sentence as the
    // termination right, with a verb no branch admits: "pays for conforming
    // goods delivered" is not a wind-down verb, and "pay" is deliberately
    // outside CONSEQUENCE so a failure-to-pay TRIGGER cannot read as an
    // effect. The connective is what identifies the clause.
    expect(
      TERM_005.check(
        buildContext([
          "Termination",
          "Buyer may terminate this order for convenience on written notice, in which case Buyer pays for conforming goods delivered and Seller's reasonable unavoidable costs, and Seller shall mitigate.",
        ]),
      ),
    ).toBeNull();
  });

  it("does not read 'in which case' from an unrelated sentence", () => {
    // The connective has to share a sentence with the termination word; the
    // branch is bounded by `[^.]` for exactly that reason.
    expect(
      TERM_005.check(
        buildContext([
          "Term",
          "Either party may terminate this Agreement for convenience on 30 days notice.",
          "Seller may dispute an invoice within ten days. Buyer may audit the disputed amount, in which case Seller shall provide supporting records.",
        ]),
      ),
    ).not.toBeNull();
  });
});

/**
 * The termination verb's object is the instrument, and it has eighteen names.
 *
 * This branch's object list was hand-written as six of them —
 * `Agreement|Lease|Contract|SOW|Note|Order` — so "may terminate this Sublease,
 * whereupon the deposit is refunded" put a noun in the object slot that the
 * rule did not recognize, and a document with a plainly stated effect of
 * termination was told it had none. It reads `INSTRUMENT_NOUN` now.
 *
 * The corpus does not exercise this: regenerating every golden after the
 * change moved nothing, because no specimen writes "terminate this Sublease"
 * with a consequence. That is precisely why these are here — a broadening the
 * corpus cannot vouch for needs its own evidence.
 */
describe("TERM-005 reads the instrument by every one of its names", () => {
  for (const noun of ["Sublease", "Deed", "Addendum", "Amendment", "Statement of Work", "Rider"]) {
    it(`recognizes a consequence when the object is a ${noun}`, () => {
      expect(
        TERM_005.check(
          buildContext([
            "Termination",
            `Either party may terminate this ${noun} on thirty days' notice, and all prepaid fees shall be refunded.`,
          ]),
        ),
      ).toBeNull();
    });
  }

  it("still warns when the same sentence names no consequence", () => {
    // The branch needs a consequence word; broadening the object list must not
    // turn a bare termination right into an effect-of-termination clause.
    expect(
      TERM_005.check(
        buildContext([
          "Termination",
          "Either party may terminate this Sublease for convenience on thirty days' notice.",
        ]),
      ),
    ).not.toBeNull();
  });
});
