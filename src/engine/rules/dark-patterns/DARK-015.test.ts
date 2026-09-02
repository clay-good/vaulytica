/**
 * The waiver Article 9 does not allow, and the two forms that are fine.
 *
 * Found on a hand-written equipment finance lease whose § 6 waived "any right
 * to notice, hearing, or redemption" and let the lessor repossess "without
 * notice or legal process" — and which drew no finding at all, because
 * BNK-143 is a presence check for "default, acceleration, and disposition of
 * collateral" and those are the words the waiving clause is made of.
 */
import { describe, expect, it } from "vitest";
import { rule as DARK_015 } from "./DARK-015.js";
import { buildContext } from "../../_test-fixtures.js";

const doc = (...lines: string[]) => buildContext(["Default and Remedies", ...lines]);

describe("DARK-015 — waiver of non-waivable Article 9 protections", () => {
  it("fires on a waiver of notice, hearing and redemption", () => {
    const f = DARK_015.check(doc("Lessee waives any right to notice, hearing, or redemption."));
    expect(f?.severity).toBe("critical");
    expect(f?.title).toMatch(/non-waivable/i);
  });

  it("fires on repossession without notice or legal process", () => {
    expect(
      DARK_015.check(
        doc("Upon default Lessor may repossess the Equipment without notice or legal process."),
      ),
    ).not.toBeNull();
  });

  it("fires on a waiver of the commercial-reasonableness standard", () => {
    expect(
      DARK_015.check(
        doc("Debtor waives all rights to require that any disposition be commercially reasonable."),
      ),
    ).not.toBeNull();
  });

  // The saving language is what makes the sentence lawful: with it the waiver
  // reaches only what § 9-602 allows to be waived.
  it.each([
    "except as prohibited by applicable law",
    "to the extent permitted by applicable law",
    "subject to the requirements of Article 9",
  ])("stays silent where the waiver is confined — %s", (carveOut) => {
    expect(
      DARK_015.check(
        doc(`Lessee waives any right to notice, hearing, or redemption, ${carveOut}.`),
      ),
    ).toBeNull();
  });

  it("stays silent on a compliant disposition clause", () => {
    expect(
      DARK_015.check(
        doc(
          "Upon default Lessor may repossess and dispose of the Equipment in accordance with Article 9, including the notice and commercial-reasonableness requirements.",
        ),
      ),
    ).toBeNull();
  });

  it("stays silent on a waiver of something Article 9 lets a debtor waive", () => {
    expect(
      DARK_015.check(
        doc("Lessee waives any right to trial by jury in any action under this Lease."),
      ),
    ).toBeNull();
  });

  it("stays silent where nothing is waived at all", () => {
    expect(
      DARK_015.check(doc("Lessee is in default if any rent is not paid when due.")),
    ).toBeNull();
  });
  // § 9-609(b)(2) permits repossession without judicial process precisely WHEN
  // it happens without a breach of the peace, so a clause that states the
  // condition is quoting the rule rather than escaping it. An existing
  // specimen — a secured equipment-finance agreement — supplied both this and
  // the full-title reference below, and the first form of this rule reported
  // its compliant remedies clause as an unlawful waiver.
  it("stays silent where self-help preserves the breach-of-the-peace limit", () => {
    expect(
      DARK_015.check(
        doc(
          "Lender may take possession of the Equipment without judicial process if it can do so without a breach of the peace.",
        ),
      ),
    ).toBeNull();
  });

  it("stays silent where the disposition names Article 9 by its full title", () => {
    expect(
      DARK_015.check(
        doc(
          "Lender may sell or otherwise dispose of the Equipment without further notice in a commercially reasonable manner as Article 9 of the Uniform Commercial Code requires.",
        ),
      ),
    ).toBeNull();
  });

  // The defect the first form of this rule had: a waiver anywhere in the
  // paragraph and a protection word anywhere after it. An ordinary non-waiver
  // clause is not a waiver of anything.
  it("stays silent on an ordinary non-waiver clause", () => {
    expect(
      DARK_015.check(
        doc(
          "Lender's remedies are cumulative and not exclusive, and no delay in exercising a remedy waives it.",
          "Lender may demand payment and give notice of any deficiency remaining after sale.",
        ),
      ),
    ).toBeNull();
  });
});
