/**
 * The SNDA trio could not fire on an SNDA.
 *
 * A presence rule whose pattern is a word from its own family's TITLE can
 * never report the clause missing, because the title is always there. This
 * playbook is named "SNDA (Subordination, Non-Disturbance, Attornment)" and
 * all three checks were spelled with the three words in that name:
 * /subordinat/i, /non.disturbance/i, /attorn/i.
 *
 * /attorn/i was worse than vacuous — it matches "attorney", so every
 * attorneys'-fees clause in the document satisfied the attornment check.
 *
 * Each check now reads the operative clause: subordination is a relationship
 * to the security instrument, non-disturbance is a promise that possession
 * survives foreclosure, and attornment is an act directed at the successor
 * landlord.
 */
import { describe, expect, it } from "vitest";
import { buildContext } from "../../../_test-fixtures.js";
import { V4_RULES } from "../index.js";

const rule = (id: string) => {
  const r = V4_RULES.find((x) => x.id === id);
  if (!r) throw new Error(`no rule ${id}`);
  return r;
};

const TITLE = "SNDA (Subordination, Non-Disturbance, Attornment)";
const snda = (...rest: string[]) => buildContext([TITLE, ...rest]);

const CLAUSES = {
  "RE-046":
    "This Lease is and shall at all times be subject and subordinate to the lien of the Mortgage and to all renewals, modifications, consolidations, and extensions thereof.",
  "RE-047":
    "So long as Tenant is not in default beyond any applicable cure period, Lender shall not disturb Tenant's possession of the Premises, and this Lease shall not be terminated in any foreclosure of the Mortgage.",
  "RE-048":
    "Tenant shall attorn to and recognize Lender, or any purchaser at a foreclosure sale, as the landlord under this Lease for the remainder of the term.",
} as const;

describe("the SNDA checks can fire on an SNDA", () => {
  for (const id of Object.keys(CLAUSES) as (keyof typeof CLAUSES)[]) {
    it(`${id} reports its clause missing when only the title names it`, () => {
      const f = rule(id).check(
        snda("The parties have executed this agreement as of March 14, 2026."),
      );
      expect(f, `${id} cannot fire — the title alone satisfies it`).not.toBeNull();
    });

    it(`${id} stays silent on the clause itself`, () => {
      const f = rule(id).check(snda(CLAUSES[id]));
      expect(f, `${id} flagged its own clause: ${f?.title ?? ""}`).toBeNull();
    });
  }

  it("an attorneys'-fees clause is not an attornment clause", () => {
    const f = rule("RE-048").check(
      snda(
        "The prevailing party in any action to enforce this agreement shall be entitled to recover its reasonable attorneys' fees and costs from the other party.",
      ),
    );
    expect(f, 'RE-048 read "attorneys\' fees" as attornment').not.toBeNull();
  });

  it("naming the Mortgage all over the document is not a subordination clause", () => {
    // Every SNDA does. Proximity between the title's own "Subordination" and
    // the ever-present "Mortgage" must not be enough.
    const f = rule("RE-046").check(
      snda(
        "Lender is the holder of the Mortgage encumbering the Property. The Mortgage was recorded in the office of the Register of Deeds. Tenant acknowledges the Mortgage.",
      ),
    );
    expect(f, "RE-046 read a recital about the Mortgage as subordination").not.toBeNull();
  });

  it("a subordination clause that names no security instrument is not one", () => {
    const f = rule("RE-046").check(
      snda("The rights of the parties hereunder are subordinate to the terms of this agreement."),
    );
    expect(f).not.toBeNull();
  });
});
